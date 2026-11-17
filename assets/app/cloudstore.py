# -*- coding: utf-8 -*-
"""
云端平台聊天仓库：把飞书 / 钉钉 / 企业微信的在线聊天记录归一化成
与本地微信库同构的表结构，让大屏用同一套渲染逻辑读所有平台。

为什么不直接读在线 API？
    大屏是轮询式看板（每 15 秒刷新）。在线 API 每次拉取都要走一遍
    鉴权 + 分页，延迟高且不稳。所以采用「拉一次 → 落本地库 → 看板读本地库」
    的模式：
        · 拉取（sync）由用户手动触发或定时触发，写入本地 SQLite
        · 看板读本地库，延迟是毫秒级，且不打扰平台 API

表结构：
    conversations(conversation_id, platform, name, chat_type, last_ts, msg_count)
    messages(msg_id, conversation_id, platform, ts, sender_id, sender_name,
             content, is_self, msg_type)

字段命名刻意与 db.py 里的微信返回保持一致（talker/name/time/sender_name/
content/isSend），这样大屏前端不用为每个平台写一套分支。
"""
import os
import re
import json
import time
import sqlite3
import threading

BASE = os.path.dirname(os.path.abspath(__file__))
# 状态目录定位顺序：
#   WB_ANALYZER_HOME（boot.py 显式传，最准）
#     → USERPROFILE/.wb_analyzer
#     → BASE/.wb_analyzer
# 坑：只用 USERPROFILE 的话，计划任务环境（系统账户）和交互式 shell
# （用户目录）会落到**两个不同的库**，
# 表现是「服务里同步了数据，大屏/接口却查不到」——数据其实写进了另一个文件。
_WB_HOME_DIR = os.environ.get("WB_ANALYZER_HOME")
if not _WB_HOME_DIR:
    _WB_HOME_DIR = os.path.join(os.environ.get("USERPROFILE") or BASE,
                                ".wb_analyzer")
CLOUD_DIR = os.getenv("WB_CLOUD_DIR") or os.path.join(_WB_HOME_DIR, "cloud")
DB_PATH = os.path.join(CLOUD_DIR, "cloud.db")

_LOCK = threading.RLock()
_CONN = {"conn": None, "path": None}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT NOT NULL,
    platform        TEXT NOT NULL,
    name            TEXT,
    chat_type       TEXT,
    last_ts         INTEGER DEFAULT 0,
    msg_count       INTEGER DEFAULT 0,
    updated_at      TEXT,
    PRIMARY KEY (platform, conversation_id)
);
CREATE TABLE IF NOT EXISTS messages (
    msg_id         TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    platform       TEXT NOT NULL,
    ts             INTEGER DEFAULT 0,
    sender_id      TEXT,
    sender_name    TEXT,
    content        TEXT,
    is_self        INTEGER DEFAULT 0,
    msg_type       TEXT,
    PRIMARY KEY (platform, conversation_id, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_msg_ts     ON messages(platform, ts);
CREATE INDEX IF NOT EXISTS idx_msg_conv   ON messages(platform, conversation_id, ts);
CREATE INDEX IF NOT EXISTS idx_conv_last  ON conversations(platform, last_ts);
"""


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def conn():
    """取（必要时建立）云端仓库连接。

    自愈：进程被强杀（taskkill / 沙箱回收）会留下 `cloud.db-journal` 回滚日志，
    下次打开就报 `sqlite3.OperationalError: disk I/O error` —— 整个云端仓库不可用。
    这里在连接失败时清掉残留 journal 再重试一次。
    """
    with _LOCK:
        if _CONN["conn"] is not None:
            return _CONN["conn"]
        os.makedirs(CLOUD_DIR, exist_ok=True)
        try:
            return _open()
        except sqlite3.OperationalError as e:
            if "disk i/o" not in str(e).lower() and "locked" not in str(e).lower():
                raise
            # 清掉残留的 journal / wal 再重试
            for suffix in ("-journal", "-wal", "-shm"):
                p = DB_PATH + suffix
                try:
                    if os.path.exists(p):
                        os.unlink(p)
                except OSError:
                    pass
            return _open()


def _open():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    # 固定用 WAL 模式。
    # 坑：默认的 rollback journal（-journal 文件）在部分环境（沙箱/受限目录）
    # 写不进去 → 任何写操作报 `disk I/O error`，表现为「云端仓库整个不可用」，
    # 但读操作正常、integrity_check 也 ok，很有迷惑性。
    # WAL 下写入稳定，且多进程并发读写更好。
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.OperationalError:
        pass
    c.executescript(_SCHEMA)
    c.commit()
    _CONN["conn"] = c
    _CONN["path"] = DB_PATH
    return c


def close():
    with _LOCK:
        if _CONN["conn"] is not None:
            try:
                _CONN["conn"].close()
            except Exception:
                pass
            _CONN["conn"] = None
            _CONN["path"] = None


# ---------------------------------------------------------------- 写入

def upsert_conversation(platform, cid, name, chat_type="", last_ts=0):
    if not cid:
        return
    with _LOCK:
        c = conn()
        c.execute(
            "INSERT INTO conversations(conversation_id, platform, name, chat_type,"
            " last_ts, msg_count, updated_at) VALUES(?,?,?,?,?,0,?)"
            " ON CONFLICT(platform, conversation_id) DO UPDATE SET"
            " name=excluded.name, chat_type=excluded.chat_type,"
            " last_ts=MAX(conversations.last_ts, excluded.last_ts),"
            " updated_at=excluded.updated_at",
            (str(cid), platform, name or "", chat_type or "", int(last_ts or 0), _now()),
        )


def add_messages(platform, cid, rows):
    """批量写入消息。rows 为 dict 列表，字段同 _SCHEMA 的 messages 表。

    重复写入同一 msg_id 会被忽略（INSERT OR IGNORE），所以同步可以反复跑。
    """
    if not rows:
        return 0
    payload = []
    for r in rows:
        if not r.get("content"):
            continue
        payload.append((
            str(r.get("msg_id") or r.get("id") or ""),
            str(cid),
            platform,
            int(r.get("ts") or 0),
            r.get("sender_id") or "",
            r.get("sender_name") or "",
            (r.get("content") or "")[:4000],
            1 if r.get("is_self") else 0,
            r.get("msg_type") or "",
        ))
    if not payload:
        return 0
    with _LOCK:
        c = conn()
        c.executemany(
            "INSERT OR IGNORE INTO messages(msg_id, conversation_id, platform, ts,"
            " sender_id, sender_name, content, is_self, msg_type)"
            " VALUES(?,?,?,?,?,?,?,?,?)", payload)
        c.commit()
        # 会话的 msg_count / last_ts 重新统计
        c.execute(
            "UPDATE conversations SET"
            " msg_count=(SELECT COUNT(*) FROM messages m WHERE m.platform=conversations.platform"
            "   AND m.conversation_id=conversations.conversation_id),"
            " last_ts=MAX(COALESCE(last_ts,0),(SELECT COALESCE(MAX(ts),0) FROM messages m"
            "   WHERE m.platform=conversations.platform AND m.conversation_id=conversations.conversation_id))"
            " WHERE platform=? AND conversation_id=?", (platform, str(cid)))
        c.commit()
    return len(payload)


# ---------------------------------------------------------------- 读取

def conversations(platform, limit=300):
    """会话列表，按最后活跃时间倒序。"""
    c = conn()
    rows = c.execute(
        "SELECT conversation_id, name, chat_type, last_ts, msg_count"
        " FROM conversations WHERE platform=?"
        " ORDER BY last_ts DESC, msg_count DESC LIMIT ?",
        (platform, int(limit))).fetchall()
    return [{
        "talker": r["conversation_id"],
        "name": r["name"] or r["conversation_id"],
        "chat_type": r["chat_type"] or "",
        "last_ts": r["last_ts"] or 0,
        "count": r["msg_count"] or 0,
        # msg_count 也给一份：前端大屏读的是 msg_count，
        # 只给 count 的话 TOP 会话列表的消息数会全显示 0。
        "msg_count": r["msg_count"] or 0,
        "conversation_id": r["conversation_id"],
        "platform": platform,
    } for r in rows]


def messages(platform, cid, limit=200, before_ts=None):
    """某会话的消息，按时间正序返回（与 db.messages 的顺序一致）。"""
    c = conn()
    if before_ts:
        rows = c.execute(
            "SELECT msg_id, ts, sender_id, sender_name, content, is_self, msg_type"
            " FROM messages WHERE platform=? AND conversation_id=? AND ts<?"
            " ORDER BY ts DESC LIMIT ?", (platform, str(cid), int(before_ts), int(limit))).fetchall()
        rows = list(reversed(rows))
    else:
        rows = c.execute(
            "SELECT msg_id, ts, sender_id, sender_name, content, is_self, msg_type"
            " FROM messages WHERE platform=? AND conversation_id=?"
            " ORDER BY ts DESC LIMIT ?", (platform, str(cid), int(limit))).fetchall()
        rows = list(reversed(rows))
    return [{
        "id": r["msg_id"],
        "time": r["ts"] or 0,
        "sender": r["sender_id"] or "",
        "sender_name": r["sender_name"] or "",
        "content": r["content"] or "",
        "isSend": 1 if r["is_self"] else 0,
        "msg_type": r["msg_type"] or "",
        "platform": platform,
    } for r in rows]


def recent(platform, limit=100, per_conv=6):
    """最近消息流：取最近活跃的若干会话，各取末尾几条，合并按时间倒序。

    与大屏 /api/dash 里本地微信的 recent 结构对齐。
    """
    convs = conversations(platform, limit=30)
    out = []
    for cv in convs:
        ms = messages(platform, cv["talker"], limit=per_conv)
        for m in ms:
            out.append({
                "name": cv["name"],
                "talker": cv["talker"],
                "time": m["time"],
                "sender": m["sender"],
                "sender_name": m["sender_name"],
                "isSend": m["isSend"],
                "content": (m["content"] or "")[:120],
                "platform": platform,
            })
    out.sort(key=lambda x: -(x["time"] or 0))
    return out[:limit]


def search(platform, keyword, limit=200):
    """平台内全文搜索。"""
    if not keyword:
        return []
    c = conn()
    rows = c.execute(
        "SELECT m.msg_id, m.conversation_id, m.ts, m.sender_name, m.content, m.is_self,"
        " COALESCE(cv.name, m.conversation_id) AS conv_name"
        " FROM messages m LEFT JOIN conversations cv"
        "   ON cv.platform=m.platform AND cv.conversation_id=m.conversation_id"
        " WHERE m.platform=? AND m.content LIKE ?"
        " ORDER BY m.ts DESC LIMIT ?",
        (platform, "%" + keyword.replace("%", r"\%") + "%", int(limit))).fetchall()
    return [{
        "id": r["msg_id"],
        "talker": r["conversation_id"],
        "name": r["conv_name"],
        "time": r["ts"] or 0,
        "sender_name": r["sender_name"] or "",
        "content": r["content"] or "",
        "isSend": 1 if r["is_self"] else 0,
        "platform": platform,
    } for r in rows]


def stats(platform=None):
    """汇总统计，用于大屏顶部的会话数 / 消息总量。"""
    c = conn()
    if platform:
        rows = c.execute(
            "SELECT COUNT(DISTINCT conversation_id) AS convs, COUNT(*) AS msgs"
            " FROM messages WHERE platform=?", (platform,)).fetchone()
    else:
        rows = c.execute(
            "SELECT COUNT(DISTINCT platform || ':' || conversation_id) AS convs,"
            " COUNT(*) AS msgs FROM messages").fetchone()
    return {"conversations": rows["convs"] or 0, "messages": rows["msgs"] or 0}


def platform_stats():
    """每个平台各自的会话数/消息数/最后同步时间。"""
    c = conn()
    rows = c.execute(
        "SELECT platform, COUNT(*) AS convs,"
        " (SELECT COUNT(*) FROM messages m WHERE m.platform=conversations.platform) AS msgs,"
        " MAX(updated_at) AS updated"
        " FROM conversations GROUP BY platform").fetchall()
    out = {}
    for r in rows:
        out[r["platform"]] = {
            "conversations": r["convs"] or 0,
            "messages": r["msgs"] or 0,
            "updated_at": r["updated"] or "",
        }
    return out


# ---------------------------------------------------------------- 分析

_HOUR_RE = re.compile(r"(\d{1,2})\s*[:：]\s*(\d{1,2})")


def time_heatmap(platform):
    """7×24 活跃热力（与 db.time_heatmap 结构一致）。

    云端消息的时间戳来自各平台 API，粒度到秒，能直接解析出小时。
    """
    c = conn()
    rows = c.execute(
        "SELECT ts FROM messages WHERE platform=? AND ts>0", (platform,)).fetchall()
    grid = [[0] * 24 for _ in range(7)]
    for r in rows:
        ts = r["ts"]
        try:
            lt = time.localtime(ts)
        except Exception:
            continue
        grid[lt.tm_wday][lt.tm_hour] += 1
    return {"grid": grid, "max": max((max(r) for r in grid), default=0)}


_WORD_RE = re.compile(r"[A-Za-z]{2,}")
_CJK_RE = re.compile(r"[一-鿿]{2,}")


def text_corpus(platform, limit=20000):
    """取正文文本，供词频/表情统计。"""
    c = conn()
    rows = c.execute(
        "SELECT content FROM messages WHERE platform=? AND content<>''"
        " ORDER BY ts DESC LIMIT ?", (platform, int(limit))).fetchall()
    return [r["content"] for r in rows]
