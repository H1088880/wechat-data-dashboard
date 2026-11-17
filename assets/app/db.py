# -*- coding: utf-8 -*-
"""
WeChat 解密数据库读取层（只读）。
同时兼容微信 3.x（MSG 单表）与 4.x（Msg_<md5(userName)> 动态分表）结构。

所有操作都不写库、不发消息、不修改任何数据。
"""
import os
import re
import sqlite3
import hashlib
import html
import time
import threading
import weakref
from collections import defaultdict

# ---------- 路径探测：找到本机微信数据目录 ----------
def candidate_wechat_roots():
    """
    返回可能的微信数据根目录列表。

    平台差异（Windows / macOS / Linux 的安装布局）统一收敛在 env.py，
    这里只负责「返回候选中真实存在的那些」。
    """
    import env as _env
    seen = set()
    out = []
    for r in _env.wechat_roots():
        rp = os.path.normpath(r)
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out


def list_accounts(root):
    """列出某 root 下的微信号目录（排除公共/非账号目录）。"""
    accs = []
    skip = {"all users", "all_users", "applet", "favtemp", "mmkv", "backup"}
    try:
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.isdir(p) and name.lower() not in skip:
                accs.append((name, p))
    except Exception:
        pass
    return accs


def find_msg_dirs(account_dir):
    """返回账号目录下的数据库目录候选（兼容 3.x Msg\\ 与 4.x db_storage\\）。"""
    cands = []
    # 注意：不要写死 "Msg\\Multi" 这种 Windows 分隔符，
    # 否则在 macOS/Linux 上会变成字面量目录名，永远匹配不到。
    for sub in ("db_storage", "Msg", os.path.join("Msg", "Multi"),
                "db", "Databases", "databases"):
        p = os.path.join(account_dir, sub)
        if os.path.isdir(p):
            cands.append(p)
    if not cands:
        cands.append(account_dir)
    return cands


def find_encrypted_dbs(msg_dir, max_depth=2):
    """递归查找加密 .db（3.x 在 Msg\\ 平铺，4.x 在 db_storage\\<分类>\\ 下分层）。"""
    dbs = []
    base = os.path.abspath(msg_dir)
    try:
        for root, dirs, files in os.walk(base):
            depth = root[len(base):].count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            for f in files:
                if f.lower().endswith(".db"):
                    dbs.append(os.path.join(root, f))
    except Exception:
        pass
    return sorted(dbs)


# ---------- 通用小工具 ----------
def _tables(conn):
    """列出表名。优先用 pragma_table_list（比全扫 sqlite_master 快一到两个数量级，
    在 1GB 级、几千张分表的微信库上差别是秒级 vs 分钟级）。"""
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM pragma_table_list WHERE type='table'").fetchall()}
    except Exception:
        pass
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    except Exception:
        return set()


def _cols(conn, table):
    try:
        return {r[1]: r[2] for r in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    except Exception:
        return {}


def _pick(cols, *names):
    for n in names:
        if n in cols:
            return n
    return None


def _count_rows_safe(conn, table):
    """数一张表有多少行，坏页时用 MAX(rowid) 兜底。

    背景：微信 4.x 的 message_N.db 里存在损坏的 btree 页，整表
    `SELECT COUNT(*)` 会抛 "database disk image is malformed"。
    直接 except 返回 0，会让大屏把活跃群显示成「0 条」，看着像丢数据。

    策略（必须便宜——这里在后台按会话循环调用，贵了会拖慢整个服务）：
      1) 整表 COUNT(*)，正常时最快；
      2) 失败则取 MAX(rowid) 作为条数近似值（0.03s，走最右叶子页，绕开坏页）；
      3) 再失败才返回 0。
    误差只可能出现在有删除记录、rowid 不连续的坏表上，量级很小；
    宁可给个接近的近似值，也不要给 0。
    """
    try:
        return conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] or 0
    except Exception:
        pass
    try:
        return int(conn.execute(f'SELECT MAX(rowid) FROM "{table}"').fetchone()[0] or 0)
    except Exception:
        return 0


def _open_ro(path):
    try:
        conn = sqlite3.connect(path, timeout=5, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


# ---------- 线程安全 SQLite 连接代理 ----------
# 坑（已踩，实测必现）：sqlite3.connect(..., check_same_thread=False)
# 只是「不再检查线程归属」，**不代表 sqlite3.Connection 本身线程安全**。
# 实测（faulthandler 抓到原生栈）：
#   线程 A（请求）: db.py close()  → conn.close()
#   线程 B（统计）: db.py _cols()  → conn.execute("PRAGMA table_info(...)")
# 两个线程同时操作**同一个** Connection 对象 → 底层 handle 被释放后仍在使用
# → Windows 上直接 ACCESS_VIOLATION (0xC0000005) 段错误，
# Python 层连异常都没有，整个 server.py 进程直接死掉，
# 表现为「大屏每隔二三十秒闪断一次」，watchdog 再拉起来，无限循环。
#
# 解法：底层连接按**线程隔离**（每个线程自己开一个），
# 线程之间互不触碰对方的 handle；
# 再用「在途计数」保证 close_all() 绝不会在有人正在读的时候关连接。
#
# 性能实测（1GB 只读库）：open+close 0.64 ms/次，
# 所以「每个请求线程各开各的」完全负担得起，不影响大屏响应。


class _Cur:
    """代理游标。

    租约模型：cursor 存活期间会**持有**一份在途计数，
    这样 close_all() 绝不会在「结果集还没读完」时把连接关掉。
    计数在以下时机释放：
      · fetchall / fetchone / fetchmany 调用结束
      · 迭代结束（含提前 break，generator 被回收时）
      · cursor 被 close() 或被 GC
    """

    __slots__ = ("_c", "_owner", "_leased")

    def __init__(self, cur, owner):
        self._c = cur
        self._owner = owner
        self._leased = True

    # ---- 租约 ----
    def _release(self):
        if not self._leased:
            return
        self._leased = False
        o = self._owner
        try:
            with o._lock:
                o._inflight -= 1
                o._cond.notify_all()
            # 若之前挂着「等读者退出再关」，此刻正好可以关：
            # 这决定了 Windows 上 os.replace 能不能成功
            # （SQLite 打开的文件不允许被替换）。
            try:
                o._maybe_close_pending()
            except Exception:
                pass
        except Exception:
            pass

    def _acquire(self):
        """批次间隙重新持有租约（连接可能已被关闭 → 调用方负责重试）。"""
        if self._leased:
            return
        self._leased = True
        o = self._owner
        with o._lock:
            o._inflight += 1

    def yield_lease(self):
        """批次间隙让出再重新持有租约。

        供长扫描在每批之间调用：让 close_all()（文件替换前的必要动作）
        有机会在间隙插进来。否则一次扫 230 万行的迭代会一直占着租约，
        连接永远关不掉 → Windows 上 os.replace 失败 → 增量刷新停摆。
        """
        self._release()
        self._acquire()

    def fetchall(self):
        try:
            return self._c.fetchall()
        finally:
            self._release()

    def fetchmany(self, size=None):
        try:
            return self._c.fetchmany() if size is None else self._c.fetchmany(size)
        finally:
            self._release()

    def fetchone(self):
        try:
            return self._c.fetchone()
        finally:
            self._release()

    def __iter__(self):
        try:
            for row in self._c:
                yield row
        finally:
            self._release()

    def close(self):
        try:
            self._c.close()
        except Exception:
            pass
        finally:
            self._release()

    def __del__(self):
        try:
            self._release()
        except Exception:
            pass

    @property
    def description(self):
        return self._c.description

    @property
    def rowcount(self):
        return self._c.rowcount

    @property
    def lastrowid(self):
        return self._c.lastrowid


class _SqlConn:
    """线程安全的 SQLite 连接代理（一个 db 文件一个实例）。

    对外接口与 sqlite3.Connection 一致（本项目只用到 execute / close），
    区别在于：
      · 底层连接**按线程隔离**，线程之间互不触碰对方的 handle；
      · close_all() 会等所有在途 SQL 结束再真正关闭，
        杜绝「一边 close 一边 execute」的 use-after-free；
      · 文件被原子替换后，通过**代次**让各线程自动重开连接，
        从而读到新内容（而不是撞上 "closed database"）。
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._local = threading.local()
        self._registry = {}      # thread_ident -> 底层连接（供跨线程关闭）
        self._inflight = 0       # 在途 SQL 操作数
        self._gen = 0            # 代次：连接被集体作废时 +1
        self._close_pending = False   # 有读者占用时，先挂起关闭，等读者退出再关

    # ---- 取当前线程的底层连接 ----
    def _conn_locked(self):
        """取当前线程的底层连接。**调用方必须已持有 self._lock**。

        全程在锁内完成「取或建」：
        这样 close_all() 要么看到连接已登记（它知道怎么关），
        要么连接还没被创建 —— 不存在「正在建的同时被关」的窗口。
        """
        c = getattr(self._local, "conn", None)
        gen = getattr(self._local, "gen", -1)
        if c is not None and gen == self._gen:
            return c
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self._local.conn = None
        # 调用方（execute）必须已按统一顺序拿到 _FILE_ACCESS 再进入这里。
        # _FILE_ACCESS 保护「打开/关闭连接」不与增量刷新的 copyfile/os.replace
        # 撞车（实测去掉它会在 shutil.copyfile 覆盖库文件时段错误）。
        # 锁顺序固定为：_FILE_ACCESS → _SqlConn._lock，与 close_all 一致，
        # 杜绝「持 _lock 等 _FILE_ACCESS」的死锁环。
        c = _open_ro(self.path)
        self._local.conn = c
        self._local.gen = self._gen
        self._registry[threading.get_ident()] = c
        return c

    def _need_new_conn(self):
        """当前线程是否需要新建连接（调用方持 self._lock）。"""
        c = getattr(self._local, "conn", None)
        gen = getattr(self._local, "gen", -1)
        return c is None or gen != self._gen

    def execute(self, sql, params=()):
        # 【锁顺序铁律】_FILE_ACCESS → self._lock，全程一致，杜绝死锁。
        #
        # faulthandler 实测踩过两个坑：
        #  1) 死锁：曾在持 self._lock 时去拿 _FILE_ACCESS，
        #     close_all 却持 _FILE_ACCESS 等 self._lock → 环 → API 全超时。
        #  2) 段错误：曾干脆去掉 _FILE_ACCESS，结果增量刷新 shutil.copyfile
        #     覆盖库文件的同时另一线程 sqlite3.connect() → 进程直接崩。
        #
        # 现在：只有「需要新建连接」时才拿全局闸门，且严格在 self._lock 之前拿。
        # 已有连接的热路径完全不碰闸门 → 并发查询性能不受影响。
        with self._lock:
            if not self._need_new_conn():
                c = self._local.conn
                cur = c.execute(sql, params)   # 锁内执行，close 撞不进来
                self._inflight += 1
                return _Cur(cur, self)

        # 需要新建连接：若该文件正在被原子替换，先在门外等
        # （等待期间不持锁，避免与替换线程互等）
        _wait_unblocked(self.path)

        # 需要新建连接：按统一顺序先拿文件闸门，再拿连接锁
        with _FILE_ACCESS:
            with self._lock:
                # 双重检查：等闸门期间别的线程可能已建好
                if not self._need_new_conn():
                    c = self._local.conn
                    cur = c.execute(sql, params)
                    self._inflight += 1
                    return _Cur(cur, self)
                c = self._conn_locked()
                if c is None:
                    raise sqlite3.OperationalError(
                        "cannot open database: %s" % self.path)
                cur = c.execute(sql, params)   # 锁内执行
                self._inflight += 1
        # 租约交给 cursor：结果集没读完之前，连接不会被关掉
        return _Cur(cur, self)

    def close(self):
        """只关闭**当前线程**手里的连接（与 sqlite3.Connection 同语义）。"""
        with self._lock:
            c = getattr(self._local, "conn", None)
            self._local.conn = None
            self._registry.pop(threading.get_ident(), None)
            if c is not None:
                try:
                    c.close()      # 锁内关闭，与 execute 互斥
                except Exception:
                    pass

    def close_all(self, timeout=8.0):
        """跨线程安全地关闭这个文件在**所有**线程里的连接。

        步骤：
          1. 代次 +1：其它线程下次取连接时会发现自己的连接已过期，
             自动重开（顺带适配「文件刚被原子替换」）。
          2. 等在途 SQL 归零（最多 timeout 秒）——
             归零即代表此刻没有任何线程在读这个文件。
          3. 归零则立即关闭所有底层连接；
             若还有读者，则**挂起**关闭（_close_pending），
             由最后一个读者退出时自动补关。

        第 3 步的「挂起」很关键：增量刷新替换明文副本前必须释放文件句柄
        （Windows 上 os.replace 会报 WinError 5），
        但此刻可能正有后台统计在扫这个库。
        直接硬关 → use-after-free → 段错误；
        放弃关闭 → 替换永远失败 → 大屏停在旧数据。
        挂起 + 自动补关两者兼得：
        读者退出的一瞬间句柄就释放了，
        调用方（增量替换的重试循环）下一轮就替换成功。

        返回 True 表示此刻已经关掉了。
        """
        deadline = time.time() + timeout
        with self._lock:
            self._gen += 1
            self._close_pending = True
            while self._inflight > 0 and time.time() < deadline:
                self._cond.wait(0.05)
            if self._inflight > 0:
                return False      # 还有读者 → 挂起，等读者退出时自动补关
        self._close_now()
        return True

    def _close_now(self):
        """真正关闭所有底层连接。

        c.close() 必须在 self._lock 内执行 —— 与 execute() 里的 c.execute()
        严格互斥，否则一边 execute 一边 close 就是 use-after-free 段错误。
        调用前调用方已确保 _inflight==0（没有正在读的游标）。
        """
        with self._lock:
            conns = list(self._registry.values())
            self._registry.clear()
            self._close_pending = False
            for c in conns:
                try:
                    c.close()
                except Exception:
                    pass

    def _maybe_close_pending(self):
        """最后一个读者退出时调用：若挂着「待关闭」，此刻正好可以关。"""
        need = False
        with self._lock:
            if self._close_pending and self._inflight <= 0:
                need = True
        if need:
            self._close_now()


def _open_conn(path):
    """打开一个「可跨线程共享」的连接代理（长期持有的一律用这个）。"""
    return _SqlConn(path)


def _iter_batched(conn, sql, params=(), size=20000):
    """分批迭代查询结果。

    为什么必须分批：连接代理把「结果集还没读完」视为一个**在途操作**，
    close_all() 必须等在途操作归零才能关连接。
    而热力图/词频要一次扫 230 万行（单次迭代几分钟），
    close_all() 会一直等不到 → 连接关不掉
    → Windows 上 os.replace 报 WinError 5 → 增量刷新永远同步不了新消息。

    分批之后，每批之间释放租约 → 在途计数会归零，
    关闭/替换就能在批次间隙插进来（最多损失当前这一批，
    调用方重试即可拿全）。
    """
    cur = conn.execute(sql, params)
    try:
        while True:
            batch = cur.fetchmany(size)
            if not batch:
                break
            for row in batch:
                yield row
            # 批次间隙让出租约：让 close_all() 有机会插进来。
            # 若连接真的被关掉了，下一批 fetchmany 会抛异常，
            # 由调用方重试（连接代理会自动重开）。
            cur.yield_lease()
    finally:
        try:
            cur.close()
        except Exception:
            pass


# ---- 实例与连接登记 ----
# 增量解密替换明文副本前，必须关闭**所有**指向该文件的 SQLite 连接
# （Windows 上 os.replace 不能覆盖被打开的文件，报 WinError 5）。
# 只关「当前缓存的那个实例」是不够的：历史上重建过的实例仍然握着句柄，
# 会让替换永远失败 —— 表现为自动刷新每轮 changed=0、大屏停在旧数据。
#
# 用 WeakSet 登记实例：实例被回收后自动摘除，不会泄漏。
_LIVE_INSTANCES = weakref.WeakSet()


def register_instance(inst):
    """登记 WeChatDB 实例（供 close_file_everywhere 遍历）。"""
    try:
        _LIVE_INSTANCES.add(inst)
    except Exception:
        pass


def close_file_everywhere(path, timeout=2.0):
    """关闭所有存活实例中指向 path 的 SQLite 连接。

    timeout: 等在途 SQL 归零的秒数上限（默认 2 秒）。
      增量替换会连续处理几十个库，每个库都死等 8 秒的话，
      一轮刷新能拖到几分钟，接口直接超时。
      归零不了也没关系 —— _SqlConn 会「挂起关闭」，
      最后一个读者退出时自动补关，替换下一轮就成功。

    返回被关闭的连接数。
    """
    try:
        key = os.path.normcase(os.path.abspath(path))
    except Exception:
        key = os.path.normcase(str(path))
    n = 0
    for inst in list(_LIVE_INSTANCES):
        try:
            n += inst.close_file(key, timeout=timeout) or 0
        except Exception:
            pass
    return n


# ---- 文件替换封锁 ----
# os.replace 前必须保证**没有线程持有该文件的 SQLite 句柄**，
# 否则 Windows 报 WinError 5（不允许替换被打开的文件）。
#
# 只「关连接」是不够的：连接关掉的瞬间，另一个线程（大屏每 20 秒轮询、
# 后台统计线程）又会把它打开 —— 于是 12 次重试全失败，
# 表现为大屏「数据链路 → 同步异常 / 本轮新增 异常」。
#
# 解法：替换期间给该路径打「封锁」标记，
#   · 读者要新建连接时先在门外等（**不持有任何锁**，避免死锁）；
#   · 替换完成后放行，读者自动连到新文件。
_QUARANTINE = set()
_QUAR_CV = threading.Condition()


def _quar_key(path):
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return os.path.normcase(str(path))


def block_file(path):
    """替换前调用：禁止新连接打开该文件（已有连接照常读）。"""
    try:
        with _QUAR_CV:
            _QUARANTINE.add(_quar_key(path))
    except Exception:
        pass


def unblock_file(path):
    """替换完成后调用：放行等待中的读者。"""
    try:
        with _QUAR_CV:
            _QUARANTINE.discard(_quar_key(path))
            _QUAR_CV.notify_all()
    except Exception:
        pass


# 每个线程可以单独设置「文件正被替换时」愿意等多久：
#   · 请求线程：最多等 12 秒。替换窗口通常 0.3~3 秒，
#     等一会儿就能拿到新文件；真等满 12 秒也只影响这一个请求，
#     不会像以前那样把整个接口拖死。
#   · 后台统计/会话统计：等 60 秒（后台任务，等得起）
_BLOCK_WAIT = threading.local()


def set_block_wait(seconds):
    """设置当前线程在「文件正被替换」时的最长等待秒数。"""
    try:
        _BLOCK_WAIT.sec = float(seconds)
    except Exception:
        pass


def _wait_unblocked(path, timeout=12.0):
    """读者侧：文件正被替换时在门外等一下。

    关键：等待期间**不持有** _FILE_ACCESS / 连接锁，
    否则替换线程会拿不到闸门 → 死锁。
    """
    k = _quar_key(path)
    if k not in _QUARANTINE:
        return
    timeout = getattr(_BLOCK_WAIT, "sec", timeout)
    end = time.time() + timeout
    with _QUAR_CV:
        while k in _QUARANTINE:
            left = end - time.time()
            if left <= 0:
                return          # 超时也放行，绝不能把页面卡死
            _QUAR_CV.wait(min(left, 0.3))


# ---- 文件访问闸门 ----
# 打开明文副本的连接会和「原子替换」互相踩：
#   * 连接开着 → os.replace 报 WinError 5（Windows 不允许替换被打开的文件）
#   * 替换进行中 → 新开的连接会读到半新半旧的文件
# 所以临时连接（用完即关的那种）必须在闸门内打开，
# 替换也必须在闸门内完成，两者互斥。
# 这是可重入锁：同一线程内嵌套调用不会自锁。
_FILE_ACCESS = threading.RLock()


def file_access_lock():
    """获取文件访问锁（用于临时连接 / 原子替换的互斥）。"""
    return _FILE_ACCESS


def _md5_hex(s):
    return hashlib.md5(s.encode("utf-8", "ignore")).hexdigest()


# 文本提取：微信 4.x message_content 对富媒体带 `(` 头，纯文本直接是明文
_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F02F"
    "\U0000FE00-\U0000FE0F\U00002190-\U000021FF\U00002B00-\U00002BFF]+"
)
_CJK = re.compile("[\u4e00-\u9fff]")

# 群消息的发送者前缀形如 "wxid_xxx:\n正文" / "gh_xxx:\n正文" / "昵称:\n正文"
# 与 _SENDER_PREFIX_RE 保持一致（同样带捕获组），避免两套规则打架。
_SENDER_PREFIX_SPLIT_RE = re.compile(
    r"^([A-Za-z0-9_\-@\.]{1,64}):\r?\n", re.MULTILINE)


def _split_sender_prefix(raw):
    """拆出微信 4.x 群消息的发送者前缀。

    返回 (正文, 发送者用户名或 None)。
    微信把「发送者ID:换行」写进 message_content 开头；
    私聊没有这个前缀。

    注意：正文可能是 zstd 压缩的二进制，必须先解压，
    否则前缀正则匹配不上（会得到乱码），发送者就丢了。
    """
    if raw is None:
        return "", None
    if isinstance(raw, (bytes, bytearray)):
        plain = _zstd_decompress(raw)
        if plain is not None:
            raw = plain
    if isinstance(raw, (bytes, bytearray)):
        s = raw.decode("utf-8", "ignore")
    else:
        s = str(raw)
    m = _SENDER_PREFIX_SPLIT_RE.match(s)
    if not m:
        return s, None
    return s[m.end():], m.group(1)


def _looks_readable(s):
    """判断一段字符串是否为「真文本」而不是二进制残留。

    微信 4.x 把非纯文本消息（图片/语音/文件/红包等）的内容存在
    message_content 里，用的是内部二进制编码（protobuf + 自定义头）。
    这些内容里偶尔会出现 ASCII 字母/数字，若直接当文本抽取，
    就会得到 'e'、'k' 这种无意义的碎片（实测踩过）。
    """
    if not s:
        return False
    # 控制字符占比过高 → 二进制
    ctrl = sum(1 for ch in s if ord(ch) < 0x20 and ch not in "\t\n\r")
    if ctrl > max(1, len(s) * 0.02):
        return False
    # 出现 U+FFFD（解码失败）→ 曾经是二进制
    if "�" in s:
        return False
    # 不可打印字符（0x80-0x9F 控制区）也算二进制信号
    bad = sum(1 for ch in s if 0x7F <= ord(ch) < 0xA0)
    if bad > max(1, len(s) * 0.01):
        return False
    return True


_XML_TEXT_TAGS = ("title", "des", "content", "des1", "des2", "word",
                  "src", "t", "nickname", "displayname")

# 微信 4.x 的分享类 XML 里，<designername>null</designername>、
# <title>null</title> 这类占位值会被当成正文抽出来，
# 结果词云里出现一片 "null"。这些不是词，直接丢掉。
_XML_NULLISH = {"null", "none", "undefined", "nil", "nan"}

# 群聊消息正文最前面会带一行发送者账号前缀，例如：
#     wxid_<示例账号>:
#     你好，这是群消息正文示例 …
#     <账号>:
#     [奸笑]
# 它是消息体的结构字段，不是用户说的话。
# 不剥掉的话，词云里就会冒出各种账号碎片。
#
# 判定规则要保守，避免误伤正文里正常的 "Ratio:\n…"：
#   · 账号形态：含数字或下划线（wxid_xxx / qq<数字> / <拼音号>）
#   · 或者纯字母但长度 >= 6（拼音号）
#
# 注意：必须有捕获组 —— _split_sender_prefix 要靠 group(1) 拿发送者。
# 这里曾经存在两个同名正则定义，后一个没有捕获组且覆盖了前一个，
# 导致 m.group(1) 抛 IndexError: no such group → 群聊详情页全部打不开。
_SENDER_PREFIX_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_\-\.]{1,39}):(?=\r?\n)")


def _sender_prefix_body(s):
    """判断 s 开头是否是「发送者账号前缀行」。

    返回 (账号, 剩余正文)；不是前缀则返回 (None, s)。
    """
    if not s:
        return None, s
    m = _SENDER_PREFIX_RE.match(s)
    if not m:
        return None, s
    tok = m.group(1)
    body = tok.lstrip("-.")
    looks_id = ("_" in body) or any(ch.isdigit() for ch in body)
    if not (looks_id or len(body) >= 6):
        return None, s
    return tok, s[m.end():].lstrip("\r\n")


def _strip_sender_prefix(s):
    """剥掉群消息正文开头的发送者账号前缀行。"""
    if not s:
        return s
    tok, body = _sender_prefix_body(s)
    return body if tok is not None else s


def _extract_from_xml(s):
    """从微信 4.x 的 XML 消息体里抽出可读文本。

    结构示例（解压后）：
        wxid_xxx:
        <?xml version="1.0"?>
        <msg>
            <appmsg>
                <title>哪里不错</title>
                ...
    优先取 title / des / content；都没有就返回空。
    """
    if not s or "<" not in s:
        return ""
    parts = []
    for tag in _XML_TEXT_TAGS:
        for m in re.finditer(r"<%s[^>]*>(.*?)</%s>" % (tag, tag), s, re.S | re.I):
            v = m.group(1)
            # 去掉嵌套标签
            v = re.sub(r"<[^>]+>", "", v)
            v = (v.replace("&amp;", "&").replace("&lt;", "<")
                  .replace("&gt;", ">").replace("&quot;", '"')
                  .replace("&apos;", "'").replace("&nbsp;", " "))
            v = v.strip()
            if not v:
                continue
            # 占位值（null/none/…）不是正文
            if v.lower() in _XML_NULLISH:
                continue
            parts.append(v)
        if parts:
            break
    if parts:
        return "\n".join(parts[:3]).strip()
    # 没有文本标签：看是不是 <emoji> 之类的表情消息
    if re.search(r"<emoji\b", s, re.I):
        return "[表情]"
    if re.search(r"<img\b", s, re.I):
        return "[图片]"
    if re.search(r"<voice\b", s, re.I):
        return "[语音]"
    if re.search(r"<video\b", s, re.I):
        return "[视频]"
    if re.search(r"<appmsg\b", s, re.I):
        return "[分享]"
    if re.search(r"<sysmsg\b", s, re.I):
        return "[系统消息]"
    return ""


def _zstd_decompress(raw):
    """解压微信 4.x 的 zstd 压缩内容，失败返回 None。

    关键坑：微信 4.x 里 message_content 大多是 zstd 压缩的二进制
    （头部 28 B5 2F FD）。之前只按明文处理，导致新消息/大部分消息
    全被当成二进制丢掉 —— 会话弹层空白、词频统计严重偏小。
    """
    if not isinstance(raw, (bytes, bytearray)):
        return None
    if not raw:
        return None
    # zstd 魔数：0x28 0xB5 0x2F 0xFD
    if raw[:4] != b"\x28\xb5\x2f\xfd":
        # 少数情况下可能没有魔数（帧头被裁掉），也试一次流式解压
        pass
    try:
        import zstandard
    except ImportError:
        return None
    try:
        dctx = zstandard.ZstdDecompressor()
        out = dctx.decompress(bytes(raw), max_output_size=1 << 22)
        if out:
            return out
    except Exception:
        pass
    # 流式模式：兼容带多帧 / 未知长度的数据
    try:
        dctx = zstandard.ZstdDecompressor()
        with dctx.stream_reader(bytes(raw)) as reader:
            out = reader.read(1 << 22)
        if out:
            return out
    except Exception:
        pass
    return None


def _extract_text(raw):
    """从微信 4.x 的 message_content / compress_content 中提取可读文本。

    对二进制内容（图片/语音/文件等内部编码）返回空串，
    避免把二进制里的偶然字节当成消息内容。
    """
    if raw is None:
        return ""
    # zstd 压缩的正文：先解压再走明文逻辑
    if isinstance(raw, (bytes, bytearray)):
        plain = _zstd_decompress(raw)
        if plain is not None:
            raw = plain
    if isinstance(raw, (bytes, bytearray)):
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    else:
        s = str(raw)
    if not s:
        return ""
    # 剥掉群消息开头的发送者账号前缀（wxid_xxx: / <账号>: …）
    s = _strip_sender_prefix(s)
    if not s:
        return ""
    # XML 消息体：单独抽文本标签
    if "<msg" in s or "<appmsg" in s or "<?xml" in s:
        return _extract_from_xml(s)
    if not _looks_readable(s):
        return ""
    # 找到第一个「像文本」的字符（CJK / 字母 / 数字 / emoji）作为起点
    start = None
    for i, ch in enumerate(s):
        o = ord(ch)
        if (_CJK.match(ch) or ('a' <= ch <= 'z') or ('A' <= ch <= 'Z')
                or ('0' <= ch <= '9') or _EMOJI_RE.match(ch)):
            start = i
            break
    if start is None:
        return ""
    s = s[start:]
    # 截到第一个不可打印控制符（二进制残留）
    out = []
    for ch in s:
        o = ord(ch)
        if (o < 0x20 and ch not in "\t\n\r") or o == 0xFFFD:
            break
        out.append(ch)
    return "".join(out).strip()


# ---------- 昵称缓存（跨 WeChatDB 实例共享） ----------
# 为什么不用实例级缓存：
#   增量刷新会把明文副本原子替换，server 必须重建 db 实例才能看到新数据，
#   实例级 _name_cache 随之全部失效 → 300 个会话要重新逐条查 contact.db，
#   实测单次 conversations() 要 9.1 秒，大屏在重建期间只能显示空白。
# 改成模块级 + TTL：跨实例复用，昵称改动最多 5 分钟才生效。
_NAME_CACHE = {}          # username -> (name, ts)
_NAME_CACHE_TTL = 300.0

# 微信内置账号：这些 id 在联系人表里没有昵称（remark/nick/alias 全空），
# 但它们是**系统会话**而不是联系人。给它一个正常名字，
# 否则界面上会出现「未知会话」这种占位，看起来像数据缺失。
_BUILTIN_NAMES = {
    "brandservicesessionholder": "微信服务通知",
    "brandsessionholder": "微信服务通知",
    "weixin": "微信",
    "filehelper": "文件传输助手",
    "fmessage": "微信团队",
    "newsapp": "微信团队",
    "notifymessage": "微信通知",
    "weixinreminder": "微信提醒",
    "tmessage": "腾讯微云",
    "qqmail": "QQ 邮箱",
    "qmessage": "QQ 邮箱",
    "qqsync": "QQ 互联",
    "weibo": "微博",
    "floatbottle": "漂流瓶",
    "medianetty": "微信互联",
}

# ---------- 分表索引（跨 WeChatDB 实例共享） ----------
# 同理：增量刷新会重建 db 实例，而「消息库里有哪 5000+ 张 Msg_ 分表」
# 这个问题扫一遍要几十秒。索引结果只跟**文件**有关，跟连接无关，
# 所以按「文件路径 + 文件大小」共享：
#   * 大小没变 → 分表集合没变，直接复用（绝大多数情况）
#   * 大小变了 → 微信新增了分表，重新扫一次
# 连接本身仍然是每个实例自己的（指向各自的 inode）。
_SHARED_MSG_TABLES = {}    # normpath(path) -> (size, [table names])
_SHARED_NAME2ID = {}       # normpath(path) -> (size, {rsid: user_name})

# ---------- 联系人昵称全量索引（跨 WeChatDB 实例共享） ----------
# 为什么要单独建索引（界面满屏 wxid_ 的根因链）：
#   1) contact 表**没有 username 索引**，单行 `WHERE username=?` 会退化成
#      全表扫描 —— 实测 8.9 万行时单次 35ms。大屏每 15 秒轮询一次，
#      一轮要解析几十上百个 username，CPU 全花在扫表上。
#   2) 增量刷新会原子替换 contact.db。替换窗口内连接被 close，
#      查询抛异常 → contact_name() 降级返回**原始 username**，
#      而这个降级值又被写进 300 秒的模块级缓存 →
#      界面上接下来整整 5 分钟全是原始 ID。
# 修法：把整张 contact 表（+ stranger 表）一次性读进内存做哈希索引。
#   实测构建 0.14s / 8.9 万条，之后 O(1) 命中；
#   按「路径 + 文件大小」共享缓存 → 文件被替换后自动重建。
_SHARED_CONTACT_IDX = {}   # normpath(path) -> (size, {username: 显示名})
_CONTACT_IDX_LOCK = threading.Lock()

# 微信对「没设置昵称/备注」的联系人会写字面量 'null' / 'undefined'，
# 取名时要把它们当成「空」，否则界面上会冒出 "null" 这种像 bug 的字样。
_NULLISH_NAME = ("null", "undefined", "none", "nil")


def _build_contact_index(path):
    """全量读取 contact + stranger 表，构建 {username: 显示名} 内存索引。

    返回模块级共享的索引对象；文件大小没变时直接复用，不重扫。
    显示优先级：备注(remark) > 昵称(nick_name) > 微信号(alias)。
    """
    key = os.path.normpath(path)
    try:
        size = os.path.getsize(path)
    except Exception:
        size = -1
    with _CONTACT_IDX_LOCK:
        cached = _SHARED_CONTACT_IDX.get(key)
        if cached and cached[0] == size:
            return cached[1]

    idx = {}
    # 最多试 2 次：第一次可能正好撞上「文件被替换」，
    # 两次都撞上就用最后一份结果（内容本身是自洽的，见下）。
    for _attempt in range(2):
        size_before = size
        idx = {}
        conn = None
        try:
            # 闸门内完成「打开 + 读完 + 关闭」：
            #   · 与「原子替换明文副本」互斥，不会读到替换到一半的文件；
            #   · 替换线程的 os.replace 只在闸门内做，二者天然互斥；
            #   · 绝不在持有 _db_lock 时拿闸门（锁顺序铁律，会死锁）。
            with _FILE_ACCESS:
                conn = _open_ro(path)
                if conn is None:
                    return {}
                try:
                    tabs = _tables(conn)
                    for t in ("contact", "Contact", "stranger", "Stranger"):
                        if t not in tabs:
                            continue
                        cols = _cols(conn, t)
                        uname = _pick(cols, "UserName", "username", "usrName", "user_name")
                        if not uname:
                            continue
                        nick = _pick(cols, "NickName", "nickname", "nick", "nick_name")
                        remark = _pick(cols, "Remark", "remark", "remarkName",
                                       "conRemark", "remark_name")
                        alias = _pick(cols, "Alias", "alias")
                        wanted = [c for c in (remark, nick, alias) if c]
                        sel = ", ".join('"%s"' % c for c in [uname] + wanted)
                        try:
                            rows = conn.execute(
                                'SELECT %s FROM "%s"' % (sel, t)).fetchall()
                        except Exception:
                            continue
                        for r in rows:
                            try:
                                u = r[0]
                                if not u:
                                    continue
                                nm = ""
                                for i in range(1, len(wanted) + 1):
                                    v = r[i]
                                    if v is None:
                                        continue
                                    sv = str(v).strip()
                                    # 微信对「未设置昵称/备注」的联系人存字面量 'null'，
                                    # 直接用会把界面上显示成 "null"，看着像程序出 bug。
                                    if not sv or sv.lower() in _NULLISH_NAME:
                                        continue
                                    nm = sv
                                    break
                                # contact 表优先；stranger 表只补 contact 没有的
                                if nm and u not in idx:
                                    idx[u] = nm
                            except Exception:
                                continue
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception:
            return {}
        try:
            size = os.path.getsize(path)
        except Exception:
            size = size_before
        if size == size_before:
            break

    with _CONTACT_IDX_LOCK:
        _SHARED_CONTACT_IDX[key] = (size, idx)
    return idx


# ---------- 主读取类 ----------
class WeChatDB:
    def __init__(self, db_dir):
        self.db_dir = db_dir
        self.version = None
        self.msg_conns = []          # [(conn, path)] 所有含消息的库
        self.table_conn = {}         # 逻辑表名(如 Msg_xxx) -> conn （4.x）
        self.table_path = {}         # 逻辑表名 -> 所在库路径（发送者编号按库独立）
        self.aux = {}                # 名称 -> conn（contact/favorite/sns/session）
        self.hash_to_user = {}       # md5(userName) -> userName （4.x）
        self.user_to_hash = {}       # userName -> md5 后缀
        self.table_map = {}          # logical -> physical（兼容旧字段）
        # 4.x 发送者解析：
        #   发送者在每个消息库里有独立的整数编号 real_sender_id，
        #   该编号正是同库 Name2Id 表的 rowid → user_name。
        #   （实测 11546/11547 命中，filehelper 全部消息的编号都映射到本人账号）
        self.sender_map = {}         # db路径 -> {rsid: user_name}
        self.self_names = set()      # 本人账号的用户名集合（各库编号不同但指向同一人）
        self._lazy_name2id = []      # 待加载 Name2Id 的消息库路径
        self._name2id_done = set()   # 已加载 Name2Id 的库路径
        # 归一化路径 -> 连接 的反查表。
        # _mark_self 原来每次都线性扫 msg_conns（20+ 个库）去找对应连接，
        # 而它被每次 messages() 调用 → 大屏轮询时白白扫几百次。
        self._conn_by_norm = {}       # normpath -> conn
        # 自我标定（_mark_self）按「文件大小」缓存：
        # 结果只跟该库的 filehelper 表有关，文件没变就不用重扫。
        self._self_marked = {}        # normpath -> 文件大小（已标定的版本）
        # 惰性索引：大消息库的路径，待需要时再建立「分表名 -> 连接」映射
        self.lazy_msg_files = []
        self._lazy_indexed = set()   # 已建立索引的库路径
        # 索引建立是重操作（5000+ 张分表），必须串行化：
        # 否则统计后台线程和请求线程会同时建索引，重复劳动且互相覆盖。
        self._index_lock = threading.Lock()
        # ---- 连接使用的读写锁 ----
        # 坑（踩过）：sqlite3.connect(..., check_same_thread=False) 允许同一个
        # Connection 对象被多个线程共用，但 SQLite 连接本身的内部状态
        # （prepared statement 缓存、游标栈）**不是线程安全的**。
        # 表现是随机的 ACCESS_VIOLATION（0xC0000005）段错误，
        # 而且没有 Python traceback —— 整个 server.py 进程直接死掉，
        # watchdog 再拉起来，表现为「大屏每隔几十秒就闪断一次」。
        #
        # 触发路径：请求线程在 conn.execute() 的同时，
        # 增量刷新线程调用 close_file() 把同一个连接 close 掉
        # → use-after-free → 段错误。
        #
        # 修法：所有对 conn 的使用（execute / close）都串行化到这把锁上。
        self._db_lock = threading.RLock()
        self._name_cache = {}        # username -> 昵称
        self._contact_tabs = None    # contact 库的表名缓存
        self._hash2user = {}         # normpath(msg库) -> {md5(user_name): user_name}
        self._contact_cols = None    # contact 表的列名缓存
        self.invalid = False         # 连接被 close_file 关掉后置位 → 需重建
        # 最近一次 messages() 查询命中的**原始行数**（过滤前）。
        # 前端用它判断「还有没有更早的消息」——不能用过滤后的条数，
        # 因为空内容/表情消息会被丢掉，条数会少于 page_size。
        self._last_msgs_raw = 0
        self._open_all()
        # 登记到全局表：增量解密替换明文副本前，
        # 要关闭**所有**实例指向该文件的连接（不只是当前缓存的那个）。
        register_instance(self)

    # ---- 惰性：为某个大消息库建立分表索引（只做一次） ----
    def _index_msg_tables(self, conn, path):
        """把一个消息库里的 Msg_ 分表登记到 table_conn。"""
        names = []
        try:
            for (t,) in _iter_batched(
                conn,
                "SELECT name FROM pragma_table_list WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'",
                size=2000,
            ):
                names.append(t)
        except Exception:
            try:
                for (t,) in _iter_batched(
                    conn,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'",
                    size=2000,
                ):
                    names.append(t)
            except Exception:
                pass
        for t in names:
            self.table_conn[t] = conn
            self.table_path[t] = path
        # 共享给后续新建的实例（重建 db 时免去重扫 5000+ 分表）
        try:
            _SHARED_MSG_TABLES[os.path.normpath(path)] = (
                os.path.getsize(path), names)
        except Exception:
            pass
    def _ensure_msg_index(self):
        """确保所有延迟的消息库都已建立索引（仅在确实需要消息表时调用）。

        建索引要扫 5000+ 张分表，属于重操作，必须加锁串行化。

        共享优化：分表名列表按「文件路径 + 大小」缓存在模块级，
        重建 db 实例时直接复用，只需把表名重新绑到新连接上，
        省掉每 20 秒一次的「重扫 5000+ 分表」（那会让大屏的
        「最近消息流」一直超时）。
        """
        with self._index_lock:
            for path in list(self.lazy_msg_files):
                if path in self._lazy_indexed:
                    continue
                self._lazy_indexed.add(path)
                # 长期持有的连接 → 用线程安全代理
                conn = _open_conn(path)
                if not conn:
                    continue
                key = os.path.normpath(path)
                try:
                    size = os.path.getsize(path)
                except Exception:
                    size = -1
                cached = _SHARED_MSG_TABLES.get(key)
                if cached and cached[0] == size and cached[1]:
                    # 复用共享索引：不用再扫，直接绑到新连接
                    names = cached[1]
                    for t in names:
                        self.table_conn[t] = conn
                        self.table_path[t] = path
                else:
                    self._index_msg_tables(conn, path)

    def _conn_for_table(self, table):
        """取某张分表所在的连接；若尚未建立索引则先建立。"""
        conn = self.table_conn.get(table)
        if conn is not None:
            return conn
        if self.lazy_msg_files:
            self._ensure_msg_index()
            return self.table_conn.get(table)
        return None

    # ================= 4.x 发送者解析 =================
    #
    # 微信 4.x 的消息表结构：
    #   Msg_<md5(talker)> 分表，一行一条消息，
    #   real_sender_id = 发送者在本库内的整数编号，
    #   同库的 Name2Id 表 rowid 恰好就是这个编号 → user_name。
    #
    # 关键点：编号空间是**每个 db 独立**的
    #   message_2.db 的 1 号 = message_6.db 的 2 号 = 同一个人（本人）。
    #   所以不能跨库用固定编号判断身份。
    #
    # 自我标定：文件传输助手（filehelper）会话里的消息必然全是本人发的，
    #   取该表出现过的 real_sender_id → Name2Id → 即为本人账号名。
    #   实测 5 个库全部命中同一个用户名。
    def _load_name2id(self, path):
        """加载某消息库的 {rsid: user_name} 映射（惰性，带缓存）。"""
        key = os.path.normpath(path)
        # 连接锁：多个请求线程可能同时要同一个库的映射。
        # 只在「判重 + 记账」时持锁，真正的加载放到锁外面 ——
        # 加载要拿文件闸门（_FILE_ACCESS），
        # 而刷新线程是「持闸门 → 再要 _db_lock」，
        # 持着 _db_lock 再要闸门 = 反向等待 = 死锁
        # （实测直接把 /api/dash 卡死，大屏一直「正在载入」）。
        with self._db_lock:
            if key in self._name2id_done:
                return self.sender_map.get(key, {})
            self._name2id_done.add(key)
        # 共享优化：Name2Id 的映射同样按「路径 + 大小」共享，
        # 重建 db 实例时不用重扫每个消息库的 Name2Id 表。
        try:
            size = os.path.getsize(path)
        except Exception:
            size = -1
        cached = _SHARED_NAME2ID.get(key)
        if cached and cached[0] == size:
            self.sender_map[key] = cached[1]
            return cached[1]
        m = {}
        try:
            # 闸门内打开：避免与「原子替换明文副本」撞车
            with _FILE_ACCESS:
                conn = _open_ro(path)
                if conn:
                    try:
                        for rid, un in conn.execute(
                                "SELECT rowid, user_name FROM Name2Id"):
                            if un:
                                m[int(rid)] = un
                    except Exception:
                        pass
                    conn.close()
        except Exception:
            pass
        self.sender_map[key] = m
        try:
            _SHARED_NAME2ID[key] = (size, m)
        except Exception:
            pass
        return m

    def _mark_self(self, path, conn, table_map):
        """用 filehelper 表标定本人在该库中的用户名。"""
        fh_tbl = "Msg_" + _md5_hex("filehelper")
        conn_ = conn
        # 用反查表定位，避免线性扫 msg_conns（20+ 个库）
        nkey = os.path.normpath(path)
        conn_ = self._conn_by_norm.get(nkey, conn)
        if conn_ is None:
            return
        if fh_tbl not in table_map:
            return
        m = self.sender_map.get(nkey, {})
        try:
            # 不持 _db_lock 执行（见 _v4_messages 里的锁顺序说明）
            rows = conn_.execute(
                'SELECT DISTINCT real_sender_id FROM "%s"' % fh_tbl).fetchall()
        except Exception:
            return
        for (rsid,) in rows:
            un = m.get(int(rsid))
            if un:
                self.self_names.add(un)

    def _ensure_sender_maps(self):
        """确保所有消息库的 Name2Id 映射都已加载，并完成自我标定。"""
        for path in list(self._lazy_name2id):
            key = os.path.normpath(path)
            if key in self._name2id_done:
                continue
            self._load_name2id(path)
            # 自我标定：找 filehelper 表所在库
            # 结果只跟该库内容有关，文件大小没变就不必重扫
            # （大屏每 15 秒轮询一次 messages，这里每次都重扫会拖慢整屏）
            try:
                size = os.path.getsize(path)
            except Exception:
                size = -1
            if self._self_marked.get(key) == size:
                continue
            try:
                # 闸门内打开：避免与「原子替换明文副本」撞车
                with _FILE_ACCESS:
                    cn = _open_ro(path)
            except Exception:
                continue
            if not cn:
                continue
            try:
                tabs = [r[0] for r in cn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name LIKE 'Msg\\_%' ESCAPE '\\'")]
                self._mark_self(path, cn, set(tabs))
                self._self_marked[key] = size
            except Exception:
                pass
            try:
                cn.close()
            except Exception:
                pass

    def _mark_self(self, path, conn, table_map):
        """用 filehelper 表标定本人在该库中的用户名。

        filehelper（文件传输助手）会话里的消息必然全是本人发的，
        因此该表出现过的 real_sender_id 对应的用户名就是本人账号。
        """
        fh_tbl = "Msg_" + _md5_hex("filehelper")
        if fh_tbl not in table_map:
            return
        m = self.sender_map.get(os.path.normpath(path), {})
        try:
            rows = conn.execute(
                'SELECT DISTINCT real_sender_id FROM "%s"' % fh_tbl).fetchall()
        except Exception:
            return
        for (rsid,) in rows:
            un = m.get(int(rsid))
            if un:
                self.self_names.add(un)

    def sender_of(self, rsid, db_path=None):
        """把 real_sender_id 解析成用户名；解析不到返回 None。"""
        if db_path:
            m = self._load_name2id(db_path)
            if m:
                un = m.get(int(rsid))
                if un:
                    return un
        # 退化：任一库命中即可（同一用户名在各库都存在）
        for m in self.sender_map.values():
            un = m.get(int(rsid))
            if un:
                return un
        return None

    def is_self(self, username):
        """该用户名是否是本人账号。"""
        return bool(username) and username in self.self_names

    # ---- 打开目录，探测版本 ----
    def _open_all(self):
        dbfiles = []
        try:
            for f in sorted(os.listdir(self.db_dir)):
                if f.lower().endswith(".db"):
                    dbfiles.append(os.path.join(self.db_dir, f))
        except Exception:
            return

        has_v3_msg = False
        has_v4 = False
        chatname2id_conn = None

        # 按文件名快速判断类型，避免对每个大库都执行 _tables()（那是 1GB 库上最慢的一步）
        # 文件名 -> 逻辑角色
        NAME_ROLES = {
            "message_": "msg", "msg": "msg", "biz_message_": "msg",
            "contact": "contact", "favorite": "fav", "sns": "sns",
            "session": "session", "general": "general", "hardlink": "hardlink",
            "bizchat": "bizchat", "chatbot": "chatbot", "emoticon": "emoticon",
            "head_image": "head_image", "media_": "media", "biz_media_": "media",
            "message_resource": "msg_resource",
        }
        aux_by_name = {
            "contact": "contact", "favorite": "fav", "sns": "sns", "session": "session",
        }

        for path in dbfiles:
            base = os.path.basename(path)
            stem = base[:-3]  # 去掉 .db
            role = None
            for k, v in aux_by_name.items():
                if stem == k or stem.startswith(k + "_"):
                    role = v
                    break

            # 已知是辅助库的，直接开，不用查表名
            if role and role not in self.aux:
                # 长期持有的连接 → 用线程安全代理
                conn = _open_conn(path)
                if conn:
                    self.aux[role] = conn
                    # 记下路径：close_file 需要知道哪个连接对应哪个文件
                    if not hasattr(self, "_aux_path"):
                        self._aux_path = {}
                    self._aux_path[role] = path
                    continue

            # 消息库判定：message_N / msg / biz_message_N。
            # 注意 message_resource 不是消息库（它是 ChatName2Id 的所在地）。
            looks_msg = (
                stem.startswith("biz_message")
                or (stem.startswith("message") and stem != "message_resource")
                or stem.startswith("msg")
            )
            conn = _open_conn(path)
            if not conn:
                continue

            # 大文件：按文件名判断，避免 _tables() 全量扫描（1GB 库上这一步就要几十秒）
            big = os.path.getsize(path) >= 50 * 1024 * 1024

            if looks_msg:
                has_v4 = True
                self.msg_conns.append((conn, path))
                self._conn_by_norm[os.path.normcase(os.path.normpath(path))] = conn
                # 大消息库延迟建索引：只在需要查某张分表时，才为这个库建立
                # 「表名 -> 连接」映射并登记到 self.msg_index，避免启动时扫几千张表的 schema。
                if big:
                    self.lazy_msg_files.append(path)
                else:
                    self._index_msg_tables(conn, path)
                if chatname2id_conn is None:
                    try:
                        conn.execute("SELECT user_name FROM ChatName2Id LIMIT 1").fetchone()
                        chatname2id_conn = conn
                    except Exception:
                        pass
                # 发送者编号表（rowid == real_sender_id），惰性加载
                self._lazy_name2id.append(path)
                continue

            # 小库：走原来的表名探测
            tabs = _tables(conn)
            # 4.x 标志：存在 Msg_ 表或 ChatName2Id
            if any(t.startswith("Msg_") for t in tabs) or ("ChatName2Id" in tabs):
                has_v4 = True
            if "ChatName2Id" in tabs:
                chatname2id_conn = conn
            # 3.x 标志：存在 MSG/message 表
            if any(t in tabs for t in ("MSG", "message", "ChatMsg")):
                has_v3_msg = True
            # 消息库（含 Msg 或 MSG）
            if any(t.startswith("Msg_") for t in tabs) or any(t in tabs for t in ("MSG", "message")):
                self.msg_conns.append((conn, path))
                self._conn_by_norm[os.path.normcase(os.path.normpath(path))] = conn
                for t in tabs:
                    if t.startswith("Msg_"):
                        self.table_conn[t] = conn
                        # 同步登记路径：close_file 靠 table_path 反查连接并关闭。
                        # 漏登 → 句柄泄漏 → 增量刷新替换永远失败。
                        self.table_path[t] = path
            # 辅助库
            for logical, cands in (("contact", ("Contact", "contact")),
                                   ("fav", ("Favorite", "favorite", "fav_db_item", "WCFavorite")),
                                   ("sns", ("SnsInfo", "Sns", "SnsTimeLine")),
                                   ("session", ("Session", "SessionTable"))):
                if logical not in self.aux:
                    for c in cands:
                        if c in tabs:
                            self.aux[logical] = conn
                            # 必须登记路径：close_file 要靠它找到并关闭这条连接。
                            # 漏登会让连接句柄一直被占着 → Windows 下 os.replace 失败。
                            if not hasattr(self, "_aux_path"):
                                self._aux_path = {}
                            self._aux_path[logical] = path
                            break

        # 版本判定：优先 4.x
        if has_v4:
            self.version = 4
            self._build_v4_map(chatname2id_conn)
        elif has_v3_msg:
            self.version = 3
            self._build_v3_map()
        else:
            self.version = 0

    def _build_v4_map(self, chatname2id_conn):
        # 建立 md5(userName) -> userName 的映射（用于会话名反查）
        if chatname2id_conn is not None:
            try:
                for (un,) in _iter_batched(chatname2id_conn,
                                          "SELECT user_name FROM ChatName2Id"):
                    h = _md5_hex(un)
                    self.hash_to_user[h] = un
                    self.user_to_hash[un] = h
            except Exception:
                pass
        # 兜底：若 ChatName2Id 缺失，尝试从 session 表拿 userName
        if not self.hash_to_user and "session" in self.aux:
            try:
                conn = self.aux["session"]
                for row in _iter_batched(conn, "SELECT * FROM SessionTable LIMIT 5000"):
                    d = dict(row)
                    un = d.get("userName") or d.get("username")
                    if un:
                        h = _md5_hex(un)
                        self.hash_to_user[h] = un
                        self.user_to_hash[un] = h
            except Exception:
                pass

    def _build_v3_map(self):
        # 兼容旧代码的 table_map
        for conn, conn_path in self.msg_conns:
            tabs = _tables(conn)
            for logical, cands in (("msg", ("MSG", "message", "ChatMsg")),
                                   ("contact", ("Contact", "contact")),
                                   ("fav", ("Favorite", "favorite")),
                                   ("sns", ("SnsInfo", "Sns"))):
                if logical not in self.table_map and any(c in tabs for c in cands):
                    for c in cands:
                        if c in tabs:
                            self.table_map[logical] = (os.path.basename(conn_path), c)
                            break

    # ---- 关闭 ----
    def close(self):
        """关闭本实例持有的全部连接（跨线程安全）。

        注意：table_conn 里的连接不在 msg_conns/aux 里（它们是同一批
        conn 对象的引用），必须一并关闭，否则文件句柄仍被占用，
        Windows 下 os.replace 会一直失败。

        这里的 conn 是线程安全代理（_SqlConn），
        必须用 close_all()（跨线程关闭）而不是 close()（只关当前线程）——
        后者会让其它线程手里的连接变成悬空句柄。

        并行关闭：一个实例持有 40+ 个库的文件，
        串行等锁会把请求线程卡住好几分钟。
        """
        conns = []
        seen = set()

        def _collect(c):
            if c is None:
                return
            if id(c) in seen:
                return
            seen.add(id(c))
            conns.append(c)

        for conn, _ in list(self.msg_conns):
            _collect(conn)
        for conn in list(self.aux.values()):
            _collect(conn)
        for conn in list(self.table_conn.values()):
            _collect(conn)

        def _one(c):
            try:
                c.close_all(timeout=3.0)
            except Exception:
                pass

        if len(conns) > 4:
            ts = [threading.Thread(target=_one, args=(c,)) for c in conns]
            for t in ts:
                t.start()
            for t in ts:
                t.join(timeout=6.0)
        else:
            for c in conns:
                _one(c)

        self.msg_conns = []
        self.aux = {}
        self.table_conn = {}
        self.table_path = {}

    def close_file(self, path, timeout=2.0):
        """关闭指向指定文件的 SQLite 连接。

        为什么需要：Windows 上 os.replace 会先删除目标文件，
        而 SQLite 打开的文件不允许被删除 → [WinError 5] 拒绝访问。
        增量解密要在替换明文副本前把连接关掉，否则刷新永远失败。

        注意：关闭后 table_conn 里指向该文件的映射要一并清掉，
        否则后续查询会用到已关闭的连接（抛 "closed database"）。

        副作用：置 self.invalid = True。
        调用方（server.get_db）据此丢弃这个实例并重建，
        否则会一直用着一个连接已被关闭的「僵尸实例」。

        返回被关闭的连接数。
        """
        try:
            key = os.path.normcase(os.path.abspath(path))
        except Exception:
            key = os.path.normcase(str(path))
        # 关键：close_all() 内部会等所有在途 SQL 结束再关，
        # 避免「请求线程 close() 掉连接、后台统计线程还在 execute()」
        # 造成的 use-after-free → 段错误（0xC0000005），整个进程直接死。
        with self._db_lock:
            return self._close_file_locked(key, path, timeout=timeout)

    def _close_file_locked(self, key, path=None, timeout=2.0):
        closed = 0
        # 收集要关闭的代理。
        # 必须去重：同一个文件里的几千张 Msg_ 分表共享**同一个**代理对象，
        # 不去重的话会对同一个代理调用几千次 close_all（每次最多等 8 秒）
        # → 增量刷新卡死几分钟。
        targets = []
        seen = set()

        def _pick(conn):
            if conn is None:
                return
            if id(conn) in seen:
                return
            seen.add(id(conn))
            targets.append(conn)

        # 消息库连接：只收集要关闭的代理，**保留**映射
        # （连接代理会自动重开，映射不该被清掉）
        for conn, p in list(self.msg_conns):
            try:
                if os.path.normcase(os.path.abspath(p)) == key:
                    _pick(conn)
            except Exception:
                pass
        # 辅助库连接（contact/fav/sns/session）
        aux_path = getattr(self, "_aux_path", {}) or {}
        for role, conn in list(self.aux.items()):
            p = aux_path.get(role)
            if not p:
                continue
            try:
                if os.path.normcase(os.path.abspath(p)) == key:
                    _pick(conn)
            except Exception:
                pass
        # 分表映射：同样只收集要关的代理，映射保留
        for t, p in list(self.table_path.items()):
            try:
                if os.path.normcase(os.path.abspath(p)) == key:
                    _pick(self.table_conn.get(t))
            except Exception:
                pass
        # 反查表：被关掉的连接不能留在里面，
        # 否则 _mark_self 会拿到已关闭的连接。
        # （原来这里写的是 os.path.normpath(path)，但本函数的形参是 key，
        #  path 未定义 → NameError 被下面的 except 吞掉，
        #  反查表实际从未被清理过。）
        try:
            for cand in (os.path.normpath(path) if path else None, key):
                if cand and cand in self._conn_by_norm:
                    del self._conn_by_norm[cand]
        except Exception:
            pass
        # 【重要】这里**不再**清空 self.aux / self.table_conn / self.table_path。
        #
        # 为什么：这些是「表名 → 连接」的映射，与连接是否被关闭无关。
        # 连接代理有「代次」机制 —— 被 close_all() 关掉的连接，
        # 下次使用时会自动重开（自动适配「文件刚被原子替换」）。
        #
        # 之前一清空，后果是：增量刷新每 20 秒关一次连接，
        # 正在跑的后台统计（用同一个实例）手里的表映射瞬间被清空
        # → text_corpus() 遍历不到任何表 → 词频/表情统计恒为 0，
        # 而日志里连一行错误都没有（因为压根没抛异常，是"查了个空"）。
        #
        # 只把「惰性索引」标记为待重建：
        # 文件被替换后可能新增了 Msg_ 分表，索引要重新扫一次。
        try:
            self._lazy_indexed.discard(key)
        except Exception:
            pass
        self.invalid = True

        # 统一关闭（并行）：去重后通常只有 1~2 个代理
        def _one(c):
            try:
                c.close_all(timeout=timeout)
            except Exception:
                pass

        if len(targets) > 1:
            ts = [threading.Thread(target=_one, args=(c,)) for c in targets]
            for t in ts:
                t.start()
            for t in ts:
                t.join(timeout=10.0)
        else:
            for c in targets:
                _one(c)
        closed = len(targets)
        return closed

    def close_thread_conns(self):
        """关闭**当前线程**在实例上打开的所有连接。

        为什么必须做：HTTP 服务器是「一个请求一个线程」，
        线程结束后线程里的 SQLite 连接仍留在连接代理的注册表里，
        文件句柄一直被占着 —— Windows 上 os.replace 永远失败
        （增量刷新每轮报「同步异常」），而且大屏接口会被拖到超时。

        请求结束时主动关掉，文件锁才真正释放。
        下次要用时连接代理会自动重开（代次机制），无副作用。
        """
        for conn, _p in list(self.msg_conns):
            try:
                conn.close()
            except Exception:
                pass
        for _role, conn in list(self.aux.items()):
            try:
                conn.close()
            except Exception:
                pass

    def close_all_files(self):
        """关闭所有连接（替换多个文件前统一调用）。"""
        conns = []
        seen = set()

        def _collect(c):
            if c is None or id(c) in seen:
                return
            seen.add(id(c))
            conns.append(c)

        for conn, _ in list(self.msg_conns):
            _collect(conn)
        for conn in list(self.aux.values()):
            _collect(conn)

        def _one(c):
            try:
                # 注意：这里原本写的是 timeout=timeout，
                # 而本函数没有 timeout 参数 → NameError 被 except 吞掉
                # → 整个「关闭全部连接」动作其实从没执行过。
                c.close_all(timeout=2.0)
            except Exception:
                pass

        if len(conns) > 4:
            ts = [threading.Thread(target=_one, args=(c,)) for c in conns]
            for t in ts:
                t.start()
            for t in ts:
                t.join(timeout=10.0)
        else:
            for c in conns:
                _one(c)

        self.msg_conns = []
        self.table_conn = {}
        self.table_path = {}
        self.aux = {}
        self.lazy_msg_files = []
        self._lazy_indexed = set()
        self._conn_by_norm = {}
        self._self_marked = {}

    # ================= 统一 API =================
    def conversations(self, limit=300):
        if self.version == 3:
            return self._v3_conversations(limit)
        if self.version == 4:
            return self._v4_conversations(limit)
        return []

    def _v3_conversations(self, limit):
        if "msg" not in self.table_map:
            return []
        f, t = self.table_map["msg"]
        conn = self._conn_by_file(f)
        cols = _cols(conn, t)
        talker = _pick(cols, "strTalker", "talker", "strUsrName")
        ctime = _pick(cols, "createTime", "createtime", "time")
        if not talker:
            return []
        sql = f'SELECT "{talker}" AS talker, COUNT(*) AS cnt, MAX("{ctime}") AS last_time FROM "{t}" GROUP BY "{talker}" ORDER BY cnt DESC LIMIT ?'
        rows = conn.execute(sql, (limit,)).fetchall()
        out = []
        for r in rows:
            name = self.contact_name(r["talker"])
            out.append({"talker": r["talker"], "name": name, "count": r["cnt"], "last_time": r["last_time"] or 0})
        return out

    def _v4_conversations(self, limit):
        # 4.x 的 Msg_ 分表可能有数千张，逐表 COUNT(*) 全扫会长时间占用 GIL，
        # 把整个服务卡死（表现为白屏/请求超时）。
        #
        # 策略：
        #  1) 会话清单直接取自 session.db 的 SessionTable —— 微信自己维护的会话表，
        #     读取是毫秒级，不需要碰消息库
        #  2) 消息计数改为「惰性」：这个函数只出清单和最后活跃时间，
        #     计数由调用方按需触发（见 count_conversation），不阻塞首屏
        sessions = self._v4_session_rows()
        last_by_user = dict(sessions) if sessions else {}

        # 会话清单：优先 session 表（微信自己维护，覆盖最全）；
        # ChatName2Id 映射作为补充（session 表里没有但确实有消息库的会话）
        candidates = []
        seen = set()
        for u, t in sessions:
            candidates.append((u, int(t or 0)))
            seen.add(u)
        for h, user in self.hash_to_user.items():
            if user not in seen:
                candidates.append((user, int(last_by_user.get(user) or 0)))
                seen.add(user)

        # 按最后活跃时间倒序
        candidates.sort(key=lambda x: -x[1])

        out = []
        for user, last_time in candidates[:limit]:
            out.append({
                "talker": user,
                "name": self.contact_name(user),
                "count": 0,
                "last_time": last_time,
            })
        return out

    def count_conversation(self, talker):
        """按需统计单个会话的消息数（惰性，不阻塞首屏）。

        注意：user_to_hash 里可能没有该会话（新会话、会话表未建/未刷新时），
        此时必须像 _v4_table 一样用 md5(talker) 兜底 —— 否则明明有消息
        却统计成 0 条（大屏 Top 会话会出现「0 条」的活跃群）。
        """
        h = self.user_to_hash.get(talker)
        if not h:
            h = _md5_hex(talker)
        conn = self._conn_for_table("Msg_" + h)
        if not conn:
            return 0
        return _count_rows_safe(conn, "Msg_" + h)

    def last_message_time(self, talker):
        """取该会话最后一条消息的时间（秒级时间戳）。

        为什么不用 session 表的 sort_timestamp：
          那是微信给「会话列表排序」用的字段，会话有新消息时才会动，
          但它不等于该会话最后一条消息的时间（微信可能因为置顶、
          未读数变化等原因重排会话）。
          要判断「这个会话最近在聊什么」，直接查消息表 MAX(create_time)
          最准 —— 每张分表都有 create_time 索引，取最大值很快。

        查不到时返回 0，调用方回退到 session 表的时间。
        """
        h = self.user_to_hash.get(talker)
        if not h:
            h = _md5_hex(talker)   # 同 count_conversation：查不到映射就按 md5 兜底
        conn = self._conn_for_table("Msg_" + h)
        if not conn:
            return 0
        try:
            cols = _cols(conn, "Msg_" + h)
            ctime = _pick(cols, "create_time", "createTime", "time")
            if not ctime:
                return 0
            v = conn.execute(
                f'SELECT MAX("{ctime}") FROM "Msg_{h}"').fetchone()[0]
            return int(v or 0)
        except Exception:
            return 0

        # 回退：没有 session 表时仍走原逻辑
        out = []
        for h, user in self.hash_to_user.items():
            table = "Msg_" + h
            conn = self._conn_for_table(table)
            if not conn:
                continue
            cnt = _count_rows_safe(conn, table)
            if cnt == 0:
                continue
            try:
                last = conn.execute(f'SELECT MAX(create_time) FROM "{table}"').fetchone()[0] or 0
            except Exception:
                last = 0
            out.append({"talker": user, "name": self.contact_name(user), "count": cnt, "last_time": int(last)})
        out.sort(key=lambda x: -x["count"])
        return out[:limit]

    def _v4_session_rows(self):
        """从 session.db 的 SessionTable 取 (username, 最后活跃时间)，不含消息计数。"""
        conn = self.aux.get("session")
        if not conn:
            return []
        try:
            tabs = _tables(conn)
        except Exception:
            return []
        if "SessionTable" not in tabs:
            return []
        try:
            cols = _cols(conn, "SessionTable")
        except Exception:
            return []
        user_c = _pick(cols, "username", "userName", "strUserName", "talker")
        if not user_c:
            return []
        # 优先 sort_timestamp（排序用），其次 last_timestamp
        time_c = _pick(cols, "sort_timestamp", "last_timestamp", "sortSequence", "lastMsgTime")
        try:
            if time_c:
                rows = conn.execute(
                    f'SELECT "{user_c}", MAX("{time_c}") FROM "SessionTable" GROUP BY "{user_c}"'
                ).fetchall()
            else:
                rows = conn.execute(f'SELECT "{user_c}" FROM "SessionTable"').fetchall()
        except Exception:
            return []
        out = []
        for r in rows:
            # conn.row_factory 可能是 sqlite3.Row，单列查询也返回 Row，
            # 统一取成普通 Python 值（str/int）
            u = t = None
            try:
                if isinstance(r, (list, tuple)):
                    u = r[0]
                    t = r[1] if len(r) > 1 else 0
                else:
                    # sqlite3.Row：按位置取值
                    u = r[0]
                    t = r[1] if len(r) > 1 else 0
            except Exception:
                continue
            if u is None:
                continue
            if not isinstance(u, str):
                try:
                    u = str(u)
                except Exception:
                    continue
            try:
                t = int(t or 0)
            except Exception:
                t = 0
            out.append((u, t))
        return out

    def contact_name(self, username):
        """把用户名解析成**显示名**（备注 / 昵称 / 群名）。

        约定：解析不到时返回**空字符串** ——
        绝不把原始 username（wxid_xxx / 哈希 / @chatroom）当名字返回，
        否则界面上会出现一大片原始 ID（这正是被投诉的那个问题）。

        缓存策略：只缓存**解析成功**的名字。
        以前连「查不到」的原始 username 也一起缓存 300 秒，
        联系人库被替换后要 5 分钟才恢复，界面上就是满屏 ID。
        """
        if not username:
            return ""
        now = time.time()
        hit = _NAME_CACHE.get(username)
        if hit is not None and (now - hit[1]) < _NAME_CACHE_TTL:
            return hit[0]
        if self.is_self(username):
            # 本人账号在 contact 表里通常没有昵称记录，统一显示为「我」
            _NAME_CACHE[username] = ("我", now)
            self._name_cache[username] = "我"
            return "我"
        builtin = _BUILTIN_NAMES.get(username)
        if builtin:
            _NAME_CACHE[username] = (builtin, now)
            self._name_cache[username] = builtin
            return builtin
        name = self._contact_name_raw(username)
        if name:
            _NAME_CACHE[username] = (name, now)
            self._name_cache[username] = name
        return name

    def _contact_index(self):
        """联系人昵称内存索引（惰性构建 + 模块级共享）。"""
        path = (getattr(self, "_aux_path", {}) or {}).get("contact")
        if not path:
            return {}
        try:
            return _build_contact_index(path)
        except Exception:
            return {}

    def _contact_name_raw(self, username):
        # 快路径：内存全量索引（O(1) 命中），
        # 取代原来每次 35ms 的「WHERE username=?」全表扫描。
        idx = self._contact_index()
        if idx:
            return idx.get(username) or ""
        # 兜底：索引没建起来（联系人库正好在被替换）→ 单行查询。
        if "contact" not in self.aux:
            return ""
        conn = self.aux["contact"]
        # 试探常见表名
        for t in ("contact", "Contact"):
            tabs = self._contact_tabs
            if tabs is None:
                tabs = _tables(conn)
                self._contact_tabs = tabs
            if t not in tabs:
                continue
            cols = self._contact_cols
            if cols is None:
                cols = _cols(conn, t)
                self._contact_cols = cols
            uname = _pick(cols, "UserName", "username", "usrName", "user_name")
            nick = _pick(cols, "NickName", "nickname", "nick", "nick_name")
            remark = _pick(cols, "Remark", "remark", "remarkName", "conRemark", "remark_name")
            alias = _pick(cols, "Alias", "alias")
            if not uname:
                continue
            try:
                row = conn.execute(f'SELECT * FROM "{t}" WHERE "{uname}"=?', (username,)).fetchone()
            except Exception:
                row = None
            if not row:
                continue
            r = dict(row)
            name = r.get(remark) or r.get(nick) or r.get(alias) or ""
            return (str(name).strip() if name else "")
        return ""

    def _user_for_table(self, table, h):
        """分表名（Msg_<md5>）→ 用户名。

        优先用 ChatName2Id 的全局映射；
        缺失时用该分表**所在消息库**的 Name2Id 反查 ——
        实测有 900 多张分表的 md5 不在 ChatName2Id 里，
        但它们都能在本库的 Name2Id 中通过 md5(user_name) 命中。
        解析不到时返回空字符串（不返回裸哈希）。
        """
        if not h:
            return ""
        u = self.hash_to_user.get(h)
        if u:
            return u
        path = self.table_path.get(table)
        if path:
            hm = self._hash2user_of(path)
            u = hm.get(h)
            if u:
                self.hash_to_user[h] = u
                self.user_to_hash.setdefault(u, h)
                return u
        return ""

    def _hash2user_of(self, path):
        """某个消息库的 {md5(user_name): user_name} 映射（按库缓存）。"""
        key = os.path.normpath(path)
        cached = self._hash2user.get(key)
        if cached is not None:
            return cached
        m = self._load_name2id(path)
        hm = {}
        for un in set(m.values() or ()):
            if un:
                hm[_md5_hex(un)] = un
        self._hash2user[key] = hm
        return hm

    def message_count(self, talker):
        if self.version == 3:
            if "msg" not in self.table_map:
                return 0
            f, t = self.table_map["msg"]
            conn = self._conn_by_file(f)
            cols = _cols(conn, t)
            talker_c = _pick(cols, "strTalker", "talker")
            if not talker_c:
                return 0
            return conn.execute(f'SELECT COUNT(*) FROM "{t}" WHERE "{talker_c}"=?', (talker,)).fetchone()[0]
        if self.version == 4:
            conn, table = self._v4_table(talker)
            if not conn:
                return 0
            return _count_rows_safe(conn, table)
        return 0

    def messages(self, talker, page=0, page_size=50, order="asc"):
        """按会话取消息。

        order="asc"  —— 最早的在前（配合 page 分页往历史方向翻）
        order="desc" —— 最新的在前（会话详情默认只看最近的消息）
        """
        if self.version == 3:
            return self._v3_messages(talker, page, page_size, order)
        if self.version == 4:
            return self._v4_messages(talker, page, page_size, order)
        return []

    def _v3_messages(self, talker, page, page_size, order="asc"):
        if "msg" not in self.table_map:
            return []
        f, t = self.table_map["msg"]
        conn = self._conn_by_file(f)
        cols = _cols(conn, t)
        talker_c = _pick(cols, "strTalker", "talker")
        content = _pick(cols, "strContent", "content", "msg")
        ctime = _pick(cols, "createTime", "createtime")
        isSend = _pick(cols, "IsSender", "isSend", "is sender")
        if not (talker_c and content):
            return []
        where = f'"{talker_c}"=?' if talker else "1=1"
        params = [talker] if talker else []
        order_col = ctime or "ROWID"
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        sql = f'SELECT "{content}" AS content, "{ctime}" AS ctime, "{isSend}" AS isSend FROM "{t}" WHERE {where} ORDER BY "{order_col}" {direction} LIMIT ? OFFSET ?'
        rows = conn.execute(sql, params + [page_size, page * page_size]).fetchall()
        self._last_msgs_raw = len(rows)
        return [{"content": (r["content"] or ""), "time": self._norm_time(r["ctime"]),
                 "isSend": int(r["isSend"] or 0)} for r in rows]

    def _v4_table(self, talker):
        h = self.user_to_hash.get(talker)
        if not h:
            h = _md5_hex(talker)
        table = "Msg_" + h
        conn = self._conn_for_table(table)
        return conn, table

    def _v4_messages(self, talker, page, page_size, order="asc"):
        conn, table = self._v4_table(talker)
        if not conn:
            return []
        self._ensure_sender_maps()
        try:
            cols = _cols(conn, table)
        except Exception:
            return []
        content = _pick(cols, "message_content", "compress_content", "content")
        ctime = _pick(cols, "create_time", "createTime", "time")
        rsid_c = _pick(cols, "real_sender_id", "sender_id")
        if not content:
            return []
        # 【排序键铁律】不要用 create_time 排序：
        #   微信 4.x 消息表的 create_time 列**没有索引**，ORDER BY create_time
        #   会全表扫描；大群库（message_6.db 9350 行）里若有损坏的 btree 页，
        #   扫描必然踩中 → "database disk image is malformed" → 被 except 吞掉
        #   返回空消息，且重试/等待把对话框加载拖到几秒~10秒。
        #   sort_seq 有索引、local_id/rowid 天然有序，语义等价（微信按 sort_seq 排序），
        #   实测 0.001s 且不会踩损坏页。create_time 仍作为输出字段显示时间。
        seq_c = _pick(cols, "sort_seq", "server_seq")
        order_col = seq_c or ("local_id" if "local_id" in cols else "ROWID")
        # 发送者编号表（该表所在库的 Name2Id.rowid）
        db_path = self.table_path.get(table)
        if db_path:
            self._load_name2id(db_path)
        sel = f'"{content}" AS content, "{ctime}" AS ctime'
        if rsid_c:
            sel += f', "{rsid_c}" AS rsid'
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        sql = (f'SELECT {sel} FROM "{table}" '
               f'ORDER BY "{order_col}" {direction} LIMIT ? OFFSET ?')
        # 【锁顺序铁律】不要持着 _db_lock 去执行 SQL：
        #   执行内部可能要拿文件闸门（新建连接时），
        #   而刷新线程是「持闸门 → 再要 _db_lock」→ 反向等待就是死锁，
        #   实测直接把 /api/dash 卡到超时、大屏一直「正在载入」。
        # 连接代理 _SqlConn 本身就是线程安全的（代次 + 在途租约），
        # 这里不需要再额外串行化。
        try:
            rows = conn.execute(sql, [page_size, page * page_size]).fetchall()
        except Exception:
            return []
        out = []
        for r in rows:
            txt, sender = _split_sender_prefix(r["content"])
            txt = _extract_text(txt)
            if not txt:
                continue
            if not sender and rsid_c and db_path:
                sender = self.sender_of(r["rsid"], db_path)
            item = {"content": txt, "time": self._norm_time(r["ctime"]),
                    "isSend": 1 if self.is_self(sender) else 0,
                    "sender": sender or ""}
            if sender:
                item["sender_name"] = self.contact_name(sender)
            out.append(item)
        # 关键：过滤后可能少于 page_size（空内容被丢掉），
        # 前端据此判断「还有没有更早的消息」时必须用**原始行数**，
        # 否则会误判成最后一页 → 「加载更早」按钮永远不出现。
        self._last_msgs_raw = len(rows)
        return out

    def search(self, q, limit=200, talker=None):
        if self.version == 3:
            return self._v3_search(q, limit, talker)
        if self.version == 4:
            return self._v4_search(q, limit, talker)
        return []

    def _v3_search(self, q, limit, talker):
        if "msg" not in self.table_map:
            return []
        f, t = self.table_map["msg"]
        conn = self._conn_by_file(f)
        cols = _cols(conn, t)
        talker_c = _pick(cols, "strTalker", "talker")
        content = _pick(cols, "strContent", "content")
        ctime = _pick(cols, "createTime", "createtime")
        isSend = _pick(cols, "IsSender", "isSend")
        if not content:
            return []
        where = f'"{content}" LIKE ?'
        params = [f"%{q}%"]
        if talker:
            where += f' AND "{talker_c}"=?'
            params.append(talker)
        order_col = ctime or "ROWID"
        sql = f'SELECT "{content}" AS content, "{ctime}" AS ctime, "{talker_c}" AS talker, "{isSend}" AS isSend FROM "{t}" WHERE {where} ORDER BY "{order_col}" DESC LIMIT ?'
        rows = conn.execute(sql, params + [limit]).fetchall()
        return [{"talker": r["talker"], "name": self.contact_name(r["talker"]),
                 "content": (r["content"] or ""), "time": self._norm_time(r["ctime"]),
                 "isSend": int(r["isSend"] or 0)} for r in rows]

    def _v4_search(self, q, limit, talker):
        out = []
        like = f"%{q}%"
        # 若限定会话，只查该表；否则全表扫描
        tables = []
        if talker:
            conn, table = self._v4_table(talker)
            if conn:
                tables = [(conn, table)]
        else:
            # 全库检索：必须先建全量分表索引，否则 table_conn 是空的，
            # 搜不到任何东西（table_path 也依赖它才能反查分表所属库）。
            if self.lazy_msg_files:
                self._ensure_msg_index()
            seen = set()
            for table, conn in self.table_conn.items():
                if table not in seen:
                    seen.add(table)
                    tables.append((conn, table))
        for conn, table in tables:
            try:
                cols = _cols(conn, table)
            except Exception:
                continue
            content = _pick(cols, "message_content", "compress_content", "content")
            ctime = _pick(cols, "create_time", "createTime")
            if not content:
                continue
            try:
                rows = conn.execute(
                    f'SELECT "{content}" AS content, "{ctime}" AS ctime FROM "{table}" WHERE "{content}" LIKE ? ORDER BY "{ctime or "ROWID"}" DESC LIMIT ?',
                    (like, 50)).fetchall()
            except Exception:
                continue
            h = table.split("_", 1)[1] if "_" in table else ""
            # 不要用 `hash_to_user.get(h, h)`：查不到时会把裸 md5 当成用户名，
            # 搜索结果里就全是 32 位哈希。这里逐级回退到所在库的 Name2Id。
            user = self._user_for_table(table, h)
            for r in rows:
                txt = _extract_text(r["content"])
                if q.lower() in txt.lower():
                    out.append({"talker": user, "name": self.contact_name(user),
                                "content": txt, "time": self._norm_time(r["ctime"]), "isSend": 0})
                    if len(out) >= limit:
                        return out
        return out

    def time_heatmap(self, talker=None):
        """7×24 活跃热力。

        性能要点（这个函数曾经让整个大屏白屏 40+ 秒）：
          4.x 有 5400+ 张分表、230 万条消息。四种写法实测对比：
            · 逐行 Python 循环 + fromtimestamp        → 52 秒
            · SQL GROUP BY 星期/小时                  → 30~57 秒（要建临时 B 树排序）
            · 168×SUM(CASE) 在 SQL 里一次算完          → 9.6 秒/单库
            · fetchmany 批量取时间戳 + Python 算术聚合 → 3.0 秒  ← 采用

          为什么最后这个最快：
            COUNT(*) 全库只要 4 秒，说明**读数据不是瓶颈**，
            瓶颈是「每行都过一次 Python 对象转换 + 5482 次查询往返」。
            改用 fetchmany(20000) 批量取，把 230 万个时间戳一次性灌进
            array('q')（C 层连续内存），再用纯整数算术分桶：
                星期 = (local_ts // 86400 + 3) % 7     （1970-01-01 是周四，周一=0）
                小时 = (local_ts % 86400) // 3600
            完全不碰 datetime.fromtimestamp，纯整数运算快一个量级。

        时间戳兼容：微信不同时期写入的 create_time 有秒和毫秒两种，
        在 SQL 侧用 CASE 归一到秒。
        """
        mat = [[0] * 24 for _ in range(7)]
        if self.version == 3:
            import datetime
            for row in self._iter_msg_rows(talker, cols=("ctime",)):
                ts = self._norm_time(row.get("ctime"))
                if not ts:
                    continue
                dt = datetime.datetime.fromtimestamp(ts)
                mat[dt.weekday()][dt.hour] += 1
            return mat
        if self.version != 4:
            return mat

        # 4.x：批量取时间戳 → Python 侧整数分桶
        import array as _array
        # 热力图要覆盖全部消息表，但索引是惰性建的（只有查某会话时才建）。
        # 这里主动建全量索引，否则只会统计到已建索引的那部分。
        if not talker and self.lazy_msg_files:
            self._ensure_msg_index()
        tables = []
        if talker:
            conn, table = self._v4_table(talker)
            if conn:
                tables = [(conn, table)]
        else:
            seen = set()
            for table, conn in self.table_conn.items():
                if table not in seen:
                    seen.add(table)
                    tables.append((conn, table))

        stamps = _array.array("q")
        for conn, table in tables:
            # 逐表收集 + 失败重试：
            # 增量刷新会在替换明文副本前 close_all() 所有连接，
            # 正好可能打在 fetchmany 的批次中间 → 本批抛异常。
            # 连接代理会自动重开（代次机制），重试一次即可拿全这张表。
            # 注意用局部缓冲，出错就清空重来，避免重复计数。
            local = _array.array("q")
            for attempt in range(2):
                try:
                    cc = _cols(conn, table)
                    ctime = _pick(cc, "create_time", "createTime")
                    if not ctime:
                        local = _array.array("q")
                        break
                    # 毫秒 → 秒（SQL 侧归一，避免 Python 里再判断）
                    expr = (f'CASE WHEN "{ctime}" > 100000000000'
                            f' THEN "{ctime}"/1000 ELSE "{ctime}" END')
                    cur = conn.execute(f'SELECT {expr} FROM "{table}"')
                    while True:
                        batch = cur.fetchmany(20000)
                        if not batch:
                            break
                        local.extend(x[0] for x in batch if x[0] and x[0] > 0)
                        # 批次间隙让出租约：让增量刷新的「关连接+替换文件」
                        # 能插进来（否则连接永远关不掉 → 刷新永远失败）
                        cur.yield_lease()
                    break
                except Exception:
                    local = _array.array("q")
                    continue
            stamps.extend(local)
            # 释放这个库的文件句柄（连接代理：只关当前线程这一份）。
            # 不关的话连接一直开着 → 增量刷新 os.replace 直接报 WinError 5
            # → 这个库这一轮刷不进去 → 大屏「数据链路」显示同步异常。
            try:
                conn.close()
            except Exception:
                pass

        off = int(-time.timezone)   # 本地时区偏移（秒），与 fromtimestamp 对齐
        for ts in stamps:
            lts = ts + off
            mat[((lts // 86400 + 3) % 7)][(lts % 86400) // 3600] += 1
        return mat

    def text_corpus(self, talker=None, limit=40000):
        """返回文本列表（用于词频）。limit 控制读取条数，避免真实大数据过慢。"""
        # 与 time_heatmap 一致：全量统计时先建全量索引。
        # 4.x 的消息分表索引是惰性建的（只有查某会话时才建那一张），
        # 不主动建全量索引就只能扫到已建索引的那几张表 → 词频统计出 0 条。
        if not talker and self.lazy_msg_files:
            self._ensure_msg_index()
        texts = []
        for row in self._iter_msg_rows(talker, cols=("content",)):
            raw = row.get("content")
            txt = _extract_text(raw)
            if txt:
                texts.append(txt)
                if len(texts) >= limit:
                    return texts
        return texts

    def english_name_stopwords(self):
        """从通讯录提取「英文人名」停用词表（带缓存）。

        聊天里出现的英文人名（jason / xiao / hl …）来自联系人账号或昵称。
        它们在词云里是纯噪声：既不是话题，也不是关键词。
        这里从 contact 表的 username/alias/remark 里抽出纯拉丁词，
        作为动态停用词传给 word_emoji_freq。

        注意：
          · 只取「不含中文」的值 —— 带中文的昵称已被中文分词接管；
          · 排除系统账号前缀（wxid/gh/chatroom/openim…）；
          · 排除非常短（< 3 字母）的词，避免误伤常用缩写；
          · 结果缓存，避免每次统计都扫 8 万行通讯录。
        """
        if getattr(self, "_en_stop_cache", None) is not None:
            return self._en_stop_cache
        words = set()
        try:
            conn = self.aux.get("contact")
            if conn is not None:
                tabs = _tables(conn)
                for t in ("contact", "Contact"):
                    if t not in tabs:
                        continue
                    cols = _cols(conn, t)
                    uname = _pick(cols, "UserName", "username", "usrName", "user_name")
                    alias = _pick(cols, "Alias", "alias")
                    remark = _pick(cols, "Remark", "remark", "remarkName", "remark_name")
                    nick = _pick(cols, "NickName", "nickname", "nick", "nick_name")
                    sel = [c for c in (uname, alias, remark, nick) if c]
                    if not sel:
                        continue
                    sql = "SELECT %s FROM \"%s\"" % (", ".join('"%s"' % c for c in sel), t)
                    for row in _iter_batched(conn, sql, size=20000):
                        d = dict(row)
                        for c in sel:
                            v = d.get(c)
                            if not v or not isinstance(v, str):
                                continue
                            if re.search(r"[\u4e00-\u9fff]", v):
                                continue          # 中文昵称不算英文名
                            for tok in re.findall(r"[A-Za-z][A-Za-z0-9]*", v):
                                low = tok.lower()
                                if len(low) < 3 or len(low) > 20:
                                    continue
                                if low in _EN_NOISE:
                                    continue
                                if low.startswith(("wxid", "gh", "openim", "chatroom")):
                                    continue
                                words.add(low)
                    break
        except Exception:
            pass
        self._en_stop_cache = words
        return words

    def messages_filtered(self, talker=None, year=None, limit=None, offset=0):
        """按会话/年份过滤，用于年度总结。真实大数据下建议带 limit。"""
        out = []
        import datetime
        for row in self._iter_msg_rows(talker, cols=("ctime", "content"), year=year):
            ts = self._norm_time(row.get("ctime"))
            txt = _extract_text(row.get("content"))
            if not txt:
                continue
            out.append({"talker": row.get("talker"), "name": self.contact_name(row.get("talker")),
                        "content": txt, "time": ts, "isSend": 0})
            if limit and len(out) >= limit:
                break
        return out

    def _iter_msg_rows(self, talker, cols, year=None):
        """统一遍历消息行，yield 字典。4.x 跨多表。"""
        import datetime
        if self.version == 3:
            if "msg" not in self.table_map:
                return
            f, t = self.table_map["msg"]
            conn = self._conn_by_file(f)
            c = _cols(conn, t)
            talker_c = _pick(c, "strTalker", "talker")
            content = _pick(c, "strContent", "content")
            ctime = _pick(c, "createTime", "createtime")
            sql = f'SELECT "{talker_c}" AS talker, "{content}" AS content, "{ctime}" AS ctime FROM "{t}"'
            wheres = []
            params = []
            if talker:
                wheres.append(f'"{talker_c}"=?'); params.append(talker)
            if year:
                y0 = int(datetime.datetime(year, 1, 1).timestamp())
                y1 = int(datetime.datetime(year + 1, 1, 1).timestamp())
                wheres.append(f'("{ctime}" BETWEEN ? AND ? OR "{ctime}" BETWEEN ? AND ?)')
                params += [y0, y1, y0 * 1000, y1 * 1000]
            if wheres:
                sql += " WHERE " + " AND ".join(wheres)
            for r in _iter_batched(conn, sql, params):
                yield {"talker": r["talker"], "content": r["content"], "ctime": r["ctime"]}
        elif self.version == 4:
            tables = []
            if talker:
                conn, table = self._v4_table(talker)
                if conn:
                    tables = [(conn, table)]
            else:
                if self.lazy_msg_files:
                    self._ensure_msg_index()
                seen = set()
                for table, conn in self.table_conn.items():
                    if table not in seen:
                        seen.add(table)
                        tables.append((conn, table))
            for conn, table in tables:
                try:
                    cc = _cols(conn, table)
                except Exception:
                    continue
                content = _pick(cc, "message_content", "compress_content", "content")
                ctime = _pick(cc, "create_time", "createTime")
                if not (content and ctime):
                    continue
                h = table.split("_", 1)[1] if "_" in table else ""
                user = self._user_for_table(table, h)
                # 按调用方需要的列来 SELECT：
                # 热力图只要时间戳，如果连 content 一起读，
                # 230 万条 zstd 压缩正文会全部过一遍磁盘 —— 实测 57 秒 vs 3 秒。
                need_content = bool(cols) and "content" in cols
                sel = f'"{ctime}" AS ctime'
                if need_content:
                    sel = f'"{content}" AS content, {sel}'
                sql = f'SELECT {sel} FROM "{table}"'
                params = []
                if year:
                    y0 = int(datetime.datetime(year, 1, 1).timestamp())
                    y1 = int(datetime.datetime(year + 1, 1, 1).timestamp())
                    sql += f' WHERE ("{ctime}" BETWEEN ? AND ? OR "{ctime}" BETWEEN ? AND ?)'
                    params = [y0, y1, y0 * 1000, y1 * 1000]
                try:
                    for r in _iter_batched(conn, sql, params):
                        item = {"talker": user, "ctime": r["ctime"]}
                        if need_content:
                            item["content"] = r["content"]
                        yield item
                except Exception:
                    continue
                finally:
                    # 释放文件句柄（见 time_heatmap 里的说明）
                    try:
                        conn.close()
                    except Exception:
                        pass

    def favorites(self, limit=200):
        if "fav" not in self.aux:
            return []
        conn = self.aux["fav"]
        for t in ("fav_db_item", "Favorite", "favorite"):
            tabs = _tables(conn)
            if t not in tabs:
                continue
            cols = _cols(conn, t)
            title = _pick(cols, "fav_title", "title", "strTitle", "FavTitle", "content")
            ftime = _pick(cols, "create_time", "time", "sourceTime", "createTime")
            try:
                rows = conn.execute(f'SELECT * FROM "{t}" LIMIT ?', (limit,)).fetchall()
            except Exception:
                continue
            out = []
            for r in rows:
                d = dict(r)
                raw = d.get(title) or ""
                out.append({"title": _extract_text(raw)[:200], "type": d.get("type"),
                            "time": self._norm_time(d.get(ftime))})
            return out
        return []

    def moments(self, limit=200):
        if "sns" not in self.aux:
            return []
        conn = self.aux["sns"]
        for t in ("SnsTimeLine", "SnsInfo", "Sns"):
            tabs = _tables(conn)
            if t not in tabs:
                continue
            cols = _cols(conn, t)
            content = _pick(cols, "content", "strContent", "xml", "Content")
            ctime = _pick(cols, "create_time", "time", "createTime")
            try:
                rows = conn.execute(f'SELECT * FROM "{t}" LIMIT ?', (limit,)).fetchall()
            except Exception:
                continue
            out = []
            for r in rows:
                d = dict(r)
                out.append({"content": _extract_text(d.get(content))[:500],
                            "time": self._norm_time(d.get(ctime))})
            return out
        return []

    def _conn_by_file(self, fname):
        for conn, path in self.msg_conns:
            if os.path.basename(path) == fname:
                return conn
        return self.msg_conns[0][0] if self.msg_conns else None

    @staticmethod
    def _norm_time(ts):
        try:
            ts = int(ts)
        except Exception:
            return 0
        if ts > 1e12:
            ts = ts // 1000
        if ts <= 0:
            return 0
        return ts


# 简易中文分词（无 jieba 时的回退）
try:
    import jieba
    jieba.setLogLevel(20)
    HAVE_JIEBA = True
except Exception:
    HAVE_JIEBA = False

STOPWORDS = set(
    "的 了 是 在 我 你 他 她 它 们 这 那 有 和 就 不 也 都 而 及 与 或 啊 吧 呢 吗 哦 嗯 呀 啦 嘛 "
    "把 被 给 让 对 从 向 到 上 下 里 中 个 之 其 此 该 等 还 又 很 太 最 更 要 会 能 可 没 别 去 来 "
    "说 看 想 知 道 觉 得 做 好 多 少 大 小 人 天 年 月 日 时 分 秒 一 二 三 四 五 六 七 八 九 十 "
    "么 什 谁 哪 怎 为 因 如 但 若 虽 然 于 以 并 且".split()
)

# 微信 4.x 的 XML 消息体会带出标签名和占位符，这些不是"词"：
#   - 结构性占位符：[图片]/[表情]/[语音]/[视频]/[分享]/[系统消息]
#   - 标签/属性名：msg/appmsg/title/content/username/fromusername 等
#   - 常见属性值碎片：com/cn/http/xml/cdn 等
_XML_NOISE = set(
    "分享 图片 表情 语音 视频 文件 位置 链接 名片 转账 红包 系统消息 系统提示 撤回 引用 卡片 位置消息 "
    "msg appmsg title content des des1 des2 word nickname src username fromusername tousername "
    "appid sdkver type aeskey md5 len md5sum hdlength hdwidth com cn http https xml cdn "
    "wxv wxv_ mpvoice amr silk jpg png gif webp api".split()
)

# 云端平台（钉钉等）的媒体占位符碎片：mediaId / fileId / fileName / url 等。
# 这些是资源标识不是"词"，留在词频里会污染结果（如 fileid 排到前面）。
_CLOUD_NOISE = set(
    "mediaid fileid filename url mid oid tid cid conid opendidtalkid openconversationid "
    "media file link image voice video sticker redpacket".split()
)

# 单字词几乎不携带语义（"的/了/是/我"…），词云里全是这种单字就等于没统计。
# 只保留有实义的二字以上词条，避免词云变成"助词排行榜"。
# 另外聊天正文里常混入账号 ID / 群名（wxid_xxx、gh_xxx、纯随机串），
# 这些也不是"词"，一并过滤掉。
_ID_LIKE_RE = re.compile(r"^[a-z0-9_]{8,}$", re.I)

# URL / 域名碎片：聊天里转发的小红书链接、公众号链接会带来
# https / com / www / user / profile / id / jd / pan … 这堆无意义的英文 token。
# 直接在分词前把链接整段删掉，比逐个加停用词干净得多。
_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'）】]+"
    r"|\b[a-z0-9\-]+\.(?:com|cn|net|org|io|co|me|cc|tv|shop|top|vip|link|xyz|info|biz)/[^\s<>\"'）】]*",
    re.I)
_BARE_DOMAIN_RE = re.compile(
    r"\b[a-z0-9\-]{2,}\.(?:com|cn|net|org|io|co|me|cc|tv|shop|top|vip|link|xyz|info|biz)\b",
    re.I)
# 常见的英文功能词 / 网页结构词，不是"人话词"
_EN_NOISE = set(
    "the and for you your are but not with have has was were this that from they "
    "will can all how what when who why out get let put its his her him she "
    "our your they we me my be is am do did done if so as at by on in to of "
    "or an up down more most some any each few other than too very just now "
    "then also into over after before between under above again further "
    "null none undefined true false view type src href http https www com cn "
    "net org html htm php jsp aspx api url uri user users profile id ids "
    "page site web app apps download login logout verify code token key "
    "act action function return const let var async await import export "
    "image images img video audio file files doc docs pdf ppt xls csv "
    "png jpg jpeg gif webp mp4 mp3 wav svg ico css js json xml yaml "
    "wechat weixin wx qq weibo taobao tmall jd xhs douyin kuaishou bilibili "
    "zhihu csdn gitee github python java golang linux windows mac android "
    "iphone ipad pc ok yes no ok maybe hello hi dear thanks thank sorry "
    "i'm i'm dont don't cant can't won't isn't it's that's".split()
)


def _is_noise_word(w):
    if not w:
        return True
    if w in STOPWORDS:
        return True
    # XML 消息体带出来的标签名/占位符/属性碎片
    if w.lower() in _XML_NOISE or w in _XML_NOISE:
        return True
    # 云端平台（钉钉等）的媒体占位符碎片：mediaId / fileId / fileName / url
    if w.lower() in _CLOUD_NOISE:
        return True
    # 常见英文功能词 / 网页碎片
    if w.lower() in _EN_NOISE:
        return True
    # 单个汉字：信息量太低
    if len(w) == 1 and re.fullmatch(r"[\u4e00-\u9fff]", w):
        return True
    # 单个字母/数字
    if len(w) <= 1:
        return True
    # 纯数字（数量、日期碎片）
    if w.isdigit():
        return True
    # 微信/飞书/钉钉账号前缀
    if re.match(r"^(wxid|gh|filehelper|weixin|openid|uin|ou_|corpid|chatid)[_\-]", w, re.I):
        return True
    # jieba 会把 "wxid_abc123" 切成 "wxid" + "abc123"，裸的这些前缀同样过滤
    if w.lower() in ("wxid", "gh", "uin", "openid", "corpid", "filehelper"):
        return True
    # 纯字母数字下划线且长度 >= 8：几乎必是账号 ID / 随机串
    if _ID_LIKE_RE.match(w):
        return True
    return False


def tokenize(text):
    if not text:
        return [], []
    emojis = _EMOJI_RE.findall(text)
    clean = _EMOJI_RE.sub(" ", text)
    # 先把链接整段删掉，避免 https/com/www/user 这些碎片进入词频
    clean = _URL_RE.sub(" ", clean)
    clean = _BARE_DOMAIN_RE.sub(" ", clean)
    words = []
    if HAVE_JIEBA:
        for w in jieba.cut(clean):
            w = w.strip()
            if not w:
                continue
            if re.fullmatch(r"[\s\W]+", w):
                continue
            if re.fullmatch(r"[a-zA-Z0-9]+", w):
                if len(w) >= 2:
                    words.append(w.lower())
            elif re.fullmatch(r"[\u4e00-\u9fff]+", w):
                if len(w) >= 2 and w not in STOPWORDS:
                    words.append(w)
    else:
        for seg in re.findall(r"[a-zA-Z0-9]+|[一-鿿]", clean):
            if re.fullmatch(r"[a-zA-Z0-9]+", seg):
                if len(seg) >= 2:
                    words.append(seg.lower())
            else:
                words.append(seg)
        zh = "".join(re.findall(r"[一-鿿]", clean))
        for i in range(len(zh) - 1):
            bg = zh[i:i + 2]
            if bg not in STOPWORDS:
                words.append(bg)
    return words, emojis


def word_emoji_freq(texts, top=50, extra_stop=None):
    """统计词频与表情频次。

    extra_stop: 额外停用词集合（例如通讯录里提取出的英文人名），
                这些词同样不计入词频。
    """
    stop = extra_stop or ()
    wc = defaultdict(int)
    ec = defaultdict(int)
    for tx in texts:
        ws, es = tokenize(tx)
        for w in ws:
            if _is_noise_word(w):
                continue
            if stop and w in stop:
                continue
            wc[w] += 1
        for e in es:
            ec[e] += 1
    words = sorted(wc.items(), key=lambda x: (-x[1], x[0]))[:top]
    emojis = sorted(ec.items(), key=lambda x: (-x[1], x[0]))[:top]
    return words, emojis
