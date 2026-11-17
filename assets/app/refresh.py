# -*- coding: utf-8 -*-
"""账号数据的增量刷新：让大屏始终显示最新消息。

回答「新数据还要再次解密吗」：
  * **密钥** 不需要再解 —— 一次提取后永久记住（keyring）
  * **数据** 需要重新解 —— 但只解变化的页（增量），秒级完成
    （SQLCipher 逐页独立加密，没有页间链式依赖，所以能做页级增量）

微信 4.x 的实际落盘行为（实测）：
  * 活跃库（message_6.db / biz_message_0.db / session.db …）持续被写入
  * WAL 会被周期性 checkpoint 并入主库 → **主库始终是最新真相**
  * 因此不需要手工合并 WAL（手工回放会引入陈旧帧，把库搞坏）

本模块的刷新流程：
  1. 找出账号的加密源库目录
  2. 对每个 .db：用 keyring 里的密钥做页级增量解密，写到明文副本
  3. 明文副本有变化 → 让上层重新加载数据库并重建会话缓存
"""
import os
import json
import time
import threading

import incremental
import keyring
import autodetect as admod


class Refresher:
    """账号数据增量刷新器。

    刷新在后台线程执行（HTTP 接口立即返回「已排队」），
    避免大屏的自动刷新把整个分析服务卡住。
    """

    def __init__(self, decrypted_dir, state_dir=None):
        self.decrypted_dir = decrypted_dir
        self.state_dir = state_dir or os.path.join(decrypted_dir, "_fp")
        self.dec = incremental.IncrementalDecryptor(self.state_dir)
        self._lock = threading.Lock()
        # 刷新互斥锁：自动刷新与手动刷新可能同时触发，
        # 两个线程同时替换同一个明文副本会互相踩（一方 os.replace 时
        # 另一方正在拷贝/改写临时文件）→ 轻则数据错乱，重则报
        # "database disk image is malformed"。这里用一把独立的锁串行化。
        self._refresh_lock = threading.Lock()
        # 源库目录缓存: account -> (ts, msg_dir)
        self._src_cache = {}
        self.last_result = {}
        self.last_run = 0
        self.running = False
        self.queued = 0
        # 刷新完成后的回调（由上层注入）。
        # 明文副本被原子替换后，服务端必须重开数据库连接才能看到新数据，
        # 否则大屏会一直显示刷新前的旧会话。
        self.after_refresh = None

    def refresh_async(self, account, only=None, verify=False):
        """排一个后台刷新任务，立即返回。

        返回 {ok, queued: True, running: bool}
        """
        with self._lock:
            if self.running:
                return {"ok": True, "queued": False, "running": True,
                        "message": "刷新进行中"}
            self.running = True
            self.queued += 1

        def worker():
            try:
                self.refresh(account, only=only, verify=verify)
            except Exception as e:
                self.last_result = {"ok": False, "error": str(e)[:200],
                                    "account": account}
            finally:
                with self._lock:
                    self.running = False

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return {"ok": True, "queued": True, "running": True, "account": account}

    # ---------- 源库定位 ----------
    def _source_dir(self, account):
        """找到账号对应的加密源库目录。

        缓存结果：scan_encrypted_accounts() 实测要 6.3 秒
        （要遍历 xwechat_files 下所有账号的库目录），
        每 20 秒调一次会让刷新周期严重超时，而且这个目录位置
        在微信运行期间几乎不变，缓存 5 分钟完全够用。
        """
        now = time.time()
        cached = self._src_cache.get(account)
        if cached and now - cached[0] < 300:
            return cached[1]
        found = None
        try:
            for a in admod.scan_encrypted_accounts():
                if a.get("account") == account:
                    found = a.get("msg_dir")
                    break
        except Exception:
            found = None
        # 扫描失败时不覆盖旧缓存，避免把已知可用的路径弄丢
        if found:
            self._src_cache[account] = (now, found)
            return found
        return found if found is not None else (cached[1] if cached else None)

    # ---------- 刷新 ----------
    def refresh(self, account, only=None, verify=False, progress=None):
        """增量刷新指定账号的所有库（同步执行）。

        only: 只刷新这些文件名（可选）
        返回统计 dict
        """
        # 串行化：自动刷新与手动刷新不能同时替换同一个明文副本。
        # 这里用非阻塞获取：拿不到锁说明已有一轮在跑，直接返回，
        # 避免两个线程互相打断导致数据损坏。
        if not self._refresh_lock.acquire(blocking=False):
            return {"ok": True, "skipped": True, "reason": "已有刷新在进行",
                    "account": account, "changed": 0, "files": [],
                    "missing_key": [], "elapsed": 0, "updated": False}
        try:
            return self._refresh_impl(account, only=only, verify=verify,
                                      progress=progress)
        finally:
            self._refresh_lock.release()

    def _refresh_impl(self, account, only=None, verify=False, progress=None):
        """真正的刷新逻辑（调用方已持有 _refresh_lock）。"""
        src_dir = self._source_dir(account)
        if not src_dir or not os.path.isdir(src_dir):
            return {"ok": False, "error": "找不到源库目录", "account": account}

        out_dir = os.path.join(self.decrypted_dir, account)
        os.makedirs(out_dir, exist_ok=True)

        # 收集待刷新的库
        targets = []
        for base, dirs, files in os.walk(src_dir):
            for f in files:
                if not f.lower().endswith(".db"):
                    continue
                if only and f not in only:
                    continue
                targets.append(os.path.join(base, f))

        stats = {"ok": True, "account": account, "total": len(targets),
                 "changed": 0, "files": [], "missing_key": [],
                 "elapsed": 0, "updated": False}
        t0 = time.time()

        for src in targets:
            base = os.path.basename(src)
            out = os.path.join(out_dir, base)

            # ── mtime 预筛 ──
            # 思路来自 wxexport 的 scripts/sync-inc.py：「只重解密 mtime 变过的分片」。
            # 微信开着时只有消息库/会话库在写，其余 40 多个库完全没动；
            # 但每轮都打开它们算页指纹，光 I/O 就把 CPU 占满，
            # 连带统计重建永远排不上队（面板一直空白）。
            #
            # 判定「没变」的条件必须同时满足：
            #   1) 源库 mtime 不比上次解密时新
            #   2) 明文副本的记录时间 >= 源库 mtime（说明源库变之前 we've 处理过）
            # 注意不能用「大小相等」做条件：微信是原地改写加密库，
            # 库大小常常不变，只有 mtime 会动。
            try:
                src_stat = os.stat(src)
                out_stat = os.stat(out) if os.path.exists(out) else None
                if (out_stat is not None
                        and out_stat.st_size > 0
                        and int(out_stat.st_mtime) >= int(src_stat.st_mtime)):
                    stats["files"].append({"file": base, "ok": True,
                                           "mode": "skipped", "changed": 0,
                                           "failed": 0, "elapsed": 0})
                    continue
            except Exception:
                pass

            # 取密钥：先看这个库的 salt 是否在 keyring 里
            try:
                salt = open(src, "rb").read(16).hex()
            except Exception:
                continue
            k, ksrc = keyring.lookup("wechat", account, salt)
            if not k:
                stats["missing_key"].append(base)
                continue
            try:
                key = bytes.fromhex(k)
            except Exception:
                stats["missing_key"].append(base)
                continue

            try:
                r = self.dec.refresh(src, out, key, verify=verify)
            except Exception as e:
                stats["files"].append({"file": base, "ok": False,
                                       "error": str(e)[:80]})
                continue
            stats["files"].append({"file": base, "ok": r.get("ok"),
                                   "mode": r.get("mode"),
                                   "changed": r.get("changed"),
                                   "failed": r.get("failed"),
                                   "elapsed": r.get("elapsed")})
            if r.get("changed"):
                stats["changed"] += r["changed"]
                stats["updated"] = True
            if progress:
                progress("%s: %s %s页" % (base, r.get("mode"),
                                        r.get("changed")))

        stats["elapsed"] = round(time.time() - t0, 2)
        stats["ts"] = time.time()
        self.last_result = stats
        self.last_run = time.time()
        # 通知上层：明文副本已更新 → 重开连接 + 重建缓存
        if stats.get("updated") and self.after_refresh:
            try:
                self.after_refresh(account, stats)
            except Exception as e:
                stats["after_refresh_error"] = str(e)[:200]
        return stats
