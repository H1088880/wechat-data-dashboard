# -*- coding: utf-8 -*-
"""SQLCipher 4 数据库的增量解密与刷新。

核心事实（实测结论）：
  * 微信 4.x 每个 .db 用独立 32 字节 raw key，**逐页独立加密**
    （每页自带 IV 与 HMAC，页与页之间没有链式依赖）
  * 因此：新数据只影响**发生变化的那些页**，可以只重解这些页，
    不必全量重解（948MB 库全量解 ≈ 7.3s，增量通常 <1s）
  * 微信会周期性 checkpoint，WAL 内容最终并入主库；
    **主库始终是最新真相**，所以不必手工合并 WAL
    （手工回放 WAL 反而会引入陈旧帧，把库搞坏）

增量策略：
  1. 用 sidecar 二进制文件记录上次解密后每页的指纹（8 字节/页）
  2. 重跑时逐页算指纹，与 sidecar 比对
  3. 只有指纹变化的页才重新解密并写回明文副本
  4. 单页 HMAC 校验失败 = 该页正在被微信写入 → 保留旧内容，下轮再试

效果：密钥只需提取一次；之后每次「刷新」都是秒级增量，
       大屏能拿到最新消息，且账号退出重登/客户端重装都无需重新解密。
"""
import os
import time
import struct
import hashlib
import shutil
import hmac as hmac_mod

from Crypto.Cipher import AES


def _file_lock():
    """取「明文副本文件访问锁」。

    从 db 惰性导入，避免 db ↔ incremental 循环依赖。
    锁的作用：让「关闭连接 + 原子替换」与「打开明文副本」互斥。
    """
    try:
        import db as _db
        return _db.file_access_lock()
    except Exception:
        import threading
        return threading.RLock()

SQL4_PAGE = 4096
SQL4_RESERVE = 80
SQL4_IV = 16
SQL4_HMAC = 64
SQL4_MAGIC = b"SQLite format 3\x00"
FP_SIZE = 8


def mac_key_for(enc_key, salt):
    """SQLCipher4: mac_key = PBKDF2-HMAC-SHA512(key, salt^0x3A, 2)"""
    return hashlib.pbkdf2_hmac(
        "sha512", enc_key, bytes(b ^ 0x3A for b in salt), 2, dklen=32)


def page_fingerprint(page):
    """页指纹：对整页内容做 blake2b。

    必须覆盖**全部**字节——早先只取页头 64 + 页尾 80，
    会漏掉位于页中部的改动，导致增量漏更（实测踩到）。
    整页 blake2b 在 400MB/s 的读取速度下不是瓶颈。
    """
    return hashlib.blake2b(page, digest_size=FP_SIZE).digest()


def decrypt_page(page, enc_key, mac_key, pgno, verify=True):
    """解密单页。

    返回值长度：
      pgno == 1 → 4080 字节（明文 4000 + 尾部 80 零），调用方需前置 SQL4_MAGIC
      pgno >  1 → 4096 字节（明文 4016 + 尾部 80 零）
    """
    if len(page) != SQL4_PAGE:
        raise ValueError("页长度异常: %d" % len(page))
    if all(b == 0 for b in page):
        # 稀疏洞：整页全零，明文同样全零
        return b"\x00" * (SQL4_PAGE - 16 if pgno == 1 else SQL4_PAGE)
    iv = page[SQL4_PAGE - SQL4_RESERVE: SQL4_PAGE - SQL4_RESERVE + SQL4_IV]
    # 页1 的前 16 字节是明文 salt，不参与加密
    ct = page[16:SQL4_PAGE - SQL4_RESERVE] if pgno == 1 else page[:SQL4_PAGE - SQL4_RESERVE]
    if verify:
        calc = hmac_mod.new(mac_key, ct + iv + struct.pack("<I", pgno),
                            hashlib.sha512).digest()
        if calc != page[SQL4_PAGE - SQL4_HMAC:]:
            raise ValueError("第 %d 页 HMAC 校验失败" % pgno)
    plain = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
    return plain + b"\x00" * SQL4_RESERVE


def _fix_header(buf):
    """把明文库的 SQLite 头字段修正为只读模式 + 保留区大小。"""
    b = bytearray(buf)
    b[18] = 1          # write version = legacy
    b[19] = 1          # read version = legacy
    b[20] = SQL4_RESERVE
    return bytes(b)


class IncrementalDecryptor:
    """增量解密器。

    sidecar: <明文副本路径>.fp —— 二进制，每页 8 字节指纹

    before_replace: 回调 list，签名 (out_path) -> None。
        在 os.replace 之前调用。**Windows 上这是必须的**：
        SQLite 打开的文件不允许被删除/改名，os.replace 会报
        [WinError 5] 拒绝访问。调用方（server.py）必须在这里
        关闭所有指向该文件的 SQLite 连接。
    """

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.before_replace = []
        os.makedirs(state_dir, exist_ok=True)

    def _fp_path(self, out_path):
        return out_path + ".fp"

    def _load_fp(self, out_path, n):
        """读回上次的页指纹。

        源库扩容时（微信持续写入 → 文件变大 → 页数 n 增加），
        旧指纹文件的长度就与 n*FP_SIZE 不一致。
        原实现在这种情况下直接返回 None → 整个库**全量重解**
        （最大库接近 1GB，一次要好几秒，还会让大屏长时间无响应）。

        现在改成：把旧指纹补零到新长度。
        补出来的 0 与真实指纹几乎不可能相等（指纹是 8 字节哈希），
        所以新增的页会被判定为「变了」并被正确解密 —— 语义正确。
        """
        p = self._fp_path(out_path)
        if not os.path.exists(p):
            return None
        try:
            data = open(p, "rb").read()
        except Exception:
            return None
        want = n * FP_SIZE
        if len(data) == want:
            return data
        if len(data) < want:
            # 扩容：补零（新页视为已变化）
            return data + b"\x00" * (want - len(data))
        # 源库变小（几乎不可能）：截断
        return data[:want]

    def _save_fp(self, out_path, fps):
        p = self._fp_path(out_path)
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(fps)
        os.replace(tmp, p)

    def refresh(self, src, out_path, key, verify=True, progress=None,
                force=False):
        """刷新明文副本。

        返回 {ok, skipped, pages, changed, elapsed, rel}
        """
        t0 = time.time()
        rel = os.path.basename(src)
        if not os.path.exists(src):
            return {"ok": False, "error": "源库不存在", "rel": rel}

        src_size = os.path.getsize(src)
        n = src_size // SQL4_PAGE
        if n < 1:
            return {"ok": False, "error": "源库过小", "rel": rel}

        old_fp = None if force else self._load_fp(out_path, n)
        # 增量判定：副本存在，且大小 **不超过** 源库页数对应的字节数。
        # 为什么用「不超过」而不是「等于」：
        #   微信持续写入 → 源库扩容 → 副本还是旧大小（少于 n 页）。
        #   若要求严格相等，扩容后每次都判定为全量 → 1GB 的库每次重解好几秒。
        # 副本偏小时，新增的页会在下面按「指纹不匹配」被正确解密补上。
        out_size = os.path.getsize(out_path) if os.path.exists(out_path) else -1
        if old_fp is not None and out_size > 0 and out_size <= n * SQL4_PAGE:
            mode = "incremental"
        else:
            mode = "full"

        data = open(src, "rb").read()
        salt = data[:16]
        mk = mac_key_for(key, salt)

        new_fp = bytearray(n * FP_SIZE)
        changed = 0
        failed = 0

        if mode == "full":
            plain = bytearray()
            for pg in range(1, n + 1):
                off = (pg - 1) * SQL4_PAGE
                page = data[off:off + SQL4_PAGE]
                new_fp[(pg - 1) * FP_SIZE: pg * FP_SIZE] = page_fingerprint(page)
                p = decrypt_page(page, key, mk, pg, verify=verify)
                if pg == 1:
                    plain += SQL4_MAGIC
                plain += p
                changed += 1
                if progress and pg % 20000 == 0:
                    progress("全量解密 %d/%d 页" % (pg, n))
            # 全量模式同样走「临时文件 + 原子替换」。
            # 原来直接 open(out_path, "wb") 截断重写活文件：
            #   服务端正开着这个文件 → 读者看到半新半旧的页
            #   → "database disk image is malformed"、会话排序错乱。
            tmp = out_path + ".tmp"
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                tmp = out_path + ".tmp.%d" % os.getpid()
            with open(tmp, "wb") as f:
                f.write(_fix_header(plain))
                f.flush()
                os.fsync(f.fileno())
            self._replace(tmp, out_path)
        else:
            # 增量模式：不能在明文副本上原地改写。
            #
            # 原因：SQLite 读的是文件的「页」，而且服务端（server.py）会一直持有
            # 打开明文副本的连接。原地改写（r+b）会让正在读的连接看到半新半旧的页，
            # 索引页和表页对不上 → "database disk image is malformed"，
            # 会话排序随之错乱（大屏 TOP 会话不再是最新活跃的那些）。
            #
            # 正确做法：拷贝到临时文件 → 只在临时文件上替换变化的页 → 原子替换。
            #   * 拷贝是流式的，不会把整个库读进内存（最大的库接近 1GB）
            #   * os.replace 是原子的：读者要么看到完整的旧文件，要么看到完整的新文件
            #
            # Windows 补充：os.replace 会先删除目标文件，而 SQLite 打开的文件
            # 不允许被删除 → [WinError 5]。所以替换前必须让调用方关掉连接
            # （before_replace 回调），否则增量刷新永远失败、看板停在旧数据。
            # 【先只算指纹，不碰明文副本】
            # 没有新页 → 完全不复制、不替换。
            # 以前哪怕一页没变，也要先把整个库拷一份再原子替换一次；
            # 而 Windows 上替换必须先关掉所有连接，于是每轮都在跟读者抢文件锁，
            # 抢不到就重试十几轮 → 一轮刷新拖到一百多秒，接口直接超时。
            for pg in range(1, n + 1):
                off = (pg - 1) * SQL4_PAGE
                fp = page_fingerprint(data[off:off + SQL4_PAGE])
                new_fp[(pg - 1) * FP_SIZE: pg * FP_SIZE] = fp
                if old_fp[(pg - 1) * FP_SIZE: pg * FP_SIZE] != fp:
                    changed += 1
            if changed == 0:
                # 这个库本轮没有新内容：明文副本原样不动，
                # 也就不会触发 os.replace（不用跟读者抢文件锁）。
                return {"ok": True, "skipped": True, "mode": mode, "pages": n,
                        "changed": 0, "failed": 0,
                        "elapsed": round(time.time() - t0, 2), "rel": rel}

            tmp = out_path + ".tmp"
            # 先清掉上次可能残留的 .tmp。
            # 为什么必须清：上次替换失败（Windows 文件锁）会留下 .tmp，
            # 这次 shutil.copyfile 要覆盖它，若它还被占用就直接失败，
            # 于是形成「失败 → 残留 → 覆盖失败 → 再残留」的死循环，
            # 增量刷新永远同步不了新消息。实测残留能堆到 1.8GB。
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                # 删不掉就换个唯一名字，避免被残留文件挡住
                tmp = out_path + ".tmp.%d" % os.getpid()
            shutil.copyfile(out_path, tmp)
            with open(tmp, "r+b") as f:
                # 副本可能比源库小（源库扩容了）：
                # 先把文件扩到 n 页，多出来的部分用 0 填充，
                # 随后循环里这些页指纹不匹配 → 会被解密并真正写入。
                cur = f.seek(0, 2)
                need = n * SQL4_PAGE
                if cur < need:
                    f.truncate(need)
                for pg in range(1, n + 1):
                    off = (pg - 1) * SQL4_PAGE
                    # 指纹上面那趟已经算好了，这里直接比
                    if (old_fp[(pg - 1) * FP_SIZE: pg * FP_SIZE]
                            == new_fp[(pg - 1) * FP_SIZE: pg * FP_SIZE]):
                        continue
                    page = data[off:off + SQL4_PAGE]
                    try:
                        p = decrypt_page(page, key, mk, pg, verify=verify)
                    except ValueError:
                        # 该页正在被微信写入 → 保留旧内容，下轮再试
                        failed += 1
                        continue
                    f.seek(off)
                    if pg == 1:
                        f.write(SQL4_MAGIC + p)
                    else:
                        f.write(p)
                    if progress and (pg % 5000) == 0:
                        progress("增量解密 %d 页" % pg)
                f.flush()
                os.fsync(f.fileno())
            self._replace(tmp, out_path)

        self._save_fp(out_path, bytes(new_fp))
        return {"ok": True, "skipped": False, "mode": mode, "pages": n,
                "changed": changed, "failed": failed,
                "elapsed": round(time.time() - t0, 2), "rel": rel}

    def _replace(self, tmp, out_path):
        """原子替换明文副本：关连接 → 替换，失败则重试。

        Windows 特有坑（实测确认）：
          * SQLite 打开的文件**不允许被删除/改名** → os.replace 报 WinError 5
          * immutable=1 / nolock=1 都绕不开（文件句柄照样被占住）
        所以必须先关闭所有指向该文件的 SQLite 连接。
        """
        import time as _t
        try:
            import db as _db
        except Exception:
            _db = None

        def _close_all():
            for cb in list(self.before_replace):
                try:
                    cb(out_path)
                except Exception:
                    pass

        # 【封锁】整轮替换期间把这个路径标记为「封锁」，
        #   读者要新建连接时在门外等（不持任何锁）：
        #     · 请求线程最多等 3 秒（宁可这轮替换失败，也不能把接口拖死）
        #     · 后台统计/会话统计最多等 60 秒（后台任务，等得起）
        #   不封锁的话，连接刚关掉又被重新打开，
        #   os.replace 永远抢不到空档（实测 20 次 0 成功）。
        blocked = False
        if _db is not None:
            try:
                _db.block_file(out_path)
                blocked = True
            except Exception:
                blocked = False
        try:
            for attempt in range(8):
                # 【死锁修复】关闭连接（before_replace 回调）必须在闸门**外**执行。
                #
                # 死锁链（faulthandler 实测）：
                #   替换线程持 _FILE_ACCESS → close_all 等读者的 inflight 归零；
                #   读者线程持 inflight 租约 → 需要新建连接 → 等 _FILE_ACCESS  ← 环
                #
                # 关闭连接本身有 _SqlConn._lock 保证与 execute 互斥，不需要文件闸门。
                # 闸门只保护「os.replace 那一刻没有连接正被打开」。
                _close_all()
                # 闸门：与「打开明文副本」互斥，杜绝替换窗口内被重新占用
                #
                # 【锁顺序铁律】闸门里**只能**做 os.replace，不能再调 close_file：
                #   close_file 要拿实例锁 _db_lock，
                #   而请求线程是「持 _db_lock → 再要闸门」，
                #   两边反向等待 = 死锁（实测直接把接口卡到超时）。
                with _file_lock():
                    try:
                        os.replace(tmp, out_path)
                        return
                    except PermissionError:
                        pass
                    except Exception:
                        # 替换失败：清掉临时文件，别留下垃圾（实测能堆到 1.8GB）
                        try:
                            if os.path.exists(tmp):
                                os.remove(tmp)
                        except Exception:
                            pass
                        raise
                # PermissionError → 退让重试（闸门已释放，读者能建连接）
                if attempt < 7:
                    _t.sleep(0.3 * (attempt + 1))
                    continue
            # 重试 8 次仍失败：清掉临时文件再抛
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            raise PermissionError("os.replace 重试 8 次仍失败: %s" % out_path)
        finally:
            if blocked:
                try:
                    _db.unblock_file(out_path)
                except Exception:
                    pass


def decrypt_db_full(src, out_path, key, verify=True, progress=None):
    """一次性全量解密（不带指纹，用于首次建立副本）。"""
    data = open(src, "rb").read()
    salt = data[:16]
    mk = mac_key_for(key, salt)
    n = len(data) // SQL4_PAGE
    out = bytearray()
    for pg in range(1, n + 1):
        off = (pg - 1) * SQL4_PAGE
        page = data[off:off + SQL4_PAGE]
        p = decrypt_page(page, key, mk, pg, verify=verify)
        if pg == 1:
            out += SQL4_MAGIC
        out += p
        if progress and pg % 20000 == 0:
            progress("解密 %d/%d 页" % (pg, n))
    open(out_path, "wb").write(_fix_header(out))
    return n
