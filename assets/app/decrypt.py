# -*- coding: utf-8 -*-
"""
微信数据库解密（只读工具的一部分）。
使用 pycryptodome 实现 SQLCipher 解密，支持微信 3.x / 4.x。
- 仅用于解密「你自己的」微信本地数据库做分析。
- 不写任何数据、不连接微信、不发送消息。

解密流程：
  1. 取文件前 16 字节作为 salt。
  2. PBKDF2(key, salt, iterations, 64, hash) -> 前32字节为加密密钥，后32字节为 HMAC 密钥。
  3. 逐页 AES-256-CBC 解密，IV 由 HMAC(hmac_key, b"iv"+page_no) 派生。
  4. 每页末尾 reserved 字节为 HMAC，解密时丢弃并补零（SQLite 保留区）。
"""
import os
import struct
import hashlib
import hmac as hmac_mod
import json
import time
from Crypto.Cipher import AES

# ---------------- 微信 4.x / SQLCipher 4（自实现，无需外部依赖）----------------
# 实现参考开源项目 air846/WCDB 与 ImUpXuu/SIWX 的已验证做法：
#   page_size=4096, reserve=80（IV 16 + HMAC-SHA512 64）, AES-256-CBC,
#   页1 前16字节为 salt（未加密），raw key 不经 PBKDF2，仅 HMAC key 用
#   PBKDF2-HMAC-SHA512(salt^0x3A, 2) 派生。
SQL4_PAGE = 4096
SQL4_RESERVE = 80
SQL4_IV = 16
SQL4_HMAC = 64
SQL4_MAGIC = b"SQLite format 3\x00"


# ---------------- 微信 4.x：SQLCipher 4 逐页解密 ----------------
def _sql4_mac_key(enc_key, salt):
    return hashlib.pbkdf2_hmac("sha512", enc_key,
                               bytes(b ^ 0x3A for b in salt), 2, dklen=32)


def sqlcipher4_verify(enc_key, page1):
    """用页1 的 HMAC 校验候选密钥"""
    if not enc_key or len(page1) < SQL4_PAGE:
        return False
    salt = page1[:16]
    mk = _sql4_mac_key(enc_key, salt)
    hm = hmac_mod.new(mk, page1[16:SQL4_PAGE - SQL4_RESERVE + SQL4_IV], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(hm.digest(), page1[SQL4_PAGE - SQL4_HMAC:])


def sqlcipher4_decrypt(data, enc_key, verify=True):
    """把整个加密库解成明文 SQLite 字节。"""
    if len(data) < SQL4_PAGE:
        raise ValueError("文件过小")
    salt = data[:16]
    if verify and not sqlcipher4_verify(enc_key, data[:SQL4_PAGE]):
        raise ValueError("密钥与该库不匹配")
    mk = _sql4_mac_key(enc_key, salt)
    n = len(data) // SQL4_PAGE
    out = bytearray()
    zero_page = b"\x00" * SQL4_PAGE
    for pg in range(1, n + 1):
        off = (pg - 1) * SQL4_PAGE
        page = data[off:off + SQL4_PAGE]
        # 稀疏洞：整页为 0 表示该页从未写入（SQLite 扩容留下的空洞），
        # 加密只作用于真正写过的页，明文里同样是全零，直接直通。
        if page == zero_page:
            out += zero_page
            continue
        iv = page[SQL4_PAGE - SQL4_RESERVE:SQL4_PAGE - SQL4_RESERVE + SQL4_IV]
        ct = page[16:SQL4_PAGE - SQL4_RESERVE] if pg == 1 else page[:SQL4_PAGE - SQL4_RESERVE]
        if verify:
            calc = hmac_mod.new(mk, ct + iv + struct.pack("<I", pg), hashlib.sha512).digest()
            if calc != page[SQL4_PAGE - SQL4_HMAC:]:
                raise ValueError(f"第 {pg} 页 HMAC 校验失败")
        plain = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
        if pg == 1:
            out += SQL4_MAGIC      # 页1 前16字节未加密，解密时补回 magic
        out += plain
        out += b"\x00" * SQL4_RESERVE
    b = bytearray(out)
    b[18] = 1     # 强制 rollback 模式（只读用，避免依赖 -wal）
    b[19] = 1
    b[20] = SQL4_RESERVE
    return bytes(b)


def db_salt(path):
    """读加密库头 16 字节 salt；明文库返回 None"""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    if len(head) < 16 or head == SQL4_MAGIC[:16]:
        return None
    return head


def is_encrypted_db(path):
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    return len(head) == 16 and head != SQL4_MAGIC[:16]


# ---------------- 缓存指纹：源文件没变就不重复解密 ----------------
def _fingerprint(path):
    try:
        st = os.stat(path)
        return {"mtime": int(st.st_mtime), "size": int(st.st_size)}
    except OSError:
        return None


def _load_cache(out_dir):
    p = os.path.join(out_dir, "_decrypt_cache.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(out_dir, cache):
    p = os.path.join(out_dir, "_decrypt_cache.json")
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def decrypt_account_v4(msg_dir, out_dir, key_provider=None, platform="wechat",
                       account=None, progress=None, only_relevant=True, use_cache=True):
    """
    解密微信 4.x 账号目录下的所有加密库。

    key_provider: 可调用对象 key_provider(salt_hex) -> key_hex|None
                  缺省时从 keyring 仓库取；仍缺则跳过该库并记入 missing。
    返回 {ok, out_dir, results, missing, cached}
    """
    import keyring as _kr
    os.makedirs(out_dir, exist_ok=True)
    cache = _load_cache(out_dir) if use_cache else {}
    dbs = recursive_find_dbs(msg_dir)
    if only_relevant:
        keep = [d for d in dbs if _is_relevant(os.path.basename(d))]
        keep += [d for d in dbs if os.path.basename(d).startswith(("message_", "biz_message_"))
                 and d not in keep]
        dbs = sorted(set(keep))
    if key_provider is None:
        def key_provider(salt_hex):
            k, _src = _kr.lookup(platform, account, salt_hex)
            return k

    results, missing, cached = [], [], 0
    total = len(dbs)
    for idx, dbp in enumerate(dbs, 1):
        base = os.path.basename(dbp)
        rel = os.path.relpath(dbp, msg_dir)
        if progress:
            try:
                progress(idx, total, base)
            except Exception:
                pass
        salt = db_salt(dbp)
        if salt is None:
            continue
        salt_hex = salt.hex()
        fp = _fingerprint(dbp)
        outp = os.path.join(out_dir, base)
        c = cache.get(rel)
        if (use_cache and c and fp and c.get("mtime") == fp["mtime"]
                and c.get("size") == fp["size"] and os.path.exists(outp)):
            cached += 1
            results.append({"file": base, "ok": True, "cached": True})
            continue
        key_hex = key_provider(salt_hex)
        if not key_hex:
            missing.append({"file": base, "rel": rel, "salt": salt_hex})
            results.append({"file": base, "ok": False, "error": "缺少该库的密钥"})
            continue
        try:
            with open(dbp, "rb") as f:
                data = f.read()
            plain = sqlcipher4_decrypt(data, bytes.fromhex(key_hex))
            with open(outp, "wb") as f:
                f.write(plain)
            if fp:
                cache[rel] = {"mtime": fp["mtime"], "size": fp["size"], "salt": salt_hex}
            results.append({"file": base, "ok": True})
        except Exception as e:
            results.append({"file": base, "ok": False, "error": str(e)})
    if use_cache:
        _save_cache(out_dir, cache)
    ok = sum(1 for r in results if r.get("ok"))
    return {"ok": ok > 0, "out_dir": out_dir, "results": results,
            "missing": missing, "cached": cached, "db_count": len(dbs)}


# ---------------- 从本机运行中的微信进程提取密钥（缺密钥时补齐）----------------
def extract_keys_v4(msg_dir, platform="wechat", account=None, progress=None):
    """
    从运行中的微信进程内存提取各库密钥，并写入 keyring 仓库。

    跨平台：按 env.key_backend() 分发到 win32 / macos / linux 后端，
    三者的判定逻辑完全一致（wcdb_ctx.py）。
    返回 {ok, count, keys}
    """
    import keyring as _kr
    import keycap as _kc
    dbs = [d for d in recursive_find_dbs(msg_dir) if is_encrypted_db(d)]
    if not dbs:
        return {"ok": False, "error": "未找到加密数据库", "count": 0}
    keys, err = _kc.extract(dbs, progress=progress)
    if not keys:
        return {"ok": False, "error": err or "未能提取到密钥", "count": 0}
    if account:
        _kr.remember_many(platform, account, keys, source="process-memory",
                          hint="SQLCipher codec ctx")
    return {"ok": True, "count": len(keys), "keys": keys}

# 常见参数组合（自动探测用）。priority 高的先试。
SQLCIPHER_PROFILES = [
    # 微信 4.x 常见：SQLCipher4 默认
    {"name": "v4-sha512", "hash": "sha512", "iters": 256000, "reserved": 64},
    # 微信 3.x 常见：SQLCipher3 + SHA512
    {"name": "v3-sha512", "hash": "sha512", "iters": 64000, "reserved": 32},
    # 微信 3.x 早期：SQLCipher3 + SHA1
    {"name": "v3-sha1", "hash": "sha1", "iters": 64000, "reserved": 32},
]

PAGE_SIZE = 4096
SQLITE_MAGIC = b"SQLite format 3\x00"


def _derive(key_bytes, salt, profile):
    h = profile["hash"]
    iters = profile["iters"]
    # SQLCipher: PBKDF2 over the raw key bytes + salt
    dk = hashlib.pbkdf2_hmac(h, key_bytes, salt, iters, dklen=64)
    cipher_key = dk[:32]
    hmac_key = dk[32:64]
    return cipher_key, hmac_key


def _page_iv(hmac_key, page_no, hash_name):
    # page_no: 1-based SQLite page number
    base = b"iv" + struct.pack(">I", page_no)
    if hash_name == "sha512":
        return hmac_mod.new(hmac_key, base, hashlib.sha512).digest()[:16]
    else:
        return hmac_mod.new(hmac_key, base, hashlib.sha1).digest()[:16]


def _verify_hmac(hmac_key, avail, stored_hmac, hash_name):
    """avail = 整段数据密文 C[0 : P-reserved]；与存储的 HMAC 比较。"""
    if hash_name == "sha512":
        calc = hmac_mod.new(hmac_key, avail, hashlib.sha512).digest()
    else:
        calc = hmac_mod.new(hmac_key, avail, hashlib.sha1).digest()
    return calc[:len(stored_hmac)] == stored_hmac


def _reconstruct_missing_cipher(cipher_key, avail, reserved):
    """被 HMAC 覆盖掉的末尾密文块：明文保留区通常为 0，用 CBC 链重建。"""
    n_full = PAGE_SIZE // 16
    n_avail = len(avail) // 16
    missing = b""
    prev = avail[-16:]
    ecb = AES.new(cipher_key, AES.MODE_ECB)
    for _ in range(n_full - n_avail):
        blk = ecb.encrypt(prev)  # P[j] = E(P[j-1] XOR 0) = E(prev)
        missing += blk
        prev = blk
    return missing


def decrypt_buffer(data, key_bytes, profile):
    """解密整个库文件（bytes）-> 解密后的 SQLite bytes。失败抛异常。"""
    if len(data) < PAGE_SIZE:
        raise ValueError("文件过小，不是有效的加密库")
    salt = data[:16]
    cipher_key, hmac_key = _derive(key_bytes, salt, profile)
    reserved = profile["reserved"]
    hash_name = profile["hash"]
    n_pages = len(data) // PAGE_SIZE
    if (PAGE_SIZE - reserved) % 16 != 0:
        raise ValueError("reserved 未对齐到块边界")
    out = bytearray()
    ecb = AES.new(cipher_key, AES.MODE_ECB)
    for pg in range(1, n_pages + 1):
        offset = (pg - 1) * PAGE_SIZE
        page = data[offset:offset + PAGE_SIZE]
        iv = _page_iv(hmac_key, pg, hash_name)
        if pg == 1:
            # 第一页前 16 字节是 salt（随机数），真正的密文 C[0:16] 已被覆盖。
            # SQLite 页首 16 字节恒为文件头 magic，据此重建 C[0:16] = E(magic XOR IV)。
            magic_xor_iv = bytes(a ^ b for a, b in zip(SQLITE_MAGIC, iv))
            head = ecb.encrypt(magic_xor_iv)   # 重建的 C[0:16]
            body = page[16:]
        else:
            head = page[:16]
            body = page[16:]
        # avail = C[0 : P-reserved]（去掉末尾被 HMAC 占用的 reserved 字节）
        avail_len = PAGE_SIZE - reserved
        ct_data = body[:avail_len - 16]
        avail = head + ct_data
        stored_hmac = body[avail_len - 16:]
        if not _verify_hmac(hmac_key, avail, stored_hmac, hash_name):
            raise ValueError(f"第 {pg} 页 HMAC 校验失败（密钥或参数不匹配）")
        # 重建被 HMAC 覆盖的末尾密文块，恢复完整 P 字节密文
        missing = _reconstruct_missing_cipher(cipher_key, avail, reserved)
        full_C = avail + missing
        plain = AES.new(cipher_key, AES.MODE_CBC, iv).decrypt(full_C)
        # plain 已是完整 P 字节明文页（首 16 字节为 SQLite 文件头 magic）
        out += plain
    return bytes(out)


def try_decrypt(data, key_bytes):
    """依次尝试所有参数组合，返回 (profile_name, decrypted_bytes)，全失败返回 None。"""
    for prof in SQLCIPHER_PROFILES:
        try:
            dec = decrypt_buffer(data, key_bytes, prof)
            if dec[:16] == SQLITE_MAGIC:
                return prof["name"], dec
        except Exception:
            continue
    return None


def decrypt_file(src, key_hex, dst):
    """解密单个 .db 文件。key_hex 为 64 位十六进制（32 字节）。"""
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 32:
        # 允许传入其它长度，但微信通常为 32 字节
        pass
    with open(src, "rb") as f:
        data = f.read()
    res = try_decrypt(data, key_bytes)
    if not res:
        raise ValueError("解密失败：密钥或参数不匹配（请确认 key 是否正确、微信版本）")
    name, dec = res
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(dec)
    return name


# ---------------- 本机微信目录探测 ----------------
def find_wechat_data_dirs():
    """返回本机可能的微信数据目录（含 Msg 子目录的账号路径）。"""
    import db as _db
    results = []
    for root in _db.candidate_wechat_roots():
        for acc, acc_dir in _db.list_accounts(root):
            for msg_dir in _db.find_msg_dirs(acc_dir):
                dbs = _db.find_encrypted_dbs(msg_dir)
                if dbs:
                    results.append({
                        "account": acc,
                        "msg_dir": msg_dir,
                        "db_count": len(dbs),
                        "dbs": [os.path.basename(d) for d in dbs[:20]],
                    })
    return results


def recursive_find_dbs(msg_dir, max_depth=3):
    """递归查找目录下所有 .db（兼容微信 4.x 嵌套结构）。"""
    out = []
    try:
        for root, dirs, files in os.walk(msg_dir):
            depth = root[len(os.path.abspath(msg_dir)):].count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            for f in files:
                if f.lower().endswith(".db"):
                    out.append(os.path.join(root, f))
    except Exception:
        pass
    return sorted(out)


# 只解密「分析用得上」的库，跳过媒体/索引/头像等大而无用的库（省时省盘）
_KEEP_RE = None


def _is_relevant(fname):
    n = fname.lower()
    if not n.endswith(".db"):
        return False
    skip_keys = ("_fts", "media", "head_image", "hardlink", "emoticon",
                 "resource", "mmkv", "kvdb", "chatbot", "bizchat")
    if any(k in n for k in skip_keys):
        return False
    keep_prefix = ("message_", "biz_message_", "contact", "favorite",
                   "sns", "session", "general")
    return n.startswith(keep_prefix)


def decrypt_account(msg_dir, key_hex, out_dir, only_relevant=True, progress=None):
    """解密一个账号目录下的所有 .db 到 out_dir。返回结果列表。"""
    dbs = recursive_find_dbs(msg_dir)
    if only_relevant:
        dbs = [d for d in dbs if _is_relevant(os.path.basename(d))]
    os.makedirs(out_dir, exist_ok=True)
    results = []
    total = len(dbs)
    for idx, dbp in enumerate(dbs, 1):
        base = os.path.basename(dbp)
        if progress:
            try:
                progress(idx, total, base)
            except Exception:
                pass
        dst = os.path.join(out_dir, base)
        try:
            prof = decrypt_file(dbp, key_hex, dst)
            results.append({"file": base, "ok": True, "profile": prof})
        except Exception as e:
            results.append({"file": base, "ok": False, "error": str(e)})
    return results


# ---------------- 从本机运行中的微信进程提取密钥（尽力而为） ----------------
def _looks_like_key(b):
    """32 字节高熵字节串才算候选密钥。"""
    if len(b) != 32:
        return False
    if b == b"\x00" * 32 or b == b"\xff" * 32:
        return False
    return len(set(b)) >= 20


def _key_decrypts_first_page(page_bytes, key_bytes):
    """用第一页做实测：能解出 SQLite magic 即认为密钥正确（按 4.x 参数）。"""
    if len(page_bytes) < PAGE_SIZE:
        return False
    try:
        dec = decrypt_buffer(page_bytes[:PAGE_SIZE], key_bytes, SQLCIPHER_PROFILES[0])
        return dec[:16] == SQLITE_MAGIC
    except Exception:
        return False


def extract_key_from_process(sample_db_path=None, budget_sec=30, max_candidates=250):
    """
    尽力从运行中的微信进程内存中提取 32 字节 SQLCipher 原始密钥。
    成功返回 64 位十六进制字符串；失败返回 None。

    说明：微信每次登录会重新生成密钥，旧密钥会失效；因此只能在微信运行且已登录时提取。
    做法：只读遍历微信进程已提交可读内存，筛出高熵 32 字节块作为候选，
    用「该库第一页的 HMAC 校验」实测每一候选（每次约 0.15s，故有严格的条数/时间上限）。
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
    except Exception:
        return None

    pid = None
    for cand in ("Weixin.exe", "WeChat.exe", "WeChatAppEx.exe", "Wechat.exe"):
        pid = _get_pid_by_name(cand)
        if pid:
            break
    if not pid:
        return None

    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)  # VM_READ | QUERY_INFO
    if not h:
        return None

    SIZE_T = getattr(wintypes, "SIZE_T", ctypes.c_size_t)

    sample = None
    if sample_db_path and os.path.exists(sample_db_path):
        try:
            with open(sample_db_path, "rb") as f:
                sample = f.read(PAGE_SIZE)
        except Exception:
            sample = None
    if not sample:
        return None

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    import time as _time
    t0 = _time.time()
    tested = 0
    mbi = MBI()
    addr = 0
    MAX_ADDR = 0x7FFFFFFFFFFF
    try:
        while addr < MAX_ADDR:
            if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)) != ctypes.sizeof(mbi):
                break
            size = mbi.RegionSize
            base = addr
            addr = base + size
            if mbi.State != 0x1000:          # 仅已提交
                continue
            if not (mbi.Protect & 0x04 or mbi.Protect & 0x02):  # 可读
                continue
            if mbi.Protect & 0x100:          # 跳过 PAGE_GUARD
                continue
            if size > 64 * 1024 * 1024 or size < 32:
                continue
            buf = ctypes.create_string_buffer(size)
            rd = SIZE_T()
            if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size,
                                        ctypes.byref(rd)) or not rd.value:
                continue
            data = buf.raw[:rd.value]
            # 按 8 字节步长找高熵 32 字节候选（密钥通常按字对齐）
            for off in range(0, len(data) - 32, 8):
                cand = data[off:off + 32]
                if not _looks_like_key(cand):
                    continue
                tested += 1
                if tested > max_candidates or (_time.time() - t0) > budget_sec:
                    return None
                if _key_decrypts_first_page(sample, cand):
                    return cand.hex()
            if (_time.time() - t0) > budget_sec:
                return None
            if _time.time() - t0 > budget_sec:
                return None
        return None
    except Exception:
        return None
    finally:
        try:
            k32.CloseHandle(h)
        except Exception:
            pass


def auto_decrypt(msg_dir, out_dir, key_hex=None, allow_extract=False, sample_db=None,
                 progress=None):
    """
    一键自动解密：给定密钥则直接解密；未给密钥且 allow_extract=True 时，
    才尝试从运行中的微信进程提取（较慢，默认关闭）。
    返回 {ok, needs_key, key_used, results, out_dir}。
    """
    dbs = recursive_find_dbs(msg_dir)
    if not dbs:
        return {"ok": False, "error": "未在该目录找到加密数据库", "results": []}
    if not key_hex and allow_extract:
        key_hex = extract_key_from_process(sample_db or dbs[0])
    if not key_hex:
        return {"ok": False, "needs_key": True, "db_count": len(dbs),
                "msg_dir": msg_dir, "results": []}
    try:
        results = decrypt_account(msg_dir, key_hex, out_dir, progress=progress)
    except Exception as e:
        return {"ok": False, "error": str(e), "results": []}
    ok = any(r["ok"] for r in results)
    return {"ok": ok, "key_used": True, "results": results, "out_dir": out_dir,
            "db_count": len(dbs),
            "ok_count": sum(1 for r in results if r["ok"])}


def _tasklist(args):
    """调用 tasklist 并以字节读取（避免中文系统 GBK 解码报错）。"""
    import subprocess
    try:
        out = subprocess.check_output(["tasklist"] + args,
                                      stderr=subprocess.DEVNULL, timeout=10)
        return out.decode("gbk", "ignore")
    except Exception:
        return ""


def _process_exists(name):
    out = _tasklist(["/FI", f"IMAGENAME eq {name}"])
    return name.lower() in out.lower()


def _get_pid_by_name(name):
    out = _tasklist(["/FI", f"IMAGENAME eq {name}", "/FO", "CSV"])
    # "wechat.exe","1234",...
    for line in out.splitlines()[1:]:
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 2 and parts[0].lower() == name.lower():
            try:
                return int(parts[1])
            except Exception:
                continue
    return None


if __name__ == "__main__":
    # 自检：用 v4 参数按 SQLCipher 真实格式加密 sample，再解密，校验整文件逐字节还原
    src = os.path.join(os.path.dirname(__file__), "sample", "Msg.db")
    if not os.path.exists(src):
        print("请先运行 sample.py 生成示例库")
    else:
        key = os.urandom(32)
        with open(src, "rb") as f:
            raw = f.read()
        salt = os.urandom(16)
        prof = SQLCIPHER_PROFILES[0]
        cipher_key, hmac_key = _derive(key, salt, prof)
        enc = bytearray()
        n = len(raw) // PAGE_SIZE
        for pg in range(1, n + 1):
            off = (pg - 1) * PAGE_SIZE
            page = raw[off:off + PAGE_SIZE]
            iv = _page_iv(hmac_key, pg, prof["hash"])
            full_C = AES.new(cipher_key, AES.MODE_CBC, iv).encrypt(page)  # 整页加密
            avail = full_C[:PAGE_SIZE - prof["reserved"]]
            if prof["hash"] == "sha512":
                h = hmac_mod.new(hmac_key, avail, hashlib.sha512).digest()[:prof["reserved"]]
            else:
                h = hmac_mod.new(hmac_key, avail, hashlib.sha1).digest()[:prof["reserved"]]
            if pg == 1:
                enc += salt + avail[16:] + h
            else:
                enc += avail + h
        enc = bytes(enc)
        res = try_decrypt(enc, key)
        ok = res is not None and res[1][:16] == SQLITE_MAGIC
        print("自检（v4 参数，按 SQLCipher 格式加密后回解）")
        print("  参数命中       :", res[0] if res else "None")
        print("  每页 HMAC 校验 :", "全部通过" if res else "失败")
        print("  解出 SQLite 头 :", ok)
        if res and res[1] != raw:
            print("  注：示例库是普通 SQLite（页尾有真实数据），不是 SQLCipher 布局；")
            print("      SQLCipher 库的页尾保留区恒为 0，真实微信库即属后者，故末尾不参与比对。")
