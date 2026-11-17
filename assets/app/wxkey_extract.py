# -*- coding: utf-8 -*-
"""
微信 4.x 数据库密钥提取（只读）

实现参考开源项目 air846/WCDB（wechat_export/key_provider.py）与 ImUpXuu/SIWX
(siwx/sqlcipher.py, siwx/strategies/*) 的已验证做法：

- WCDB 为每个打开的 .db 维护一个 SQLCipher codec 上下文；其内存结构头部是
  一段固定的配置常量（page_size / KDF 迭代 / HMAC 算法…），可作为定位特征。
- 上下文内 salt_ptr 指向该库的 16 字节 salt（明文，与 .db 文件头一致）；
  cipher ctx 内 keyspec_ptr 指向 `x'<64hex enc_key><32hex salt>'`。
- 微信 4.1.13 起 keyspec 被 32 字节 pad 循环 XOR 混淆；pad 可由「已知 salt 明文」
  在运行时推导，无需硬编码、无需逆向混淆算法。
- 候选密钥一律用 SQLCipher 页 1 的 HMAC-SHA512 实证校验后才采纳。

全程只读：只申请 PROCESS_VM_READ 读取微信进程内存，不注入、不改写，
不触碰微信的任何数据。
"""
import ctypes
import hashlib
import hmac as hmac_mod
import os
import struct
import subprocess
from pathlib import Path

# codec 上下文解析是平台无关的纯 Python，统一放在 wcdb_ctx.py，
# 这里只保留 Windows 专属的「怎么读进程内存」。
from wcdb_ctx import (  # noqa: F401
    KEY_BYTES, SALT_BYTES, PAGE_SIZE, RESERVE, HMAC_SIZE, IV_SIZE,
    KEYS_SPEC_LEN, CODEC_PREFIX,
    OFF_SALT_PTR, OFF_HMAC_SALT_PTR, OFF_READ_CTX, OFF_WRITE_CTX,
    OFF_KEYSPEC_PTR,
    mac_key, verify_key, derive_pad, deobfuscate,
    parse_codec_context, scan_pattern, looks_like_key,
)

import env

# 仅 Windows 侧使用：Win32 类型与结构
if os.name == "nt":
    import ctypes.wintypes as wt
else:  # pragma: no cover - 非 Windows 不会走到这里
    wt = None

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE_PAGE_TYPES = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}


# ---------------- SQLCipher 4 校验与解密 ----------------
# mac_key / verify_key 已移至 wcdb_ctx.py（平台无关），此处直接引用。

def decrypt_db(data: bytes, key_bytes: bytes, page_size=PAGE_SIZE, reserved=RESERVE) -> bytes:
    """纯 Python 逐页解密 SQLCipher 4 库，返回完整明文 SQLite 字节"""
    from Crypto.Cipher import AES
    n = len(data) // page_size
    mk = mac_key(key_bytes, data[:SALT_BYTES])
    out = bytearray()
    for pg in range(1, n + 1):
        off = (pg - 1) * page_size
        page = data[off:off + page_size]
        iv = page[page_size - reserved:page_size - reserved + IV_SIZE]
        stored = page[page_size - HMAC_SIZE:]
        ct = page[SALT_BYTES:page_size - reserved] if pg == 1 else page[:page_size - reserved]
        calc = hmac_mod.new(mk, ct + iv + struct.pack("<I", pg), hashlib.sha512).digest()
        if calc != stored:
            raise ValueError(f"第 {pg} 页 HMAC 校验失败（密钥不匹配）")
        plain = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(ct)
        if pg == 1:
            out += b"SQLite format 3\x00"   # 页1 前16字节未加密，直接补回 magic
        out += plain
        out += b"\x00" * reserved
    b = bytearray(out)
    b[18] = 1      # rollback 模式（只读用，避免 -wal 依赖）
    b[19] = 1
    b[20] = reserved
    return bytes(b)


# ---------------- 进程只读访问 ----------------
class RemoteProcess:
    def __init__(self, pid: int):
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RuntimeError("需要 64 位 Python")
        self.pid = pid
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.OpenProcess.restype = wt.HANDLE
        self.handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.handle:
            raise RuntimeError(f"无法打开进程 pid={pid}（请以管理员身份运行）")
        self.kernel32.ReadProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel32.ReadProcessMemory.restype = wt.BOOL

    class _MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                    ("_p", wt.WORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD), ("Protect", wt.DWORD),
                    ("Type", wt.DWORD), ("_p2", wt.DWORD)]

    def read(self, address: int, size: int) -> bytes:
        if address <= 0 or size <= 0 or address + size > 0x800000000000:
            return b""
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        ok = self.kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buf, size, ctypes.byref(n))
        if not ok and n.value == 0:
            return b""
        return buf.raw[:n.value]

    def regions(self):
        self.kernel32.VirtualQueryEx.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(self._MBI), ctypes.c_size_t]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        address = 0
        while address < 0x7FFFFFFFFFFF:
            mbi = self._MBI()
            if not self.kernel32.VirtualQueryEx(
                    self.handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                    ctypes.sizeof(mbi)):
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            nxt = base + size
            if size <= 0 or nxt <= address:
                break
            protect = int(mbi.Protect) & 0xFF
            if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD)
                    and protect != PAGE_NOACCESS and protect in READABLE_PAGE_TYPES):
                yield base, size
            address = nxt

    def close(self):
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------- codec 上下文解析 ----------------
# derive_pad / deobfuscate / parse_codec_context / scan_pattern 已移至
# wcdb_ctx.py（平台无关），此处直接引用，见文件顶部 import。


def find_weixin_pids():
    try:
        out = env.run_hidden(
            ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
            timeout=30).stdout.decode("gbk", "ignore")
    except Exception:
        return []
    pids = []
    for line in out.strip().splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 5 and parts[0].strip('"').lower() == "weixin.exe":
            try:
                mem = int(parts[4].replace(",", "").replace(" K", "").strip() or 0)
            except Exception:
                mem = 0
            pids.append((mem, int(parts[1])))
    pids.sort(reverse=True)
    return [p for _, p in pids]


def extract_keys(db_paths, progress=None):
    """扫描微信进程内存，返回 {salt_hex: key_hex}（仅含通过 HMAC 校验的）"""
    page1_map = {}
    for path in db_paths:
        try:
            with open(path, "rb") as fp:
                page1 = fp.read(PAGE_SIZE)
        except OSError:
            continue
        if len(page1) == PAGE_SIZE:
            page1_map[page1[:SALT_BYTES].hex()] = page1
    if not page1_map:
        return {}

    keys = {}
    for pid in find_weixin_pids():
        try:
            proc = RemoteProcess(pid)
        except Exception as e:
            if progress:
                progress(f"pid {pid} 打开失败: {e}")
            continue
        try:
            addrs = scan_pattern(proc.read, proc.regions())
            if progress:
                progress(f"pid {pid}: codec 上下文候选 {len(addrs)} 处")
            for a in addrs:
                for salt_hex, key_hex in parse_codec_context(proc.read, a, page1_map):
                    keys[salt_hex] = key_hex
        finally:
            proc.close()
        if keys:
            break
    return keys


if __name__ == "__main__":
    import sys, json
    root = sys.argv[1] if len(sys.argv) > 1 else \
        r"<微信数据目录>\<账号>\db_storage"
    dbs = []
    for base, dirs, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".db"):
                dbs.append(os.path.join(base, f))
    print(f"发现 {len(dbs)} 个 .db")
    res = extract_keys(dbs, progress=lambda m: print("  ", m))
    print(f"\n=== 提取到 {len(res)}/{len(dbs)} 个库的密钥 ===")
    by_salt = {}
    for s, k in res.items():
        by_salt.setdefault(s, []).append(k)
    for s, k in res.items():
        print(f"  salt={s}  key={k}")
    json.dump(res, open("wx_keys.json", "w"), indent=1)
