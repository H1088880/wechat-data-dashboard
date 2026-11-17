# -*- coding: utf-8 -*-
"""
WCDB codec 上下文解析（**纯 Python，平台无关**）。

这一层不含任何 ctypes / Win32 调用，因此 Windows / macOS / Linux 都能复用。
只有「怎么读进程内存」这一层各平台不同，放在各自的 keycap 后端里。

背景（参考开源项目 air846/WCDB 与 ImUpXuu/SIWX 的已验证做法）：
    · WCDB 为每个打开的 .db 维护一个 SQLCipher codec 上下文；
      其内存结构头部是一段固定的配置常量（page_size / KDF 迭代 / HMAC 算法…），
      可作为定位特征。
    · 上下文内 salt_ptr 指向该库的 16 字节 salt（明文，与 .db 文件头一致）；
      cipher ctx 内 keyspec_ptr 指向 `x'<64hex enc_key><32hex salt>'`。
    · 微信 4.1.13 起 keyspec 被 32 字节 pad 循环 XOR 混淆；
      pad 可由「已知 salt 明文」在运行时推导，无需硬编码、无需逆向混淆算法。
    · 候选密钥一律用 SQLCipher 页 1 的 HMAC-SHA512 实证校验后才采纳。
"""
import hashlib
import hmac as hmac_mod
import struct

KEY_BYTES = 32
SALT_BYTES = 16
PAGE_SIZE = 4096
RESERVE = 80
HMAC_SIZE = 64
IV_SIZE = 16
KEYS_SPEC_LEN = 99          # x' + 64hex + 32hex + '

# SQLCipher codec 配置常量前缀
# privacy-ok: 这是开源 WCDB 的 codec 结构常量（page_size/迭代次数/HMAC 算法等），不是密钥
CODEC_PREFIX = bytes.fromhex(
    "0000000000e80300020000001000000020000000100000001000000000100000"
    "630000005000000040000000000000000200000002000000"
)

OFF_SALT_PTR = 0x48
OFF_HMAC_SALT_PTR = 0x50
OFF_READ_CTX = 0x68
OFF_WRITE_CTX = 0x70
OFF_KEYSPEC_PTR = 0x20


# ---------------- SQLCipher 4 校验 ----------------
def mac_key(enc_key: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", enc_key,
                               bytes(b ^ 0x3A for b in salt), 2, dklen=KEY_BYTES)


def verify_key(key_bytes: bytes, page1: bytes) -> bool:
    """SQLCipher 4 页1 HMAC 校验 —— 判定密钥是否真的属于这个库。"""
    if len(page1) < PAGE_SIZE or len(key_bytes) != KEY_BYTES:
        return False
    salt = page1[:SALT_BYTES]
    mk = mac_key(key_bytes, salt)
    hm = hmac_mod.new(mk, page1[SALT_BYTES:PAGE_SIZE - RESERVE + IV_SIZE], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(hm.digest(), page1[PAGE_SIZE - HMAC_SIZE:])


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def derive_pad(keyspec_ct: bytes, salt_hex: str):
    """由混淆 keyspec + 已知 salt 推导 32 字节 XOR pad"""
    if len(keyspec_ct) != KEYS_SPEC_LEN or len(salt_hex) != SALT_BYTES * 2:
        return None
    salt_ascii = salt_hex.encode("ascii")
    pad = bytearray(32)
    pad[2:32] = bytes(a ^ b for a, b in zip(keyspec_ct[66:96], salt_ascii[0:30]))
    pad[0:2] = bytes(a ^ b for a, b in zip(keyspec_ct[96:98], salt_ascii[30:32]))
    if pad[0:2] != bytes(a ^ b for a, b in zip(keyspec_ct[0:2], b"x'")):
        return None
    return bytes(pad)


def deobfuscate(data: bytes, pad: bytes) -> bytes:
    return bytes(b ^ pad[i % 32] for i, b in enumerate(data))


def parse_codec_context(read, address: int, page1_map=None):
    """
    解析一个 codec 上下文，返回 [(salt_hex, key_hex)]。

    read: 回调 read(addr, size) -> bytes
    page1_map: {salt_hex: page1_bytes}；传了就做实证校验
    """
    codec = read(address, 0x88)
    if len(codec) < 0x88 or codec[:len(CODEC_PREFIX)] != CODEC_PREFIX:
        return []
    fields = struct.unpack_from("<15I", codec, 0)
    salt = read(_u64(codec, OFF_SALT_PTR), fields[3])
    if len(salt) != fields[3]:
        return []
    hmac_salt = read(_u64(codec, OFF_HMAC_SALT_PTR), fields[3])
    if hmac_salt and hmac_salt != bytes(b ^ 0x3A for b in salt):
        return []
    salt_hex = salt.hex()
    if page1_map is not None and salt_hex not in page1_map:
        return []
    out, seen = [], set()
    for offset in (OFF_READ_CTX, OFF_WRITE_CTX):
        caddr = _u64(codec, offset)
        if not caddr:
            continue
        cipher = read(caddr, 0x28)
        if len(cipher) < 0x28:
            continue
        keyspec_ct = read(_u64(cipher, OFF_KEYSPEC_PTR), fields[8])
        if len(keyspec_ct) != fields[8]:
            continue
        pad = derive_pad(keyspec_ct, salt_hex)
        if pad is None:
            continue
        keyspec = deobfuscate(keyspec_ct, pad)
        if not (keyspec.startswith(b"x'") and keyspec.endswith(b"'")
                and len(keyspec) == KEYS_SPEC_LEN):
            continue
        key_hex = keyspec[2:66].decode("ascii", "ignore")
        if keyspec[66:98].decode("ascii", "ignore") != salt_hex:
            continue
        if key_hex in seen:
            continue
        seen.add(key_hex)
        if page1_map is not None and not verify_key(bytes.fromhex(key_hex), page1_map[salt_hex]):
            continue
        out.append((salt_hex, key_hex))
    return out


def scan_pattern(read, regions, pattern: bytes = CODEC_PREFIX, chunk: int = 8 << 20):
    """在给定内存区域里扫描特征串，返回命中地址列表。"""
    hits = []
    overlap = len(pattern) - 1
    for base, size in regions:
        offset = 0
        tail = b""
        while offset < size:
            data = read(base + offset, min(chunk, size - offset))
            if not data:
                offset += 0x1000
                tail = b""
                continue
            combined = tail + data
            combined_base = base + offset - len(tail)
            start = 0
            while True:
                idx = combined.find(pattern, start)
                if idx < 0:
                    break
                hits.append(combined_base + idx)
                start = idx + 1
            tail = combined[-overlap:] if overlap else b""
            offset += len(data)
    return hits


# ---------------- 兜底：高熵候选扫描（不依赖 WCDB 结构） ----------------
def looks_like_key(b: bytes) -> bool:
    """32 字节高熵字节串才算候选密钥。"""
    if len(b) != KEY_BYTES:
        return False
    if b == b"\x00" * KEY_BYTES or b == b"\xff" * KEY_BYTES:
        return False
    return len(set(b)) >= 20


def scan_entropy_candidates(read, regions, budget_sec=30, max_candidates=4000,
                            time_fn=None, progress=None):
    """
    兜底扫描：在内存区域里找高熵 32 字节块作为候选密钥。

    与 WCDB codec 上下文解析相比：
      优点 —— 不依赖客户端内部结构，跨版本/跨平台更耐打
      缺点 —— 候选多，需要逐个做 HMAC 实测校验（较慢）
    返回候选字节串列表（已去重）。
    """
    import time as _time
    time_fn = time_fn or _time.time
    t0 = time_fn()
    seen = set()
    out = []
    for base, size in regions:
        if time_fn() - t0 > budget_sec:
            break
        offset = 0
        while offset < size:
            if time_fn() - t0 > budget_sec:
                break
            data = read(base + offset, min(4 << 20, size - offset))
            if not data:
                offset += 0x1000
                continue
            for off in range(0, len(data) - KEY_BYTES, 8):
                cand = data[off:off + KEY_BYTES]
                if not looks_like_key(cand):
                    continue
                if cand in seen:
                    continue
                seen.add(cand)
                out.append(cand)
                if len(out) >= max_candidates:
                    if progress:
                        progress(f"候选已达上限 {max_candidates}")
                    return out
            offset += len(data)
    return out
