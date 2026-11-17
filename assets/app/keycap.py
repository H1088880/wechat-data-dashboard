# -*- coding: utf-8 -*-
"""
跨平台密钥捕获（只读）。

背景
----
微信 4.x 每个 .db 有**独立的 salt + 独立的 32 字节 raw key**。
密钥在客户端进程内存里（SQLCipher codec 上下文）。
不同平台的「怎么读进程内存」不一样，但「拿到内存后怎么定位密钥」是通用的
（在 wcdb_ctx.py，平台无关）。

本模块按平台分发到三个后端：

  Windows  —— wxkey_extract.RemoteProcess
              （ReadProcessMemory + VirtualQueryEx）
  macOS    —— lldb 附加进程，dump 内存区后走同一套 codec 解析
  Linux    —— /proc/<pid>/mem 只读扫描 + /proc/<pid>/maps 取区域

三者的判定逻辑完全一致（都在 wcdb_ctx）：
  1) 扫 CODEC_PREFIX 特征串 → 命中 codec 上下文
  2) 解析出 (salt_hex, key_hex)
  3) 用目标库页 1 的 HMAC-SHA512 实测校验，只保留真正能解开的

若 codec 结构对不上（微信换版本），自动降级为「高熵候选扫描 + 实测校验」。

安全边界：全程只读目标进程内存，不注入、不改写、不触碰微信数据。
"""
import os
import time

import wcdb_ctx
import env as _env


# ---------------------------------------------------------------- 通用工具
def _page1_map(db_paths):
    """{salt_hex: 页1字节}，用于实测校验候选密钥。"""
    out = {}
    for path in db_paths or []:
        try:
            with open(path, "rb") as fp:
                page1 = fp.read(wcdb_ctx.PAGE_SIZE)
        except OSError:
            continue
        if len(page1) == wcdb_ctx.PAGE_SIZE:
            out[page1[:wcdb_ctx.SALT_BYTES].hex()] = page1
    return out


def _verify_against(page1_map, key_bytes):
    """返回该密钥对应的 salt_hex（能解开某个库才返回）。"""
    for salt_hex, page1 in (page1_map or {}).items():
        try:
            if wcdb_ctx.verify_key(key_bytes, page1):
                return salt_hex
        except Exception:
            continue
    return None


def _harvest(read, regions, page1_map, progress=None, budget_sec=60,
             max_entropy=4000):
    """
    通用提取流程：先走 codec 结构解析，不行再降级高熵扫描。

    read:   read(addr, size) -> bytes
    regions: [(base, size), ...]
    返回 {salt_hex: key_hex}

    注意：codec 路径对**进程内存快照**敏感 —— 微信正在写库时，
    同一批地址在两次扫描间可能失效。因此这里对**每个 pid 独立重扫**，
    而不是「扫一次全局复用」。
    """
    keys = {}
    t0 = time.time()

    # --- 路径 1：WCDB codec 上下文（精确、快）---
    try:
        addrs = wcdb_ctx.scan_pattern(read, regions)
        if progress:
            progress(f"codec 上下文候选 {len(addrs)} 处")
        for a in addrs:
            if time.time() - t0 > budget_sec:
                break
            for salt_hex, key_hex in wcdb_ctx.parse_codec_context(read, a, page1_map):
                keys[salt_hex] = key_hex
        if keys:
            if progress:
                progress(f"命中 {len(keys)}/{len(page1_map or {})} 个库的密钥")
            return keys
    except Exception as e:
        if progress:
            progress(f"codec 解析异常：{e}")

    # --- 路径 2：高熵候选扫描（兜底，慢）---
    # 逐个候选即时校验，命中足够多就提前结束，避免全量扫完。
    need = len(page1_map or {})
    if progress:
        progress("降级为高熵候选扫描（较慢）…")
    got = 0
    try:
        for c in wcdb_ctx.scan_entropy_candidates(
                read, regions, budget_sec=budget_sec, max_candidates=max_entropy,
                progress=progress):
            salt_hex = _verify_against(page1_map, c)
            if salt_hex and salt_hex not in keys:
                keys[salt_hex] = c.hex()
                got += 1
                if progress:
                    progress(f"命中 salt={salt_hex}（{got}/{need}）")
                if need and got >= need:
                    break
    except Exception as e:
        if progress:
            progress(f"高熵扫描异常：{e}")
    return keys


# ---------------------------------------------------------------- Windows
def _extract_windows(db_paths, progress=None):
    try:
        from wxkey_extract import RemoteProcess, find_weixin_pids
    except Exception as e:
        return {}, f"Windows 后端不可用: {e}"
    pids = find_weixin_pids()
    if not pids:
        return {}, "未找到微信进程（Weixin.exe / WeChat.exe）"
    page1_map = _page1_map(db_paths)
    if not page1_map:
        return {}, "没有可读的加密库"
    need = len(page1_map)
    keys = {}
    for pid in pids:
        try:
            proc = RemoteProcess(pid)
        except Exception as e:
            if progress:
                progress(f"pid {pid} 打开失败: {e}")
            continue
        try:
            # 微信在写库时进程内存会变动，codec 上下文地址可能失效，
            # 因此最多重扫 3 轮，每轮重新枚举内存区域。
            for attempt in range(3):
                regions = list(proc.regions())
                if progress:
                    progress(f"pid {pid}#{attempt + 1}: 可读内存区域 "
                             f"{len(regions)} 个")
                got = _harvest(proc.read, regions, page1_map, progress=progress)
                keys.update(got)
                if progress:
                    progress(f"pid {pid} 累计命中 {len(keys)}/{need}")
                if need and len(keys) >= need:
                    break
            if need and len(keys) >= need:
                break
        except Exception as e:
            if progress:
                progress(f"pid {pid} 扫描异常: {e}")
        finally:
            try:
                proc.close()
            except Exception:
                pass
        if keys:
            break
    return keys, None


# ---------------------------------------------------------------- macOS
def _extract_macos(db_paths, progress=None):
    """
    macOS 用 lldb 附加进程并 dump 可读内存区，再走同一套 codec 解析。

    lldb 不可用时直接返回明确错误提示（让用户人工提供密钥）。
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("lldb"):
        return {}, ("macOS 后端需要 lldb（未安装：xcode-select --install）；"
                    "请人工提供 64 位十六进制密钥")

    # 找 pid
    try:
        out = _env.run_hidden(["pgrep", "-x", "WeChat"],
                              timeout=10).stdout.decode("utf-8", "ignore")
        pids = [int(x) for x in out.split() if x.isdigit()]
    except Exception:
        pids = []
    if not pids:
        try:
            out = _env.run_hidden(["pgrep", "-if", "WeChat"],
                                  timeout=10).stdout.decode("utf-8", "ignore")
            pids = [int(x) for x in out.split() if x.isdigit()]
        except Exception:
            pids = []
    if not pids:
        return {}, "未找到微信进程（WeChat）"

    page1_map = _page1_map(db_paths)
    if not page1_map:
        return {}, "没有可读的加密库"

    dump_path = os.path.join(tempfile.gettempdir(), "wb_memdump.bin")
    keys = {}
    for pid in pids:
        if progress:
            progress(f"lldb 附加 pid {pid}…")
        try:
            # 一次性把进程内存 dump 到文件（lldb 自带，不需 root 的 ptrace 限制）
            r = _env.run_hidden(
                ["lldb", "-p", str(pid), "-o", "process save-core --force "
                 "--o %s" % dump_path, "-o", "detach", "-o", "quit"],
                timeout=300)
            err = r.stderr.decode("utf-8", "ignore")
            if not os.path.exists(dump_path):
                if progress:
                    progress(f"lldb dump 失败: {err[-300:]}")
                continue
        except Exception as e:
            if progress:
                progress(f"lldb 异常: {e}")
            continue

        try:
            regions = _regions_from_core(dump_path)
            if progress:
                progress(f"core 区域 {len(regions)} 个")
            with open(dump_path, "rb") as f:
                blob = f.read()

            def read(addr, size):
                # core 文件的段映射由 _regions_from_core 给出
                for base, off, size_ in regions:
                    if base <= addr < base + size_:
                        s = off + (addr - base)
                        return blob[s:s + size]
                return b""

            keys.update(_harvest(read, [(b, s) for b, _, s in regions],
                                 page1_map, progress=progress))
        except Exception as e:
            if progress:
                progress(f"core 解析异常: {e}")
        finally:
            try:
                os.remove(dump_path)
            except Exception:
                pass
        if keys:
            break
    return keys, None


def _regions_from_core(path):
    """
    解析 Mach-O core 的段映射，返回 [(vaddr, file_off, size)]。

    只取 __DATA 段与可读写段（SQLCipher codec 上下文在堆上，通常在 __DATA 之外的
    malloc 区，但 core 里会以 SECT / __DATA 一并给出），这里保守地取所有带 vaddr 的段。
    """
    import struct
    regions = []
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
            if len(head) < 28:
                return regions
            magic = struct.unpack_from("<I", head, 0)[0]
            if magic != 0x464C6147:      # 0xcafebabe 大端
                return regions
            ncmds = struct.unpack_from("<I", head, 16)[0]
            off = 32
            f.seek(0)
            data = f.read()
            for _ in range(ncmds):
                if off + 8 > len(data):
                    break
                cmd, cmdsize = struct.unpack_from("<II", data, off)
                if cmd == 0x19:          # LC_SEGMENT_64
                    segname = data[off + 8:off + 24].split(b"\x00")[0].decode(
                        "ascii", "ignore")
                    nsects = struct.unpack_from("<Q", data, off + 64)[0]
                    soff = off + 72
                    for i in range(nsects):
                        s = soff + i * 80
                        if s + 80 > len(data):
                            break
                        sectname = data[s:s + 16].split(b"\x00")[0].decode(
                            "ascii", "ignore")
                        addr = struct.unpack_from("<Q", data, s + 32)[0]
                        size = struct.unpack_from("<Q", data, s + 40)[0]
                        foff = struct.unpack_from("<Q", data, s + 48)[0]
                        if size and size < (1 << 31):
                            regions.append((addr, foff, size))
                off += cmdsize
                if cmdsize == 0:
                    break
    except Exception:
        return regions
    return regions


# ---------------------------------------------------------------- Linux
def _extract_linux(db_paths, progress=None):
    """
    Linux：/proc/<pid>/mem 只读扫描。

    需要 ptrace 权限（同用户通常够；跨用户需 root 或 CAP_SYS_PTRACE）。
    """
    import glob
    import re

    names = _env.wechat_process_names()
    pids = []
    for d in glob.glob("/proc/[0-9]*"):
        try:
            with open(os.path.join(d, "comm"), "r", encoding="utf-8",
                      errors="ignore") as f:
                comm = f.read().strip()
        except Exception:
            continue
        if comm.lower() in [n.lower() for n in names]:
            pids.append(int(os.path.basename(d)))
    if not pids:
        return {}, "未找到微信进程（%s）" % "/".join(names)

    page1_map = _page1_map(db_paths)
    if not page1_map:
        return {}, "没有可读的加密库"

    keys = {}
    for pid in pids:
        try:
            mem = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except Exception as e:
            if progress:
                progress(f"pid {pid} 打开 /proc/mem 失败: {e}")
            continue
        try:
            regions = _linux_regions(pid)
            if progress:
                progress(f"pid {pid}: 可读区域 {len(regions)} 个")

            def read(addr, size, _mem=mem):
                try:
                    _mem.seek(addr)
                    return _mem.read(size)
                except Exception:
                    return b""

            keys.update(_harvest(read, regions, page1_map, progress=progress))
        except Exception as e:
            if progress:
                progress(f"pid {pid} 扫描异常: {e}")
        finally:
            try:
                mem.close()
            except Exception:
                pass
        if keys:
            break
    return keys, None


def _linux_regions(pid):
    """从 /proc/<pid>/maps 解析可读区域。"""
    regions = []
    try:
        with open("/proc/%d/maps" % pid, "r", encoding="utf-8",
                  errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                if "r" not in perms:
                    continue
                if "w" not in perms:
                    continue          # codec 上下文在可写堆上
                rng = parts[0].split("-")
                try:
                    start = int(rng[0], 16)
                    end = int(rng[1], 16)
                except Exception:
                    continue
                size = end - start
                if size <= 0 or size > (512 << 20):
                    continue
                regions.append((start, size))
    except Exception:
        pass
    return regions


# ---------------------------------------------------------------- 统一入口
_BACKENDS = {
    "win32": _extract_windows,
    "macos": _extract_macos,
    "linux": _extract_linux,
}


def extract(db_paths, progress=None, backend=None):
    """
    提取密钥。返回 {salt_hex: key_hex}

    backend: 强制指定后端；缺省按平台自动选。
    """
    b = backend or _env.key_backend()
    fn = _BACKENDS.get(b)
    if not fn:
        return {}, f"当前平台没有可用的密钥提取后端（{b}）"
    try:
        keys, err = fn(db_paths, progress=progress)
    except Exception as e:
        return {}, f"{b} 后端异常: {e}"
    return keys, err
