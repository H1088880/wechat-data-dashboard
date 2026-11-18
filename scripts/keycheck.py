# -*- coding: utf-8 -*-
"""密钥提取自检：本机微信版本 → 加密库 → 进程内存取密钥 → 逐库 HMAC 实证。

判据是**密码学实证**，不是版本号猜测：
  取本机若干 .db 的页 1，从微信进程内存只读出每个库的 32 字节密钥，
  再用 SQLCipher 4 的页 1 HMAC-SHA512 校验。
  校验通过 = 这个密钥真的属于这个库，跟"微信版本号是多少"没有关系。

用法：
    python scripts/keycheck.py                 # 自动探测加密库，取前 5 个库
    python scripts/keycheck.py "<加密库目录>" -n 8

退出码：0 全部通过；2 一个密钥都没取到；3 取到了但有库校验失败。
"""
import argparse
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
APP = os.path.join(ROOT, "assets", "app")


def _exe_candidates():
    """微信可执行文件的常见位置（Windows / macOS）。

    目录用环境变量与盘符拼出来，不写死任何一台机器的安装路径。
    """
    if sys.platform.startswith("win"):
        roots = []
        for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            v = os.environ.get(var)
            if v:
                roots.append(v)
        for letter in "CDEFG":
            for sub in ("Program Files", "Program Files (x86)"):
                roots.append(os.path.join(letter + ":" + os.sep, sub))
        out, seen = [], set()
        for r in roots:
            for sub, exe in (("Tencent\\Weixin\\Weixin.exe", "Weixin.exe"),
                             ("Tencent\\WeChat\\WeChat.exe", "WeChat.exe")):
                p = os.path.join(r, sub)
                if p.lower() not in seen:
                    seen.add(p.lower())
                    out.append(p)
        return out
    if sys.platform == "darwin":
        return ["/Applications/WeChat.app", "/Applications/Weixin.app"]
    return []


def _win_file_version(path):
    """读 exe 的 ProductVersion（纯 ctypes，不依赖 pywin32）。"""
    try:
        import ctypes
        from ctypes import wintypes

        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        ln = wintypes.UINT()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(ln)):
            return None
        # VS_FIXEDFILEINFO：dwFileVersionMS 在偏移 8，LS 在 12
        ms = ctypes.cast(ptr, ctypes.POINTER(wintypes.DWORD))[2]
        ls = ctypes.cast(ptr, ctypes.POINTER(wintypes.DWORD))[3]
        return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    except Exception:
        return None


def wechat_version():
    """尽力读微信版本：Windows 取 exe 版本号，macOS 读 Info.plist。"""
    for p in _exe_candidates():
        if not os.path.exists(p):
            continue
        if sys.platform.startswith("win"):
            v = _win_file_version(p)
            return (v or "未知"), p
        if sys.platform == "darwin":
            try:
                out = subprocess.run(
                    ["defaults", "read", os.path.join(p, "Contents", "Info.plist"),
                     "CFBundleShortVersionString"],
                    capture_output=True, text=True, timeout=5)
                return (out.stdout.strip() or "未知"), p
            except Exception:
                return "未知", p
    return "未知（没找到安装目录，可能装在自定义路径）", None


def git_state():
    """仓库是否干净 —— 自改过的 wcdb_ctx.py 是最常见的"取不到密钥"来源。"""
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        return None, None
    try:
        log = subprocess.run(["git", "-C", ROOT, "log", "-1", "--oneline"],
                             capture_output=True, text=True, timeout=8)
        st = subprocess.run(["git", "-C", ROOT, "status", "--short"],
                            capture_output=True, text=True, timeout=8)
        return log.stdout.strip(), st.stdout.strip()
    except Exception:
        return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("msg_dir", nargs="?", help="加密库目录（缺省自动探测）")
    ap.add_argument("-n", "--num", type=int, default=5, help="取样库数量，默认 5")
    args = ap.parse_args()

    sys.path.insert(0, APP)
    try:
        import keycap
        import wcdb_ctx
        import autodetect
    except Exception as e:
        print("✗ 包不完整，导入失败：%s" % e)
        print("  先跑 python scripts/preflight.py --imports")
        return 1

    ver, exe = wechat_version()
    print("微信版本      : %s" % ver)
    if exe:
        print("可执行文件    : %s" % exe)

    enc = args.msg_dir or autodetect.auto_pick_encrypted()
    if not enc or not os.path.isdir(enc):
        print("✗ 没找到微信加密库目录；请把 db_storage 路径作为参数传进来")
        return 2
    dbs = sorted(glob.glob(os.path.join(enc, "**", "*.db"), recursive=True))
    print("加密库目录    : %s" % enc)
    print("库数量        : %d" % len(dbs))
    if not dbs:
        print("✗ 目录里没有 .db")
        return 2

    # 优先挑有名有姓的库，比随机挑 message_* 更能说明问题
    def rank(p):
        b = os.path.basename(p)
        order = ("session.db", "contact.db", "favorite.db", "bizchat.db")
        return (order.index(b) if b in order else 99, b)
    pick = sorted(dbs, key=rank)[:max(1, args.num)]
    print("取样          : %s" % ", ".join(os.path.basename(x) for x in pick))
    print("-" * 64)

    keys, err = keycap.extract(pick, progress=lambda m: print("  · %s" % m))
    print("-" * 64)
    if err:
        print("提取接口返回  : %s" % err)
    print("取到密钥      : %d 个" % len(keys))

    ok = 0
    for db in pick:
        try:
            with open(db, "rb") as f:
                page1 = f.read(wcdb_ctx.PAGE_SIZE)
        except OSError as e:
            print("  %-18s 读不到: %s" % (os.path.basename(db), e))
            continue
        salt = page1[:wcdb_ctx.SALT_BYTES].hex()
        k = keys.get(salt)
        passed = bool(k) and wcdb_ctx.verify_key(bytes.fromhex(k), page1)
        ok += 1 if passed else 0
        print("  %-18s salt=%s  %s" % (os.path.basename(db), salt[:8] + "…",
                                       "✓ HMAC 校验通过" if passed else "✗ 无密钥/校验失败"))

    print("-" * 64)
    print("结果          : %d/%d 个库密钥实证通过" % (ok, len(pick)))
    log, dirty = git_state()
    if log:
        print("仓库提交      : %s" % log)
        if dirty:
            print("⚠ 工作区有未提交改动（自行改过 wcdb_ctx.py / keycap.py 时经常会取不到密钥）：")
            for line in dirty.splitlines()[:10]:
                print("    %s" % line)

    if ok and ok == len(pick):
        print("结论          : ✓ 本机密钥提取可用，「版本不兼容」不成立")
        return 0
    if not keys:
        print("结论          : ✗ 一个密钥都没取到，按下面顺序查：")
        print("  1) 微信是否正在运行并已登录（退出登录后内存里就没有密钥了）")
        print("  2) 是否与微信同一系统用户（Windows 换用户、Linux 需 ptrace 权限）")
        print("  3) git status 是否干净（自行重建过 wcdb_ctx.py 会解析错位）")
        print("  4) 若以上都对：把本脚本完整输出贴给作者，别自行改写解析代码")
        return 2
    print("结论          : 部分库取到、部分没取到（微信可能正在写库，重跑一次再判断）")
    return 3


if __name__ == "__main__":
    sys.exit(main())
