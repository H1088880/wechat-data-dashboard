#!/usr/bin/env python3
"""平台无关的环境与微信数据目录探测。

用法: python env_probe.py
只读探测，不修改任何文件，不输出密钥或聊天内容。
"""
import os
import sys
import glob


def os_kind():
    p = sys.platform.lower()
    if p == "win32":
        return "win32"
    if p == "darwin":
        return "darwin"
    return "linux"


def home():
    return os.path.expanduser("~")


def win_roots():
    roots = []
    up = os.environ.get("USERPROFILE", home())
    roots.append(os.path.join(up, "Documents", "WeChat Files"))
    pf = os.environ.get("ProgramFiles", "C:\\Program Files")
    roots.append(os.path.join(pf, "Tencent", "xwechat_files"))
    # 4.x 可能装在其它盘，扫常见盘符
    for d in "CDEF-GHIJKL".replace("-", ""):
        roots.append(os.path.join(d + ":\\", "xwechat_files"))
        roots.append(os.path.join(d + ":\\", "Tencent", "xwechat_files"))
    return roots


def mac_roots():
    up = home()
    bundle = "com.tencent.xinWeChat"
    return [
        os.path.join(up, "Library", "Containers", bundle, "Data", "Documents", "xwechat_files"),
        os.path.join(up, "Library", "Group Containers", "group." + bundle, "xwechat_files"),
        os.path.join(up, "Documents", "xwechat_files"),
    ]


def linux_roots():
    up = home()
    return [
        os.path.join(up, ".config", "xwechat_files"),
        os.path.join(up, ".local", "share", "xwechat_files"),
        os.path.join(up, "Documents", "xwechat_files"),
        os.path.join(up, "Documents", "Tencent", "xwechat_files"),
    ]


def scan():
    kind = os_kind()
    roots = {"win32": win_roots, "darwin": mac_roots, "linux": linux_roots}[kind]()
    print("OS        :", kind)
    print("Python    :", sys.version.split()[0])
    print("Home      :", home())
    print("数据目录候选：")
    found = False
    seen = set()
    for r in roots:
        if r in seen or not os.path.isdir(r):
            continue
        seen.add(r)
        # 只看一级子目录（通常每个是一个账号），不打印账号明细以外的信息
        subs = [p for p in glob.glob(os.path.join(r, "*")) if os.path.isdir(p)]
        print("  -", r)
        if subs:
            print("    含", len(subs), "个子目录（账号）")
            found = True
    if not found:
        print("  （未找到，请确认微信已安装并登录过，或手动指定数据目录）")
    print("\n内存读取方式：", {"win32": "ReadProcessMemory + WCDB codec 上下文",
                             "linux": "/proc/<pid>/mem 只读扫描",
                             "darwin": "按平台可用方式"}[kind])
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(scan())
