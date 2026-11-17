#!/usr/bin/env python3
"""一键启动：启动分析服务 + 拉起全屏大屏（平台无关）。

用法:
    python launch.py                 # 自动探测数据目录并启动
    python launch.py --data <目录>    # 指定解密数据目录
    python launch.py --port 7890      # 指定端口
    python launch.py --no-screen      # 只启动服务，不开大屏

前置条件（脚本会检查并提示）：
  1. Python 3.8+ 与 pip 依赖 pycryptodome
  2. 已解密的数据目录（decrypted/<账号>），或可用的微信源库 + 密钥
  3. 本机有 Chrome / Edge / Chromium（用于 --app 全屏大屏）

只读、离线；本脚本不会上传任何数据。
"""
import os
import sys
import time
import json
import argparse
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 7890


def check_deps():
    try:
        import Crypto  # noqa
    except ImportError:
        print("[依赖] 缺少 pycryptodome，正在尝试安装…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "-q"])
    print("[依赖] OK")


def find_decrypted():
    """在常见位置找已解密的数据目录。"""
    cands = []
    decrypted = os.path.join(HERE, "decrypted")
    if os.path.isdir(decrypted):
        for name in os.listdir(decrypted):
            p = os.path.join(decrypted, name)
            if os.path.isdir(p):
                cands.append(p)
    if cands:
        return cands[0]
    return None


def wait_http(url, timeout=120):
    import urllib.request
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def start_service(port, data_dir, extra):
    cmd = [sys.executable, "-u", "server.py", str(port), "--auto"]
    if data_dir:
        cmd += ["--data", data_dir]
    cmd += extra
    print("[服务] 启动:", " ".join(cmd))
    creation = 0
    if os.name == "nt":
        creation = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return subprocess.Popen(cmd, cwd=HERE, creationflags=creation,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def open_screen(port):
    import urllib.request
    url = "http://127.0.0.1:%d/api/screen" % port
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            print("[大屏] 已触发全屏窗口，HTTP", r.status)
    except Exception as e:
        print("[大屏] 拉起失败:", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="已解密数据目录")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--no-screen", action="store_true")
    args = ap.parse_args()

    check_deps()
    data_dir = args.data or find_decrypted()
    if not data_dir:
        print("[提示] 未找到已解密数据目录。请先用解密入口页完成解密，"
              "或用 --data 指定 decrypted/<账号> 目录。")
        print("[提示] 服务仍会启动，你可在页面里手动配置数据源。")

    start_service(args.port, data_dir, [])

    base = "http://127.0.0.1:%d" % args.port
    print("[服务] 等待就绪…")
    if wait_http(base + "/api/dash", timeout=120):
        print("[服务] 就绪。")
        if not args.no_screen:
            open_screen(args.port)
        print("\n完成。大屏地址:", base + "/bigscreen.html")
        print("解密入口:", base + "/index.html")
    else:
        print("[服务] 启动超时，请查看 wa_stdout.log / 控制台。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
