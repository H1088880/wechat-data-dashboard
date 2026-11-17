"""
wb-analyzer 微信数据分析大屏 —— 一键拉起（WEB 形态）。

要点（对应用户的原始要求）：
  · WEB 形式：用 Chromium 的 --app 模式打开页面 —— 没有标签页、没有地址栏，
    呈现的就是一个网页（不是打包软件界面）。
  · 拉起即全屏铺满。
  · 任务栏不显示浏览器图标（Windows 用 WS_EX_TOOLWINDOW，保留 Alt+Tab）。
  · **全程不弹任何窗口**：自身不弹控制台，子进程也不弹。

跨平台：Windows / macOS / Linux 都可用，浏览器查找与屏幕尺寸自动探测。
用法：
    python launch_big.py                # 拉起大屏
    python launch_big.py --url <URL>    # 自定义页面
    python launch_big.py --no-fullscreen
"""
import os
import sys
import time
import glob
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import env  # noqa: E402

WA_PORT = int(os.environ.get("WB_PORT") or 7890)
# 大屏默认停在哪个平台：WB_PLAT=dingtalk / feishu / wecom，留空则默认微信。
# 平台名会拼成 ?plat=xxx，前端据此自动切换（bigscreen.html 里的 URL 参数逻辑）。
#
# 为什么不只靠环境变量：计划任务启动的进程拿不到交互式 shell 里设的
# 临时环境变量（$env:WB_PLAT 传不进去），所以额外支持一个配置文件：
#   <状态目录>/wb_plat.txt   内容如 "dingtalk"
# 环境变量优先于配置文件。
_PLAT = (os.environ.get("WB_PLAT") or "").strip()
if not _PLAT:
    try:
        _pf = os.path.join(env.state_dir(), "wb_plat.txt")
        if os.path.isfile(_pf):
            with open(_pf, "r", encoding="utf-8", errors="ignore") as _f:
                _PLAT = _f.read().strip()
    except Exception:
        _PLAT = ""
DEFAULT_URL = "http://127.0.0.1:%d/bigscreen.html" % WA_PORT
if _PLAT and _PLAT != "wechat":
    DEFAULT_URL += "?plat=" + _PLAT
# 大屏窗口标题里的特征串（用于 Win32 定位窗口，Chrome 不保证窗口挂在 browser 进程上）
# 必须够严：解密页的标题是「微信数据分析 · 精简版（只读）」，如果用宽泛的
# 「微信数据分析」，会把普通浏览器里开着的解密页当成大屏窗口「聚焦」过去。
TITLE_HINT = "微信数据分析 · 大屏"

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
DETACHED_PROCESS = 0x00000008


def add_appwin(url):
    """
    给大屏地址打上 appwin=1 标记。

    为什么需要：--app 窗口里点「← 返回解密」是**同一个窗口**导航到首页的，
    此时窗口已经不在大屏页了。首页拿到 appwin=1 才知道「点📺大屏应在本窗口
    跳回去」，而不是 window.open 开出一个普通浏览器标签页（那样就丢了大屏窗口，
    窗口没标题栏、任务栏也没图标，用户会以为它消失了）。
    非大屏地址不加，避免污染任意 --url。
    """
    if not url or "bigscreen" not in url or "appwin=1" in url:
        return url
    return url + ("&" if "?" in url else "?") + "appwin=1"


# ------------------------------------------------------------------ Windows 窗口
def focus_existing(timeout=0.8):
    """
    已有大屏窗口就把它叫到前台，返回 hwnd；没有则返回 0。

    只在 Windows 上做（靠标题匹配）。这样在浏览器标签页里点「📺 大屏」
    是「切回那个全屏窗口」，不会越点越多。
    """
    if not env.IS_WIN:
        return 0
    try:
        hwnd, _how = _win32_find_window(0, TITLE_HINT, timeout=timeout)
    except Exception:
        return 0
    if not hwnd:
        return 0
    try:
        import ctypes
        u = ctypes.windll.user32
        u.ShowWindow(hwnd, 9)          # SW_RESTORE：最小化过也能叫回来
        _win32_prepare(hwnd)           # 重新铺满 + 去边框
        u.SetForegroundWindow(hwnd)
    except Exception:
        return 0
    return hwnd


def close_window():
    """
    按窗口标题关闭大屏窗口，返回是否发出关闭请求。

    必要性：--app 窗口没有标题栏，铺满全屏后又从任务栏隐藏了图标，
    直连 7890 时前端根本关不掉，只能 Alt+F4。服务端替它发 WM_CLOSE。
    """
    if not env.IS_WIN:
        return False
    try:
        import ctypes
        hwnd, _how = _win32_find_window(0, TITLE_HINT, timeout=0.4)
        if not hwnd:
            return False
        ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)   # WM_CLOSE
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ 浏览器
def find_browser():
    """跨平台查找 Chromium 系浏览器（Chrome / Edge / Chromium）。"""
    if env.IS_WIN:
        cands = []
        for base in (os.environ.get("PROGRAMFILES") or "",
                     os.environ.get("PROGRAMFILES(X86)") or "",
                     os.environ.get("LOCALAPPDATA") or ""):
            if not base:
                continue
            for rel in (r"Google\Chrome\Application\chrome.exe",
                        r"Microsoft\Edge\Application\msedge.exe",
                        r"Chromium\Application\chrome.exe"):
                cands.append(os.path.join(base, rel))
        for c in cands:
            if os.path.isfile(c):
                return c
        for name in ("chrome.exe", "msedge.exe", "chrome"):
            p = shutil.which(name)
            if p:
                return p
        return None

    if env.IS_MAC:
        for app in ("Google Chrome", "Microsoft Edge", "Chromium",
                    "Brave Browser"):
            p = os.path.join("/Applications", app + ".app", "Contents",
                             "MacOS", app.split()[0])
            if os.path.isfile(p):
                return p
            p = os.path.join("/Applications", app + ".app", "Contents",
                             "MacOS", app)
            if os.path.isfile(p):
                return p
        for name in ("google-chrome", "chromium", "microsoft-edge"):
            p = shutil.which(name)
            if p:
                return p
        return None

    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "microsoft-edge"):
        p = shutil.which(name)
        if p:
            return p
    for pat in ("/usr/bin/*chrom*", "/usr/bin/*edge*",
                "/opt/google/chrome/chrome", "/snap/bin/chromium"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return None


# ------------------------------------------------------------------ 屏幕
def screen_size():
    """屏幕尺寸 (w, h)。"""
    if env.IS_WIN:
        try:
            import ctypes
            u = ctypes.windll.user32
            return int(u.GetSystemMetrics(0)), int(u.GetSystemMetrics(1))
        except Exception:
            pass
    if env.IS_MAC:
        try:
            out = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True, timeout=8).stdout.decode("utf-8", "ignore")
            import re
            m = re.search(r"Resolution:\s*(\d+)\s*x\s*(\d+)", out)
            if m:
                return int(m.group(1)), int(m.group(2))
        except Exception:
            pass
    for cmd in (["xrandr"], ["xdpyinfo"]):
        try:
            import re
            out = subprocess.run(cmd, capture_output=True,
                                 timeout=6).stdout.decode("utf-8", "ignore")
            m = re.search(r"(\d{3,5})x(\d{3,5})", out)
            if m:
                return int(m.group(1)), int(m.group(2))
        except Exception:
            continue
    v = os.environ.get("WB_SCREEN")
    if v and "x" in v:
        try:
            w, h = v.lower().split("x")
            return int(w), int(h)
        except Exception:
            pass
    return 1920, 1080


# ------------------------------------------------------------------ 服务
def port_alive(port, timeout=1.2):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def ensure_service():
    """分析服务没跑就拉起来（用 boot.py，无窗口）。"""
    if port_alive(WA_PORT):
        return True
    boot = os.path.join(HERE, "boot.py")
    if not os.path.isfile(boot):
        return False
    pyw = None
    for name in ("pythonw.exe", "pythonw"):
        p = shutil.which(name)
        if p:
            pyw = p
            break
    if not pyw:
        pyw = sys.executable
    try:
        flags = (CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP) if env.IS_WIN else 0
        subprocess.Popen([pyw, boot], cwd=HERE,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=flags, start_new_session=not env.IS_WIN)
    except Exception:
        return False
    for _ in range(40):
        time.sleep(0.5)
        if port_alive(WA_PORT):
            return True
    return False


# ------------------------------------------------------------------ Windows 窗口处理
def _win32_prepare(hwnd):
    """去掉标题栏边框 + 铺满全屏 + 任务栏不显示图标。"""
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32
    GWL_EXSTYLE = -20
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_APPWINDOW = 0x00040000
    SWP_NOZORDER = 0x0004
    SWP_SHOWWINDOW = 0x0040

    ex = u.GetWindowLongW(hwnd, GWL_EXSTYLE)
    u.SetWindowLongW(hwnd, GWL_EXSTYLE,
                      (ex & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW)
    w = u.GetSystemMetrics(0)
    h = u.GetSystemMetrics(1)
    u.SetWindowPos(hwnd, 0, 0, 0, w, h,
                   SWP_NOZORDER | SWP_SHOWWINDOW)
    u.ShowWindow(hwnd, 5)   # SW_SHOW


def _win32_find_window(pid, title_hint="", timeout=12.0):
    """
    找浏览器主窗口句柄。

    先按启动 pid 找；Chrome 的窗口未必挂在 browser 进程上（可能被转交其它
    进程），所以再按**窗口标题关键字**回退匹配。返回 (hwnd, how)。
    """
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32

    hits_pid = []
    hits_title = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _l):
        if not u.IsWindowVisible(hwnd):
            return True
        p = wintypes.DWORD()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if pid and p.value == pid:
            hits_pid.append(hwnd)
        if title_hint:
            n = u.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(hwnd, buf, n + 1)
                if title_hint in buf.value:
                    hits_title.append(hwnd)
        return True

    t0 = time.time()
    while time.time() - t0 < timeout:
        hits_pid.clear()
        hits_title.clear()
        u.EnumWindows(cb, 0)
        if hits_pid:
            return hits_pid[0], "pid"
        if hits_title:
            return hits_title[0], "title"
        time.sleep(0.4)
    return 0, "none"


# ------------------------------------------------------------------ 主流程
def open_window(url=None, fullscreen=True, wait=12.0):
    """
    打开大屏窗口。返回 (pid, hwnd, how)。

    可被服务进程（server.py）直接调用 —— 服务由计划任务启动，
    脱离工具/沙箱的进程组与 Job Object，所以拉起的浏览器能长期存活。
    （从命令行/工具链直接调用时，调用方一退出浏览器就可能被回收。）
    """
    url = add_appwin(url or DEFAULT_URL)
    # 已有大屏窗口就只做「提到前台」——避免用户反复点导致一屏堆好几个窗口
    if "bigscreen" in url:
        hwnd = focus_existing()
        if hwnd:
            return 0, hwnd, "focus"

    browser = find_browser()
    if not browser:
        return 0, 0, "no-browser"

    profile = os.path.join(env.state_dir(), "wb-chrome-profile")
    try:
        os.makedirs(profile, exist_ok=True)
    except OSError:
        profile = os.path.join(HERE, ".wb-chrome-profile")

    w, h = screen_size()
    args_b = [
        "--app=%s" % url,
        "--user-data-dir=%s" % profile,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-session-crashed-bubble",
        "--hide-crash-restore-bubble",
    ]
    if fullscreen:
        args_b += ["--window-position=0,0", "--window-size=%d,%d" % (w, h)]

    # 关键：Chrome 是 **GUI 子系统** 程序（PE subsystem = Windows GUI），
    # 它自己根本不分配控制台，所以**不需要** CREATE_NO_WINDOW。
    # 但要传 DETACHED_PROCESS —— 否则 Chrome 会依附调用方进程组，
    # 调用方一退出浏览器就被一起回收，窗口随之消失。
    # 注意 DETACHED_PROCESS 与 CREATE_NO_WINDOW 互斥（同时用会让进程立刻退出）。
    flags = DETACHED_PROCESS if env.IS_WIN else 0
    chrome_log = os.path.join(env.state_dir(), "wb-chrome.log")
    try:
        os.makedirs(env.state_dir(), exist_ok=True)
        lf = open(chrome_log, "ab", buffering=0)
    except OSError:
        lf = subprocess.DEVNULL
    try:
        p = subprocess.Popen([browser] + args_b, cwd=HERE,
                             stdin=subprocess.DEVNULL,
                             stdout=lf,
                             stderr=lf,
                             creationflags=flags,
                             start_new_session=not env.IS_WIN)
    except Exception:
        return 0, 0, "spawn-failed"
    finally:
        try:
            if lf is not subprocess.DEVNULL:
                lf.close()
        except Exception:
            pass

    hwnd, how = 0, "none"
    if env.IS_WIN and fullscreen:
        hwnd, how = _win32_find_window(p.pid, TITLE_HINT, timeout=wait)
        if hwnd:
            try:
                _win32_prepare(hwnd)
            except Exception:
                hwnd = 0
    return p.pid, hwnd, how


def main():
    args = sys.argv[1:]
    url = DEFAULT_URL
    fullscreen = True
    i = 0
    while i < len(args):
        if args[i] == "--url" and i + 1 < len(args):
            url = args[i + 1]
            i += 2
        elif args[i] == "--no-fullscreen":
            fullscreen = False
            i += 1
        else:
            i += 1

    env.patch_subprocess_nowindow()

    up = ensure_service()
    print("分析服务 7890: %s" % ("已在运行" if up else "未能启动"))

    pid, hwnd, how = open_window(url=url, fullscreen=fullscreen)
    if not pid and not hwnd:
        print("打开失败：未找到 Chrome/Edge/Chromium，请手动访问 %s" % url)
        return 1
    if how == "focus":
        print("大屏窗口已在运行，已切到前台")
        return 0

    w, h = screen_size()
    print("已拉起大屏: %s (pid=%d, %dx%d)" % (url, pid, w, h))
    print("Chrome 日志: %s" % os.path.join(env.state_dir(), "wb-chrome.log"))
    if hwnd:
        print("已铺满全屏并隐藏任务栏图标（窗口匹配方式: %s）" % how)
    else:
        print("未找到浏览器窗口句柄（Chrome 可能退出了）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
