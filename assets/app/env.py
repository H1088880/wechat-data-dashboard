# -*- coding: utf-8 -*-
"""
跨环境适配层：把「平台差异」收敛到这一个文件。

设计原则（回答「这套 skill 能适应各种环吗」）：
    · 解密引擎（SQLCipher4 / AES-256-CBC / HMAC-SHA512 / zstd）是**纯 Python**，
      天生跨平台，不含任何 Windows 专属调用。
    · 真正会因环境而异的只有三件事，全部收进本模块：
        1. 微信数据目录长什么样（Windows / macOS / Linux 各不相同）
        2. 密钥怎么拿到（进程内存读取方式各平台不同）
        3. 配置、密钥仓库放在哪（各平台的用户目录约定不同）
    · 其它模块一律 **只 import 本模块**，不再自己写 `os.name == 'nt'` 判断。

对外稳定 API（其它文件只依赖这几个）：
    IS_WIN / IS_MAC / IS_LINUX / OS_NAME
    home_dir()                 用户主目录
    app_dir()                  本项目代码目录
    state_dir()                运行期状态目录（配置 / keyring / 快照）
    wechat_roots()             微信数据根候选（已存在才返回）
    wechat_process_names()     微信进程名候选（用于进程内存密钥提取）
    key_backend()              当前平台可用的密钥获取后端名
    key_backend_available()    该后端在当前环境是否可用
    describe()                 自述信息，供 /api/status 展示
"""
import os
import sys
import glob
import shutil

# ---------------------------------------------------------------- 平台判定
OS_NAME = sys.platform.lower()          # 'win32' / 'darwin' / 'linux'
IS_WIN = OS_NAME.startswith("win")
IS_MAC = OS_NAME == "darwin"
IS_LINUX = OS_NAME.startswith("linux")

APP_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- 目录
def home_dir():
    """
    用户主目录，跨平台可靠。

    优先级按平台区分：
      · Windows：$USERPROFILE 优先（$HOME 在 Git Bash 等场景可能是历史遗留的
        别的路径，如 C:\\Users\\<user>，与实际用户目录不一致）
      · macOS/Linux：$HOME 优先
    最后才退回 os.path.expanduser('~')。
    """
    order = ("USERPROFILE", "HOME") if IS_WIN else ("HOME", "USERPROFILE")
    for name in order:
        v = os.environ.get(name)
        if v and os.path.isdir(v):
            return v
    try:
        h = os.path.expanduser("~")
        if h and h != "~" and os.path.isdir(h):
            return h
    except Exception:
        pass
    return os.getcwd()


def _env_first(*names):
    """取第一个存在的环境变量值。"""
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


def state_dir():
    """
    运行期状态目录：配置 / 密钥仓库 / 解密快照都放这。

    优先级：WB_ANALYZER_HOME > XDG_STATE_HOME/wb-analyzer > ~/.wb_analyzer
    密钥仓库绝不放项目目录，避免明文密钥被误提交。
    """
    v = _env_first("WB_ANALYZER_HOME")
    if v:
        return os.path.abspath(os.path.expanduser(v))
    v = os.environ.get("XDG_STATE_HOME")
    if v:
        return os.path.join(os.path.abspath(os.path.expanduser(v)), "wb-analyzer")
    return os.path.join(home_dir(), ".wb_analyzer")


def ensure_dir(d):
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except Exception:
        return d


def _wb_has_cli(root):
    """判断某个 WorkBuddy 根目录下是否真的装了**连接器 CLI 包**。

    坑：C:\\Users\\<user>\\.workbuddy 下也有 binaries/（PortableGit/node/python），
    甚至有 node/versions/<ver>/node.exe，但它**没有** wecom-cli / lark-cli / dws
    —— 那是系统账户的运行时，不是账号池。只看"有没有 node"会选错根目录，
    导致三个 CLI 全部找不到、大屏永远显示"未安装"。

    判据：能找到任一连接器包装脚本才算数。
    """
    if not root:
        return False
    base = os.path.join(root, ".workbuddy", "binaries", "node")
    if not os.path.isdir(base):
        return False
    # 连接器包装脚本可能在 cli-connector-packages，也可能直接装在 versions/<ver>/
    names = ("wecom-cli", "lark-cli", "dws")
    dirs = [os.path.join(base, "cli-connector-packages")]
    vers = os.path.join(base, "versions")
    if os.path.isdir(vers):
        for v in sorted(os.listdir(vers), reverse=True):
            dirs.append(os.path.join(vers, v))
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for n in names:
            for ext in (".cmd", ".CMD", ".exe", ""):
                if os.path.isfile(os.path.join(d, n + ext)):
                    return True
    return False


def workbuddy_root():
    """WorkBuddy 安装/数据根目录（跨环境）。

    连接器 CLI 装在 <root>/.workbuddy/binaries/node/ 下。计划任务启动的服务
    继承的是**系统账户**环境（USERPROFILE 指向 C:\\Users\\<user>），
    而实际连接器装在 pool 账号下，所以不能只靠 USERPROFILE 推导 ——
    必须找到**确实装了 CLI 包**的那个根。

    返回 None 表示当前环境里找不到 WorkBuddy 根。
    """
    # 1) 显式环境变量优先
    for k in ("WORKBUDDY_HOME", "WORKBUDDY_ROOT", "WORKBUDDY_POOL_HOME",
              "WB_POOL_HOME", "WB_HOME"):
        v = os.environ.get(k)
        if v and os.path.isdir(os.path.join(v, ".workbuddy")):
            return os.path.abspath(v)

    # 2) 从本文件所在路径向上找（技能包装在 <root>/.workbuddy/skills/... 下）
    cur = APP_DIR
    for _ in range(8):
        if os.path.isdir(os.path.join(cur, ".workbuddy", "binaries")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    # 3) 用户主目录 —— 必须是**装了 CLI 包**的那个，
    #    否则系统账户的 C:\\Users\\<user> 会把结果带偏。
    for base in (home_dir(), os.path.expanduser("~")):
        if base and os.path.isdir(os.path.join(base, ".workbuddy")):
            if _wb_has_cli(base):
                return os.path.abspath(base)

    # 4) 扫各盘符下的 pool 目录（不写死具体盘符，换机器也能用）
    for base in [os.path.join(d + os.sep, "WorkBuddyPools") for d in "CDEFGHIJKL"] + [
                 os.path.join(home_dir(), "WorkBuddyPools")]:
        if not os.path.isdir(base):
            continue
        try:
            for name in sorted(os.listdir(base)):
                pool = os.path.join(base, name)
                if not os.path.isdir(pool):
                    continue
                if _wb_has_cli(pool):
                    return os.path.abspath(pool)
        except OSError:
            continue

    # 5) 兜底：只要有 .workbuddy/binaries 就算数（至少 node 运行时可用）
    for base in (home_dir(), os.path.expanduser("~")):
        if base and os.path.isdir(os.path.join(base, ".workbuddy", "binaries")):
            return os.path.abspath(base)
    return None


def config_path():
    """运行配置文件路径（放状态目录，代码目录只读也能跑）。"""
    v = os.environ.get("WB_ANALYZER_CONFIG")
    if v:
        return os.path.abspath(os.path.expanduser(v))
    return os.path.join(state_dir(), "config.json")


def legacy_config_paths():
    """旧版把配置写在代码目录下的 config.json —— 兼容读取。"""
    out = []
    v = os.environ.get("WB_ANALYZER_CONFIG")
    if v:
        out.append(os.path.abspath(os.path.expanduser(v)))
    out.append(os.path.join(APP_DIR, "config.json"))
    return out


def _keyring_candidates():
    """密钥仓库候选位置（按优先级）。"""
    out = []
    v = _env_first("WB_KEYRING_PATH", "WX_KEYRING_PATH")
    if v:
        out.append(os.path.abspath(os.path.expanduser(v)))
    out.append(os.path.join(state_dir(), "keyring.json"))
    # 历史上用过的位置（换环境/换账号池后仍能找到老密钥）
    for name in ("USERPROFILE", "HOME"):
        h = os.environ.get(name)
        if h and os.path.isdir(h):
            out.append(os.path.join(h, ".wb_analyzer", "keyring.json"))
    # WorkBuddy 账号池：各池一个 .wb_analyzer；遍历常见盘符
    for base in [os.path.join(d + os.sep, "WorkBuddyPools") for d in "CDEFGHIJKL"] + [
                 os.path.join(home_dir(), "WorkBuddyPools")]:
        try:
            if not os.path.isdir(base):
                continue
            for name in os.listdir(base):
                out.append(os.path.join(base, name, ".wb_analyzer", "keyring.json"))
        except OSError:
            continue
    return out


def keyring_path():
    """
    密钥仓库路径。

    优先用环境变量指定；否则在候选位置里挑**已存在且非空**的那个
    （这样换机器、换账号池后，老密钥仍能被找到）；
    都没有则用状态目录下的默认位置。
    """
    v = _env_first("WB_KEYRING_PATH", "WX_KEYRING_PATH")
    if v:
        return os.path.abspath(os.path.expanduser(v))
    cands = _keyring_candidates()
    for p in cands:
        try:
            if os.path.exists(p) and os.path.getsize(p) > 2:
                return p
        except OSError:
            continue
    return cands[1] if len(cands) > 1 else cands[0]


def export_dir():
    """导出目录。"""
    v = os.environ.get("WB_EXPORT_DIR")
    if v:
        return os.path.abspath(os.path.expanduser(v))
    return os.path.join(state_dir(), "output")


def decrypted_dir():
    """
    解密产物目录（明文聊天记录）。

    默认在代码目录下的 decrypted/；若代码目录不可写（如 skill 包被挂载到
    只读位置），自动回落到状态目录 ~/.wb_analyzer/decrypted。
    """
    v = os.environ.get("WB_DECRYPTED_DIR")
    if v:
        return os.path.abspath(os.path.expanduser(v))
    local = os.path.join(APP_DIR, "decrypted")
    try:
        os.makedirs(local, exist_ok=True)
        probe = os.path.join(local, ".wtest")
        with open(probe, "w") as f:
            f.write("1")
        os.remove(probe)
        return local
    except Exception:
        d = os.path.join(state_dir(), "decrypted")
        ensure_dir(d)
        return d


# ---------------------------------------------------------------- 微信目录
def _windows_roots():
    up = home_dir()
    roots = []
    if up:
        for sub in ("WeChat Files", "xwechat_files", "XWeChat Files"):
            roots.append(os.path.join(up, "Documents", sub))
    # 4.x 常装在 Program Files\Tencent\xwechat_files（全盘扫 C:–H:）
    for d in ("C:", "D:", "E:", "F:", "G:", "H:"):
        for pf in ("Program Files", "Program Files (x86)"):
            roots.append(os.path.join(d, os.sep, pf, "Tencent", "xwechat_files"))
            roots.append(os.path.join(d, os.sep, pf, "Tencent", "WeChat"))
    # 自定义安装 / 迁移路径
    for d in ("C:", "D:", "E:", "F:", "G:", "H:"):
        roots.append(os.path.join(d, os.sep, "WeChat Files"))
        roots.append(os.path.join(d, os.sep, "xwechat_files"))
        roots.append(os.path.join(d, os.sep, "Tencent", "xwechat_files"))
    return roots


def _macos_roots():
    """
    macOS 微信数据目录（4.x 沙盒容器）。

    实测常见布局：
      ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files
      ~/Documents/xwechat_files
    旧版 3.x：~/Documents/WeChat Files
    """
    up = home_dir()
    roots = []
    if up:
        for sub in ("WeChat Files", "xwechat_files", "XWeChat Files"):
            roots.append(os.path.join(up, "Documents", sub))
        for bundle in ("com.tencent.xinWeChat", "com.tencent.WeChat",
                       "com.tencent.xinWeChatMac"):
            roots.append(os.path.join(
                up, "Library", "Containers", bundle, "Data", "Documents",
                "xwechat_files"))
            roots.append(os.path.join(
                up, "Library", "Containers", bundle, "Data", "Documents",
                "WeChat Files"))
        roots.append(os.path.join(
            up, "Library", "Group Containers", "group.com.tencent.xinWeChat",
            "xwechat_files"))
    return roots


def _linux_roots():
    """
    Linux 微信数据目录。Linux 版微信官方不提供，常见于 Wine/waydroid
    容器或手动迁移；因此除了常规位置，也扫一下 Wine 前缀。
    """
    up = home_dir()
    roots = []
    if up:
        for sub in ("WeChat Files", "xwechat_files", "XWeChat Files"):
            roots.append(os.path.join(up, "Documents", sub))
            roots.append(os.path.join(up, sub))
        roots.append(os.path.join(up, ".config", "xwechat_files"))
        roots.append(os.path.join(up, ".local", "share", "xwechat_files"))
        roots.append(os.path.join(up, ".var", "app", "com.tencent.WeChat"))
    # Wine 前缀（微信 Linux  unofficial / wine 运行）
    for pat in (os.path.join(home_dir(), ".wine", "drive_c", "users", "*",
                             "Documents", "xwechat_files"),
                os.path.join(home_dir(), ".wine", "drive_c", "Program Files",
                             "Tencent", "xwechat_files")):
        roots.extend(glob.glob(pat))
    return roots


def wechat_root_candidates():
    """返回本平台微信数据根候选路径（不判存在）。"""
    if IS_WIN:
        return _windows_roots()
    if IS_MAC:
        return _macos_roots()
    if IS_LINUX:
        return _linux_roots()
    # 其它平台（BSD 等）：给一个保守的猜测
    return [os.path.join(home_dir(), "Documents", "WeChat Files"),
            os.path.join(home_dir(), "Documents", "xwechat_files")]


def wechat_roots():
    """返回**存在**的微信数据根目录（已去重）。"""
    seen = set()
    out = []
    for r in wechat_root_candidates():
        try:
            rp = os.path.normpath(os.path.abspath(os.path.expanduser(r)))
        except Exception:
            continue
        if rp in seen or not os.path.isdir(rp):
            continue
        seen.add(rp)
        out.append(rp)
    return out


def wechat_process_names():
    """
    微信进程名候选（进程内存密钥提取用）。

    Windows：Weixin.exe / WeChat.exe / WeChatAppEx.exe
    macOS  ：WeChat / WeChatAppEx
    Linux  ：wechat / WeChat
    """
    if IS_WIN:
        return ["Weixin.exe", "WeChat.exe", "WeChatAppEx.exe", "Wechat.exe"]
    if IS_MAC:
        return ["WeChat", "WeChatAppEx", "Weixin"]
    if IS_LINUX:
        return ["wechat", "WeChat", "WeChatAppEx"]
    return ["wechat"]


# ---------------------------------------------------------------- 密钥后端
def key_backend():
    """
    当前平台可用的密钥获取后端名。

    · win32  —— ReadProcessMemory 扫进程内存 + WCDB codec 上下文解析
    · macos  —— lldb 附加进程，捕获 CCryptorCreate 的密钥参数
    · linux  —— /proc/<pid>/mem 只读扫描
    · none   —— 本平台需人工提供密钥
    """
    if IS_WIN:
        return "win32"
    if IS_MAC:
        return "macos"
    if IS_LINUX:
        return "linux"
    return "none"


def key_backend_available():
    """该后端在当前环境是否**真的可用**（依赖工具是否就位）。"""
    b = key_backend()
    if b == "win32":
        return hasattr(sys.modules.get("ctypes"), "windll") or _ctypes_ok()
    if b == "macos":
        return bool(shutil.which("lldb"))
    if b == "linux":
        return os.path.isdir("/proc/self") and os.path.exists("/proc/self/mem")
    return False


def _ctypes_ok():
    try:
        import ctypes  # noqa
        return True
    except Exception:
        return False


def key_backend_hint():
    """给用户看的后端说明（含缺失依赖提示）。"""
    b = key_backend()
    if b == "win32":
        return "Windows：只读扫描微信进程内存中的 WCDB codec 上下文（需管理员权限）"
    if b == "macos":
        if shutil.which("lldb"):
            return "macOS：lldb 附加微信进程捕获 CCryptorCreate 密钥参数"
        return "macOS：未检测到 lldb（xcode-select --install），请人工提供密钥"
    if b == "linux":
        return "Linux：/proc/<pid>/mem 只读扫描微信进程内存（需 ptrace 权限）"
    return "当前平台无自动密钥提取，需人工提供 64 位十六进制密钥"


# ---------------------------------------------------------------- 无窗口子进程
# 为什么必须显式处理：
#   服务端由 pythonw.exe 启动，**本身没有控制台**。Windows 上 Python 拉起
#   子进程时，若不显式给 CREATE_NO_WINDOW，系统会为子进程新分配并**显示**
#   一个控制台窗口 —— 这就是「点一下登录就弹黑窗」的根因。
#   而 npm 装的 CLI（wecom-cli / lark-cli / dws）在 Windows 上是 .cmd 批处理，
#   必然经由 cmd.exe 执行，弹窗概率 100%。
#   统一收敛到这里，避免各处漏加。
CREATE_NO_WINDOW = 0x08000000
SW_HIDE = 0


def no_window_kwargs():
    """
    subprocess 的「无窗口」参数。Windows 生效，其它平台返回空 dict。

    只用 CREATE_NO_WINDOW，**不要**再叠 STARTF_USESHOWWINDOW/SW_HIDE：
      · CREATE_NO_WINDOW 只影响控制台程序（cmd.exe / python.exe），
        对 GUI 程序（chrome.exe）完全无害；
      · 而 SW_HIDE 会让 GUI 程序的主窗口以隐藏方式创建 —— Chrome 会
        「进程活着但没有窗口」，实测踩过这个坑。
    """
    if not IS_WIN:
        return {}
    import subprocess
    # 注意：CREATE_NO_WINDOW 与 DETACHED_PROCESS 互斥，
    # 两者同时使用会让子进程立即退出（之前踩过这个坑）。
    return {"creationflags": CREATE_NO_WINDOW}


def run_hidden(args, timeout=180, **kw):
    """执行子进程且**绝不弹窗**（跨平台）。返回 CompletedProcess。"""
    import subprocess
    kw.setdefault("capture_output", True)
    kw.update(no_window_kwargs())
    return subprocess.run(args, timeout=timeout, **kw)


def popen_hidden(args, **kw):
    """启动子进程且**绝不弹窗**（跨平台）。返回 Popen。"""
    import subprocess
    kw.update(no_window_kwargs())
    return subprocess.Popen(args, **kw)


def patch_subprocess_nowindow():
    """
    给 subprocess.Popen 打全局兜底补丁：**默认注入 CREATE_NO_WINDOW**。

    为什么需要这层：
      上面 run_hidden / popen_hidden 是显式封装，但将来新增代码一旦漏用，
      就会重新出现「一点就弹黑窗」。这里从根上兜住 —— 只要在 Windows 上
      走 subprocess，窗口就一定被抑制。

    规则：
      · 调用方显式传了 creationflags 且已含 CREATE_NO_WINDOW / DETACHED_PROCESS
        → 尊重调用方，不改。
      · 调用方显式传了 startupinfo → 尊重调用方，不覆盖（避免破坏隐藏窗口语义）。
      · 其余情况 → **只**注入 CREATE_NO_WINDOW。

    注意：**不要**注入 STARTF_USESHOWWINDOW/SW_HIDE。
    SW_HIDE 会让 GUI 程序（chrome.exe）的主窗口隐藏 → 进程活着但看不见窗口。

    返回是否成功打上补丁（重复调用幂等）。
    """
    if not IS_WIN:
        return False
    import subprocess
    if getattr(subprocess.Popen, "_wb_nowin_patched", False):
        return True
    _orig_init = subprocess.Popen.__init__
    DETACHED_PROCESS = 0x00000008

    def _init(self, args, *a, **kw):
        flags = kw.get("creationflags") or 0
        if not (flags & CREATE_NO_WINDOW) and not (flags & DETACHED_PROCESS):
            kw["creationflags"] = flags | CREATE_NO_WINDOW
        # 动态取原始 __init__（单测/调试可替换它来观察实际传参）
        base = getattr(subprocess.Popen, "_wb_orig_init", _orig_init)
        return base(self, args, *a, **kw)

    subprocess.Popen.__init__ = _init
    try:
        subprocess.Popen._wb_nowin_patched = True
        # 保留原始 __init__，便于单测/调试观察补丁实际传了什么参数
        subprocess.Popen._wb_orig_init = _orig_init
    except Exception:
        pass
    return True


def nowin_patched():
    """当前进程是否已启用无窗口兜底补丁。"""
    import subprocess
    return bool(getattr(subprocess.Popen, "_wb_nowin_patched", False))


# ---------------------------------------------------------------- 其它
def third_party_key_files():
    """
    已知第三方工具的密钥文件位置（**只读**，跨平台）。

    之前这些是写死的 Windows 绝对路径，换环境就失效；现在按平台生成，
    并且都能被环境变量 WB_THIRD_PARTY_KEY_FILES（os.pathsep 分隔）覆盖。
    """
    files = []
    env = os.environ.get("WB_THIRD_PARTY_KEY_FILES")
    if env:
        files.extend([p for p in env.split(os.pathsep) if p.strip()])

    home = home_dir()
    if IS_WIN:
        appdata = os.environ.get("APPDATA")
        if appdata:
            files.append(os.path.join(appdata, "wechat-data-analysis-desktop",
                                      "output", "account_keys.json"))
        files.append(os.path.join(home, ".wb_analyzer", "account_keys.json"))
    elif IS_MAC:
        files.append(os.path.join(home, "Library", "Application Support",
                                  "wechat-data-analysis-desktop", "output",
                                  "account_keys.json"))
    else:
        files.append(os.path.join(home, ".config", "wechat-data-analysis-desktop",
                                  "output", "account_keys.json"))
    # 通用兜底：状态目录里同名文件
    files.append(os.path.join(state_dir(), "account_keys.json"))
    return files


def describe():
    """自述信息，供 /api/status 与 skill 文档展示。"""
    return {
        "os": OS_NAME,
        "os_label": {"win32": "Windows", "darwin": "macOS"}.get(
            OS_NAME, "Linux" if IS_LINUX else OS_NAME),
        "arch": "x64" if sys.maxsize > 2 ** 32 else "x86",
        "home": home_dir(),
        "state_dir": state_dir(),
        "keyring": keyring_path(),
        "key_backend": key_backend(),
        "key_backend_available": key_backend_available(),
        "key_backend_hint": key_backend_hint(),
        "wechat_roots": wechat_roots(),
        "export_dir": export_dir(),
        "python": sys.version.split()[0],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(describe(), ensure_ascii=False, indent=2))
