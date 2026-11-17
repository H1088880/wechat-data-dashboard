# 无窗口启动 wb-analyzer 分析服务（7890）
# 用 pythonw.exe + 本脚本：完全不弹控制台窗口，
# 且进程由系统托管，脱离调用方会话独立存活。
#
# 目录与解释器都**自动探测**，换机器/换位置都不用改本文件。
import os
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
DIR = os.path.dirname(os.path.abspath(__file__))


def _python_ok(p):
    """检查解释器能否 import 解密链路的关键依赖。

    坑：WorkBuddy 的 Python 运行时里 site-packages 偶尔会被裁剪
    （Crypto 只剩 .pyd，Python 层的 AES.py/__init__.py 没了），
    用它启动 server.py 会直接 ImportError 起不来。
    所以选解释器时不能只看"文件存在"，要真跑一次 import。
    """
    if not p or not os.path.isfile(p):
        return False
    import subprocess
    try:
        cp = subprocess.run(
            [p, "-c", "from Crypto.Cipher import AES; import zstandard"],
            capture_output=True, timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return cp.returncode == 0
    except Exception:
        return False


def _find_python():
    """挑一个**依赖完整**的 Python 解释器。

    优先级：
      1) env.workbuddy_root() 指向的账号池（它会校验确实装了连接器 CLI 包）；
      2) WORKBUDDY_HOME / 当前用户目录下的内置 Python；
      3) PATH 上的 python；
      4) 当前解释器。
    每个候选都要过 _python_ok()，避免选到 site-packages 被裁剪的那份。
    """
    import glob

    cands = []
    try:
        sys.path.insert(0, DIR)
        import env as _env_mod
        root = _env_mod.workbuddy_root()
        if root:
            cands.append(os.path.join(root, ".workbuddy", "binaries", "python",
                                      "versions", "*", "python.exe"))
    except Exception:
        pass
    home = os.environ.get("WORKBUDDY_HOME") or os.path.expanduser("~")
    if home:
        cands.append(os.path.join(home, ".workbuddy", "binaries", "python",
                                  "versions", "*", "python.exe"))
        cands.append(os.path.join(home, ".workbuddy_pools", "_shared",
                                  "python", "versions", "*", "python.exe"))
    for pat in cands:
        for hit in sorted(glob.glob(pat), reverse=True):
            if _python_ok(hit):
                return hit
    from shutil import which
    for name in ("python.exe", "python"):
        p = which(name)
        if p and _python_ok(p):
            return p
    if _python_ok(sys.executable):
        return sys.executable
    # 全都不合格时，至少返回一个能用的（后续 _ensure_deps 会尝试修复）
    for pat in cands:
        hits = sorted(glob.glob(pat), reverse=True)
        if hits:
            return hits[0]
    return sys.executable


def _existing_state_dirs():
    """列出可能存在密钥仓库的状态目录（按可信度排序）。

    背景：计划任务启动时继承的是**系统账户**环境（USERPROFILE 指向
    C:\\Users\\...），与交互式 shell（WorkBuddy 账号池）不同，
    密钥仓库会找不到。这里主动在若干常见位置里找**已存在**的 keyring.json，
    保证从任何入口启动都指向同一个密钥仓库。
    """
    out = []
    seen = set()

    def _add(p):
        if not p:
            return
        rp = os.path.normpath(p)
        if rp in seen:
            return
        seen.add(rp)
        try:
            if os.path.exists(os.path.join(rp, "keyring.json")):
                out.append(rp)
        except OSError:
            pass

    # 1) 显式指定
    for k in ("WORKBUDDY_POOL_HOME", "WB_POOL_HOME", "WORKBUDDY_HOME"):
        v = os.environ.get(k)
        if v:
            _add(os.path.join(v, ".wb_analyzer"))
    for k in ("WORKBUDDY_POOL", "WB_POOL"):
        v = os.environ.get(k)
        if v:
            _add(os.path.join(v, ".wb_analyzer"))

    # 2) 代码目录同级
    _add(os.path.join(os.path.dirname(DIR.rstrip("\\/")), ".wb_analyzer"))

    # 3) 用户目录
    _add(os.path.join(os.path.expanduser("~"), ".wb_analyzer"))

    # 4) WorkBuddy 账号池根目录（各池一个 .wb_analyzer）；遍历常见盘符
    for base in [os.path.join(d + os.sep, "WorkBuddyPools") for d in "CDEFGHIJKL"] + [
                 os.path.join(os.path.expanduser("~"), "WorkBuddyPools")]:
        try:
            if not os.path.isdir(base):
                continue
            for name in os.listdir(base):
                _add(os.path.join(base, name, ".wb_analyzer"))
        except OSError:
            continue

    return out


def _resolve_state_home():
    """确定状态目录（配置 / 密钥仓库所在处）。"""
    v = os.environ.get("WB_ANALYZER_HOME")
    if v:
        return v
    # 优先复用**已存在**密钥仓库的状态目录：
    # 换机器/换位置后，老密钥仍在原处，不该因为路径变了就"找不到密钥"。
    dirs = _existing_state_dirs()
    if dirs:
        return dirs[0]
    for k in ("WORKBUDDY_POOL_HOME", "WB_POOL_HOME"):
        if os.environ.get(k):
            return os.path.join(os.environ[k], ".wb_analyzer")
    return os.path.join(os.path.dirname(DIR.rstrip("\\/")), ".wb_analyzer")


def _find_workbuddy_home():
    """定位 WorkBuddy 账号池根目录（含 .workbuddy/binaries 的那层）。

    坑：计划任务启动的服务继承的是**系统账户**环境，USERPROFILE 指向
    C:\\Users\\<user>，而连接器 CLI 实际装在 <账号池目录> 下。
    不显式传过去，服务里就找不到 wecom-cli / lark-cli / dws，
    大屏上三个平台永远显示"未安装"。

    委托给 env.workbuddy_root()：它已经处理了「系统账户目录里也有
    .workbuddy/binaries 但没装 CLI 包」这个坑（判据是必须含 CLI 包）。
    """
    try:
        sys.path.insert(0, DIR)
        import env as _env_mod
        root = _env_mod.workbuddy_root()
        if root:
            return os.path.abspath(root)
    except Exception:
        pass
    return ""


def _load_cli_env(pool_home):
    """读取 WorkBuddy 为连接器 CLI 生成的环境变量文件。

    WorkBuddy 在 <pool>/.workbuddy/cli-env/<connector>.sh 里写好了 CLI 需要的
    环境变量（凭据目录 WECOM_CLI_CONFIG_DIR、附加请求头等）。
    CLI 找不到这些变量就找不到已授权的凭据 → 大屏永远显示"未授权"。

    返回 dict（文件不存在则空 dict）。
    """
    out = {}
    if not pool_home:
        return out
    import re
    d = os.path.join(pool_home, ".workbuddy", "cli-env")
    try:
        files = os.listdir(d)
    except OSError:
        return out
    for fn in files:
        if not fn.endswith(".sh"):
            continue
        try:
            with open(os.path.join(d, fn), encoding="utf-8", errors="replace") as f:
                txt = f.read()
        except OSError:
            continue
        for line in txt.splitlines():
            line = line.strip()
            m = re.match(r"^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip()
            # 去掉外层引号（sh 风格）
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                v = v[1:-1]
            out[k] = v
    return out


PY = _find_python()
HOME_DIR = _resolve_state_home()
WB_HOME = _find_workbuddy_home()


def _kill_old_instances(port=7890):
    """启动前先干掉上一轮的 server.py 实例。

    为什么必须做：
      计划任务 Stop 只会结束 boot.py 本身，
      而 boot.py 拉起的 server.py 是**独立子进程**，
      停止计划任务不会连带结束它。
      结果就是旧进程一直占着 7890 端口，
      新代码启动时端口已被占用（多半静默失败或起不来），
      页面还在用老代码 —— 表现为「改了代码但没生效」。

    定位方式用两条**不依赖 wmic** 的路径：
      1) PID 文件 wa_pid.txt —— 上一轮 boot.py 自己写的，最准；
      2) netstat 找 LISTENING 占用该端口的 PID —— 兜底，
         覆盖 PID 文件丢失/损坏的情况。
      之前这里用 wmic，但 wmic 已被安全策略拉黑 → 整段静默失败，
      旧进程一直占着端口，代码改了不生效就是这么来的。
    """
    if os.name != "nt":
        return
    import subprocess
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def _kill(pid):
        if not pid or pid == os.getpid():
            return
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, creationflags=flags)
        except Exception:
            pass

    # 1) PID 文件
    try:
        with open(os.path.join(DIR, "wa_pid.txt"), encoding="utf-8") as f:
            _kill(f.read().strip())
    except Exception:
        pass

    # 2) 端口占用兜底
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace",
                             creationflags=flags)
        text = out.stdout or ""
    except Exception:
        text = ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[1]
        state = parts[3]
        pid_s = parts[4]
        if state.upper() != "LISTENING":
            continue
        if not local.endswith(":%d" % port):
            continue
        if pid_s.isdigit():
            _kill(int(pid_s))

    # 3) 【关键】按命令行全量清理 server.py 残留实例。
    #    netstat 只能看到**正在 LISTENING** 的那个 PID；
    #    而 Windows 上 SO_REUSEADDR 允许两个实例同时绑定同一端口，
    #    第二个实例可能还没走到 LISTENING（或正在起连接）就被 netstat 漏掉。
    #    漏网的那个会和 watchdog 拉起的新实例**同时跑增量刷新**，
    #    互相 os.replace 同一批解密库 → SQLite 原生段错误 → 进程静默消失。
    #    所以这里按「命令行含 server.py 且工作目录匹配」全量清一遍。
    try:
        out2 = subprocess.run(
            ["wmic", "process", "where", "name='python.exe' or name='pythonw.exe'",
             "get", "ProcessId,CommandLine", "/format:csv"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=flags)
        text2 = out2.stdout or ""
    except Exception:
        text2 = ""
    if text2.strip():
        for line in text2.splitlines():
            low = line.lower()
            if "server.py" not in low:
                continue
            # 排除本进程（boot.py 自己的命令行里不会出现 server.py，安全）
            for cell in line.split(","):
                c = cell.strip().strip('"')
                if c.isdigit():
                    pid = int(c)
                    if pid and pid != os.getpid():
                        _kill(pid)
    else:
        # wmic 不可用时的兜底：PowerShell CIM 查询（wmic 已被安全策略拉黑）
        try:
            out3 = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance Win32_Process -Filter "
                 "\"Name='python.exe' or Name='pythonw.exe'\" | "
                 "Where-Object { $_.CommandLine -like '*server.py*' } | "
                 "ForEach-Object { $_.ProcessId }"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                creationflags=flags)
            for tok in (out3.stdout or "").split():
                if tok.isdigit():
                    pid = int(tok)
                    if pid and pid != os.getpid():
                        _kill(pid)
        except Exception:
            pass


def _ensure_deps(log=None):
    """启动前探测关键依赖，缺失则自动安装。

    背景：WorkBuddy 的 Python 运行时里 site-packages 偶尔会被清理/裁剪，
    典型表现是 `Crypto` 目录只剩几个 `.pyd` 底层扩展，Python 层的
    AES.py / __init__.py 全没了 → server.py 一启动就
    `ImportError: cannot import name 'AES' from 'Crypto.Cipher'`，
    服务直接起不来，看起来像"代码写错了"。

    这里做一次轻量自检：能用就不动，缺了就 pip 装回去（无窗口、无弹窗）。
    """
    import subprocess

    def _log(msg):
        if log is not None:
            try:
                log.write((msg + "\n").encode("utf-8", "ignore"))
            except Exception:
                pass

    checks = [
        ("pycryptodome", "from Crypto.Cipher import AES"),
        ("zstandard", "import zstandard"),
        ("Pillow", "from PIL import Image"),
        ("qrcode", "import qrcode"),
        # jieba 缺失时会退化成 bigram 切分，词频里全是「碗碗」「吃碗」这类
        # 重叠词组，大屏看起来像乱码
        ("jieba", "import jieba"),
    ]
    missing = []
    for pkg, code in checks:
        try:
            cp = subprocess.run([PY, "-c", code], capture_output=True,
                                timeout=90,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if cp.returncode != 0:
                missing.append(pkg)
        except Exception:
            missing.append(pkg)
    if not missing:
        return
    _log("[boot] 依赖缺失，自动安装: %s" % ", ".join(missing))
    try:
        subprocess.run([PY, "-m", "pip", "install", "--no-input"] + missing,
                       capture_output=True, timeout=600,
                       creationflags=CREATE_NO_WINDOW)
        _log("[boot] 依赖安装完成")
    except Exception as e:
        _log("[boot] 依赖安装失败: %r" % (e,))


def _acquire_boot_lock():
    """boot.py 自身的单例锁：同一台机器只允许一个 watchdog。

    【为什么必须有】
    两个 watchdog 各自守着一个 server.py，就会拉起**两个 server.py 实例**。
    而 Windows 上 SO_REUSEADDR 允许两个实例同时绑定 7890，
    两个进程于是同时对同一批 decrypted/*.db 做增量刷新和 os.replace
    → SQLite 原生 ACCESS_VIOLATION 段错误（Python 层无 traceback）
    → 进程静默消失 → 两个 watchdog 各自再拉一个 → 无限重启风暴。

    返回 True=拿到锁；False=已有 watchdog 在跑（直接退出）。
    """
    if os.name != "nt":
        return True
    lock_path = os.path.join(DIR, "wa_boot.lock")
    try:
        import msvcrt
    except Exception:
        return True
    fh = None
    try:
        fh = open(lock_path, "a+b")
        if fh.seek(0, os.SEEK_END) == 0:
            fh.write(b"\0")
            fh.flush()
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            fh.seek(0)
            fh.write(("pid=%d\n" % os.getpid()).encode("utf-8"))
            fh.flush()
        except Exception:
            pass
        _BOOT_LOCK_HANDLE.append(fh)
        return True
    except Exception:
        try:
            if fh is not None:
                fh.close()
        except Exception:
            pass
        return False


_BOOT_LOCK_HANDLE = []


def main():
    os.chdir(DIR)
    # 无窗口兜底补丁（boot.py 自己也可能拉起子进程）
    try:
        sys.path.insert(0, DIR)
        import env as _env_mod
        _env_mod.patch_subprocess_nowindow()
    except Exception:
        pass
    # 【单例守卫】已有 watchdog 在跑就别再起一个（会拉出双 server.py 实例）
    if not _acquire_boot_lock():
        try:
            with open(os.path.join(DIR, "wa_stdout.log"), "ab", buffering=0) as lg:
                lg.write(b'[boot] another watchdog is already running, exiting.\n')
        except Exception:
            pass
        return
    # 先清理上一轮残留实例，避免旧代码占着 7890 端口
    _kill_old_instances()
    # 状态目录显式传给子进程：计划任务启动时继承的是系统账户环境，
    # 与交互式 shell 不同，不钉死就会"找不到密钥"。
    child_env = dict(os.environ)
    child_env["WB_ANALYZER_HOME"] = HOME_DIR
    # WorkBuddy 根目录同样要显式传：连接器 CLI 装在账号池下，
    # 不传的话服务里 wecom-cli / lark-cli / dws 全部找不到。
    if WB_HOME:
        child_env["WORKBUDDY_HOME"] = WB_HOME
        child_env["WORKBUDDY_POOL_HOME"] = WB_HOME
        # 连接器的凭据也按 HOME 定位：
        #   wecom → <HOME>/.workbuddy/connectors/<session>/wecom-cli/personal/credentials.enc
        #   lark  → <HOME>/.lark-cli/config.json
        # 计划任务环境下 HOME 指向系统账户，读不到账号池里已授权的凭据。
        # 注意这里只覆盖 HOME/USERPROFILE，不动其它系统变量。
        if os.path.isdir(WB_HOME):
            child_env["HOME"] = WB_HOME
            child_env["USERPROFILE"] = WB_HOME
        # 调试开关：置 1 时把每次 CLI 调用的 argv/环境/输出写到 wa_cli_debug.log
        child_env.setdefault("WB_CLI_DEBUG", "1")
        # 连接器 CLI 的环境变量（凭据目录等）：没有它 CLI 读不到已授权凭据
        for k, v in _load_cli_env(WB_HOME).items():
            child_env[k] = v
    try:
        os.makedirs(HOME_DIR, exist_ok=True)
    except OSError:
        pass
    log = open(os.path.join(DIR, 'wa_stdout.log'), 'ab', buffering=0)
    # 依赖自愈：site-packages 偶尔会被清理/裁剪（比如只留 .pyd 扩展、删掉
    # AES.py / __init__.py），表现是 server.py 一启动就
    # ImportError: cannot import name 'AES' from 'Crypto.Cipher' → 服务起不来，
    # 但表面看是"代码有问题"。这里启动前探一次，缺就静默装回来。
    try:
        _ensure_deps(log)
    except Exception:
        pass
    try:
        p = subprocess.Popen(
            [PY, '-u', 'server.py', '7890'],
            cwd=DIR,
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            creationflags=CREATE_NO_WINDOW,
        )
        with open(os.path.join(DIR, 'wa_pid.txt'), 'w') as f:
            f.write(str(p.pid))
    except Exception as e:
        log.write(('start failed: %r\n' % (e,)).encode('utf-8', 'ignore'))
        p = None

    # 大屏浏览器：由本进程（计划任务托管）拉起。
    # 坑：直接从交互式 shell / Agent 会话拉起的 Chrome 会被**沙箱 Job Object
    # 回收** —— 进程刚起就消失，表现为「大屏莫名其妙没了」。
    # 只有挂在计划任务这条链上（boot.py → server.py → chrome）才能存活。
    try:
        _launch_bigscreen(child_env)
    except Exception as e:
        try:
            log.write(('bigscreen launch failed: %r\n' % (e,)).encode("utf-8", "ignore"))
        except Exception:
            pass

    # ---- 常驻守护 ----
    # 为什么必须常驻：boot.py 一旦退出，作为子进程的 server.py
    # 会被 Windows 的 Job Object **连坐回收**（计划任务结束 = 整个作业树结束）。
    # 表现就是「大屏开着开着服务就没了」，只能手动重启。
    #
    # 这里守着 server.py：
    #   * 它退出（崩溃/被杀）→ 隔几秒自动拉起
    #   * 它活着 → boot.py 一直不退出，计划任务保持 Running
    if p is not None:
        import time as _time
        # 退避：连续崩溃时拉长间隔，避免「启动→秒退→再启动」的风暴。
        # 风暴期间端口时通时断，前端就会随机报 Failed to fetch。
        backoff = 3
        while True:
            t_run = _time.time()
            try:
                rc = p.wait()
            except Exception as e:
                # p.wait() 异常绝不能退出整个 watchdog：
                # boot.py 一旦退出，作为子进程的 server.py 会被 Windows 的
                # Job Object 连坐回收 → 「大屏开着开着服务就没了」，
                # 而且计划任务显示 Ready 但没人守着。
                # 这里记录后继续守着，等下一次 p.wait() 拿到真实退出码。
                try:
                    log.write(('[watchdog] p.wait() error: %r, keep watching...\n'
                               % (e,)).encode('utf-8', 'ignore'))
                except Exception:
                    pass
                _time.sleep(2)
                continue
            ran = _time.time() - t_run
            # 稳定跑够一分钟 → 认定为偶发崩溃，退避复位
            if ran > 60:
                backoff = 3
            # server.py 退出了 → 重启它
            try:
                log.write(('[watchdog] server.py exited (rc=%s, ran %.0fs), restarting...\n'
                           % (rc, ran)).encode('utf-8', 'ignore'))
            except Exception:
                pass
            # 【主动退出不重启】server.py 用返回码表达"我不该再跑"：
            #   3 = 已有另一个实例在跑；4 = 端口被占用。
            # 这两种情况重启只会制造双实例/抢端口风暴，必须停手。
            if rc in (3, 4):
                try:
                    log.write(('[watchdog] server.py 主动退出 (rc=%s)，不再重启；'
                               '请先清理旧实例。\n' % rc).encode('utf-8', 'ignore'))
                except Exception:
                    pass
                break
            _time.sleep(backoff)
            # 等旧进程真正把 7890 让出来：还能连上就说明还有人占着，
            # 再等一会；连不上说明已释放，立刻拉起新进程（避免抢端口失败）
            for _ in range(80):
                try:
                    import socket as _sock
                    _s = _sock.socket()
                    _s.settimeout(0.3)
                    _s.connect(('127.0.0.1', 7890))
                    _s.close()
                    _time.sleep(0.25)
                except Exception:
                    break
            try:
                # 诊断模式：wa_fault_dump.flag 存在时，重启的 server 每 8 秒
                # 把所有线程栈写进 wa_fault.log。排查卡死后删掉这个 flag 即可。
                _renv = dict(child_env)
                if os.path.isfile(os.path.join(DIR, 'wa_fault_dump.flag')):
                    _renv['WB_FAULT_DUMP'] = '8'
                p = subprocess.Popen(
                    [PY, '-u', 'server.py', '7890'],
                    cwd=DIR,
                    env=_renv,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    creationflags=CREATE_NO_WINDOW,
                )
                with open(os.path.join(DIR, 'wa_pid.txt'), 'w') as f:
                    f.write(str(p.pid))
                backoff = min(backoff * 2, 30)
            except Exception as e:
                try:
                    log.write(('restart failed: %r\n' % (e,)).encode('utf-8', 'ignore'))
                except Exception:
                    pass
                _time.sleep(5)


def _launch_bigscreen(child_env):
    """拉起大屏 Chrome（--app 全屏、任务栏无图标）。"""
    import time as _time
    # 等服务起来再开页面，否则大屏会显示"无法连接"
    for _ in range(40):
        _time.sleep(0.5)
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:7890/api/platforms", timeout=3)
            break
        except Exception:
            continue
    # 环境要显式传下去：WB_ANALYZER_HOME 决定状态目录（profile 路径），
    # WB_PLAT 决定大屏默认停在哪个平台。
    # 坑：计划任务环境里 USERPROFILE 指向系统账户，
    # 不传 child_env 的话大屏的 Chrome profile 会落到系统账户目录下，
    # 跟服务用的账号池目录不一致。
    old = {}
    try:
        for k in ("WB_ANALYZER_HOME", "WB_PLAT", "WORKBUDDY_HOME",
                  "WORKBUDDY_POOL_HOME", "HOME", "USERPROFILE"):
            old[k] = os.environ.get(k)
            if child_env.get(k):
                os.environ[k] = child_env[k]
        import launch_big
        # 用 DEFAULT_URL（可能带 ?plat=xxx），不要写死 URL
        launch_big.open_window(launch_big.DEFAULT_URL, fullscreen=True)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


if __name__ == "__main__":
    main()
