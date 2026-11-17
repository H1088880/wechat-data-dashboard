# -*- coding: utf-8 -*-
"""
云端平台适配器：把飞书 / 钉钉 / 企业微信的在线聊天记录拉进本地仓库。

设计原则
--------
1. **CLI 是唯一入口**。三个平台在 WorkBuddy 里都是官方 CLI 连接器：
       飞书      lark-cli     （@larksuite/cli）
       钉钉      dws          （dingtalk-workspace-cli）
       企业微信  wecom-cli    （@wecom/cli）
   统一走 subprocess 调用，不引入 SDK 依赖。

2. **拉取与展示分离**。在线 API 每次都要鉴权+分页，延迟高且不稳；
   所以「拉一次 → 落本地 SQLite（cloudstore）→ 看板读本地库」。
   看板因此是毫秒级响应，也不会因为平台 API 抖动而白屏。

3. **归一化到统一结构**。三家字段名完全不同：
       飞书   message_id / create_time / body.content / sender.id
       钉钉   messageId  / createTime   / content     / senderId
       企微   msg_id     / send_time    / text.content/ userid
   这里统一成：
       msg_id / ts / content / sender_id / sender_name / is_self / msg_type

4. **只读**。只调用 list/search 类命令，绝不发送消息。

时间戳统一转为 Unix 秒（int）。
"""
import os
import re
import json
import time
import shutil
import subprocess
import threading

import cloudstore
import env

BASE = os.path.dirname(os.path.abspath(__file__))


def _cli_dirs():
    """CLI 可执行文件候选目录（按优先级）。

    连接器 CLI 装在 <workbuddy_root>/.workbuddy/binaries/node/ 下，
    但**不一定在同一个子目录**：
      · cli-connector-packages/  ← wecom-cli 等 npm 全局包装
      · versions/<ver>/           ← lark-cli / dws
    所以两个子目录都要列为候选，让 _find_cli 逐个找。

    坑：计划任务启动的服务继承系统账户环境（USERPROFILE=C:\\Users\\<user>），
    那边的 .workbuddy 有 node 运行时但**没有**这些 CLI —— 不能只靠 USERPROFILE。
    统一走 env.workbuddy_root()（它会校验"确实装了 CLI 包"）。
    """
    dirs = []
    # 1) 技能包同级（技能装在 <root>/.workbuddy/skills/wb-analyzer/app 下）
    skill_root = os.path.dirname(os.path.dirname(BASE))
    dirs.append(os.path.join(skill_root, ".workbuddy", "binaries", "node",
                             "cli-connector-packages"))
    dirs.append(os.path.join(skill_root, ".workbuddy", "binaries", "node"))

    # 2) WorkBuddy 根目录（权威来源）
    root = env.workbuddy_root()
    if root:
        node_dir = os.path.join(root, ".workbuddy", "binaries", "node")
        dirs.append(os.path.join(node_dir, "cli-connector-packages"))
        dirs.append(node_dir)
        vers = os.path.join(node_dir, "versions")
        if os.path.isdir(vers):
            for v in sorted(os.listdir(vers), reverse=True):
                dirs.append(os.path.join(vers, v))

    # 3) 用户主目录（常规安装）
    node_dir = os.path.join(env.home_dir(), ".workbuddy", "binaries", "node")
    dirs.append(os.path.join(node_dir, "cli-connector-packages"))
    dirs.append(node_dir)

    # 4) 状态目录同级（自部署场景）
    dirs.append(os.path.join(os.path.dirname(env.state_dir()), "binaries", "node",
                             "cli-connector-packages"))
    # 去重并保序
    out = []
    for d in dirs:
        if d and d not in out:
            out.append(d)
    return out


_CLI_DIRS = _cli_dirs()

_EXEC = {}

# ── 入口 JS：直接用 node.exe 跑，绕开 .cmd 包装对 PATH 里 node 的依赖 ──────
# 坑：wecom-cli.cmd 所在目录没有 node.exe，它会 fallback 成 "node"，
# 而计划任务启动的服务 PATH 里没有 node → 命令直接跑不起来。
# dws.cmd / lark-cli.cmd 与 node.exe 同目录，没这个问题，但统一处理更省心。
_CLI_ENTRIES = {
    "wecom-cli": os.path.join("node_modules", "@wecom", "cli", "bin", "wecom.js"),
    "lark-cli": os.path.join("node_modules", "@larksuite", "cli", "scripts", "run.js"),
    "dws": os.path.join("node_modules", "dingtalk-workspace-cli", "bin", "dws.js"),
}


def _node_exe():
    """定位 node.exe 绝对路径。"""
    root = env.workbuddy_root()
    if root:
        node_dir = os.path.join(root, ".workbuddy", "binaries", "node")
        # versions/<ver>/node.exe
        vers = os.path.join(node_dir, "versions")
        if os.path.isdir(vers):
            for name in sorted(os.listdir(vers), reverse=True):
                cand = os.path.join(vers, name, "node.exe")
                if os.path.isfile(cand):
                    return cand
        cand = os.path.join(node_dir, "node.exe")
        if os.path.isfile(cand):
            return cand
    p = shutil.which("node")
    return p or None


_NODE = None


def _argv(cli, args):
    """把 (cli, args) 展开成可直接 exec 的 argv。

    优先用 node.exe + 入口 JS（不依赖 PATH）；找不到就退回原 .cmd。
    """
    if cli:
        name = os.path.basename(cli)
        for ext in (".cmd", ".CMD", ".exe", ""):
            if name.endswith(ext):
                name = name[: -len(ext)] if ext else name
                break
        rel = _CLI_ENTRIES.get(name)
        if rel:
            global _NODE
            if _NODE is None:
                _NODE = _node_exe()
            if _NODE:
                js = os.path.join(os.path.dirname(cli), rel)
                if os.path.isfile(js):
                    return [_NODE, js] + list(args)
    return [cli] + list(args)


def _find_cli(name):
    """定位 CLI 可执行文件。返回路径或 None。"""
    if name in _EXEC:
        return _EXEC[name]
    cands = []
    for d in _CLI_DIRS:
        for ext in (".cmd", ".exe", ""):
            cands.append(os.path.join(d, name + ext))
    for c in cands:
        if os.path.isfile(c):
            _EXEC[name] = c
            return c
    p = shutil.which(name)
    if p:
        _EXEC[name] = p
        return p
    _EXEC[name] = None
    return None


def _run(cli, args, timeout=180):
    """执行 CLI 并返回 (ok, stdout, stderr)。全程无窗口。

    cwd 固定为 BASE：dws 的 --output 只接受**工作目录内的相对路径**，
    服务进程的 cwd 未必是代码目录，不固定就会报「只接受工作目录内的相对路径」。
    """
    if not cli:
        return False, "", "未找到 CLI 可执行文件"
    argv = _argv(cli, args)
    try:
        cp = env.run_hidden(argv, timeout=timeout, cwd=BASE)
    except subprocess.TimeoutExpired:
        return False, "", "命令超时"
    except Exception as e:
        return False, "", str(e)
    out = cp.stdout.decode("utf-8", "ignore")
    err = cp.stderr.decode("utf-8", "ignore")
    if os.environ.get("WB_CLI_DEBUG"):
        try:
            with open(os.path.join(BASE, "wa_cli_debug.log"), "a", encoding="utf-8") as f:
                f.write("argv=%s\n  HOME=%s\n  CWD=%s\n  USER=%s\n  out=%s\n  err=%s\n" % (
                    argv, os.environ.get("HOME"), os.getcwd(),
                    _whoami(),
                    out[:300].replace("\n", " | "),
                    err[:300].replace("\n", " | ")))
                # 只记可疑的环境变量（CLI 可能据此定位凭据目录）
                for k in sorted(os.environ):
                    if re.search(r"WORKBUDDY|WECON|LARK|DING|DWS|CONNECTOR|SESSION|WB_", k, re.I):
                        f.write("    env %s=%s\n" % (k, os.environ[k][:120]))
                f.write("    cred_probe: %s\n" % _cred_probe())
                f.write("    probe_run: %s\n" % _probe_run(argv))
                f.write("    ENV_DUMP_BEGIN\n")
                for k in sorted(os.environ):
                    f.write("      %s=%s\n" % (k, os.environ[k][:200]))
                f.write("    ENV_DUMP_END\n---\n")
        except OSError:
            pass
    return cp.returncode == 0, out, err


def _whoami():
    """当前进程用户身份（诊断用）。"""
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "?"


def _probe_run(argv):
    """诊断：绕开 run_hidden，直接 subprocess.run 一次 CLI。"""
    try:
        import subprocess as _sp
        r = _sp.run(argv, capture_output=True, timeout=60)
        return "rc=%s out=%s err=%s" % (
            r.returncode,
            r.stdout.decode("utf-8", "ignore")[:200].replace("\n", " | "),
            r.stderr.decode("utf-8", "ignore")[:200].replace("\n", " | "))
    except Exception as e:  # noqa: BLE001
        return "err=%r" % (e,)


def _cred_probe():
    """诊断：直接读凭据文件，看服务进程能不能访问。"""
    home = os.environ.get("HOME") or ""
    root = os.path.join(home, ".workbuddy", "connectors")
    out = []
    try:
        sess = os.listdir(root)
    except OSError as e:
        return "connectors 目录不可读: %r" % (e,)
    for s in sess:
        if s.startswith("."):
            continue
        d = os.path.join(root, s, "wecom-cli", "personal")
        if not os.path.isdir(d):
            continue
        for fn in (".encryption_key", "credentials.enc"):
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
                out.append("%s/%s size=%d mtime=%d" % (s[:8], fn, st.st_size, int(st.st_mtime)))
            except OSError as e:
                out.append("%s/%s ERR %r" % (s[:8], fn, e))
    return " | ".join(out) if out else "no cred dirs"


def _render_qr(text, title="", code=""):
    """把文本渲染成二维码 PNG，返回文件路径（失败返回空串）。

    dws 的设备码流程只输出文字链接，不给图片，所以统一在这里补一层渲染，
    让所有平台的登录入口在网页上长得一样：都是一张能直接扫的图。
    """
    import time as _time
    try:
        import qrcode
    except Exception:
        return ""
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                           box_size=10, border=2)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    except Exception:
        return ""
    try:
        from PIL import Image, ImageDraw, ImageFont
        W, H = img.size
        pad = 90 if title else 20
        bottom = 70 if (title or code) else 0
        canvas = Image.new("RGB", (W + pad * 2, H + pad * 2 + bottom), "white")
        canvas.paste(img, (pad, pad))
        d2 = ImageDraw.Draw(canvas)
        f = f2 = None
        for cand in ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc",
                     "C:/Windows/Fonts/simhei.ttf"):
            try:
                f = ImageFont.truetype(cand, 40)
                f2 = ImageFont.truetype(cand, 28)
                break
            except Exception:
                continue
        if f is None:
            f = f2 = ImageFont.load_default()
        if title:
            d2.text((W // 2 + pad, pad - 52), title, fill="black", font=f, anchor="mm")
        if code:
            d2.text((W // 2 + pad, H + pad + 38), "设备码 " + code,
                    fill="black", font=f2, anchor="mm")
        img = canvas
    except Exception:
        pass
    path = os.path.join(BASE, "qr_%d.png" % int(_time.time() * 1000))
    try:
        img.save(path)
        return path
    except Exception:
        return ""


def _run_bg(cli, args, timeout=180, wait_for_exit=True, grace=12.0, bg_key=None):
    """后台执行 CLI（登录流程会阻塞等待用户扫码），返回 (ok, stdout, stderr)。

    用 Popen + 临时文件落盘，避免把登录进程挂在请求线程上。

    wait_for_exit=False 时：进程启动后最多等 grace 秒就返回，
    期间读到的 stdout/stderr 已经返回（扫码链接通常这时就打出来了），
    CLI 进程继续在后台等用户扫码，不会把 HTTP 请求挂死。
    """
    if not cli:
        return False, "", "未找到 CLI 可执行文件"
    import tempfile
    import time as _time
    out_f = tempfile.NamedTemporaryFile(prefix="wbcli_", suffix=".out", delete=False)
    err_f = tempfile.NamedTemporaryFile(prefix="wbcli_", suffix=".err", delete=False)
    try:
        p = env.popen_hidden(_argv(cli, args), stdout=out_f, stderr=err_f,
                             cwd=BASE,
                             stdin=subprocess.DEVNULL)
    except Exception as e:
        out_f.close(); err_f.close()
        return False, "", str(e)

    if wait_for_exit:
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
    else:
        # 给 CLI 一点时间把扫码链接/二维码写出来，然后立刻返回。
        # 坑：CLI 启动监听端口 + 打印链接要十几秒，若 grace 太短就读到**空输出**，
        # 大屏上就显示"拿不到链接"。这里 grace 到期且输出仍为空时，
        # 再补一段等待（最多 30s），给慢启动的 CLI 留出余量。
        def _peek():
            out_txt = ""
            for _fn in (out_f.name, err_f.name):
                try:
                    with open(_fn, "r", encoding="utf-8", errors="ignore") as _f:
                        out_txt += _f.read()
                except Exception:
                    pass
            return out_txt

        deadline = _time.time() + max(1.0, float(grace))
        while _time.time() < deadline:
            if p.poll() is not None:
                break
            if _peek().strip():
                break
            _time.sleep(0.3)
        # grace 用完但还没输出 → 再等等（CLI 可能还在起端口）
        if not _peek().strip() and p.poll() is None:
            extra = _time.time() + 30.0
            while _time.time() < extra:
                if p.poll() is not None:
                    break
                if _peek().strip():
                    break
                _time.sleep(0.4)

    def _read(fh):
        try:
            fh.flush()
        except Exception:
            pass
        try:
            return open(fh.name, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            return ""

    out = _read(out_f)
    err = _read(err_f)
    out_f.close(); err_f.close()
    if wait_for_exit:
        for f in (out_f.name, err_f.name):
            try:
                os.unlink(f)
            except Exception:
                pass
    else:
        # 后台进程还在跑，临时文件交给它，别急着删
        try:
            p._wb_tmpfiles = (out_f.name, err_f.name)
        except Exception:
            pass
        # 登记到登录进程登记簿：下次发起同平台登录时先把它结束掉，
        # 避免两个设备码/扫码流程同时在等，用户扫了新的却没反应。
        if bg_key:
            _kill_bg_login(bg_key)
            _register_bg_login(bg_key, p)
    return (p.returncode == 0) if p.poll() is not None else True, out, err


# ── 后台登录进程登记簿 ─────────────────────────────────────────────
# 坑：设备码/扫码流程是长轮询进程。每次点「授权」都会新起一个，
# 旧的不结束就会出现**两个码同时在等**——用户扫了新的，
# 旧进程还在轮询同一个 CLI 状态，表现为「扫了但没反应」；
# 更糟的是旧码先过期会把 CLI 的凭据文件写坏。
# 这里登记所有后台登录进程，发起新流程前先把同平台的旧进程结束掉。
_BG_LOGINS = {}
_BG_LOCK = threading.Lock()


def _kill_bg_login(key):
    """结束某平台上一次遗留的后台登录进程。"""
    with _BG_LOCK:
        p = _BG_LOGINS.pop(key, None)
    if p is None:
        return
    try:
        if p.poll() is None:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
    except Exception:
        pass
    for f in getattr(p, "_wb_tmpfiles", ()) or ():
        try:
            os.unlink(f)
        except Exception:
            pass


def _register_bg_login(key, p):
    with _BG_LOCK:
        _BG_LOGINS[key] = p


def _auth_state(text):
    """从 CLI 的授权输出里解析状态。

    坑：早期版本用 `"authorized" in txt` 判断，结果 "unauthorized" 里也含
    "authorized"，导致未授权被误判成已授权（三个平台全中招）。
    这里改成严格匹配 Status 字段，并优先识别否定词。
    """
    low = (text or "").lower()
    # 先找否定
    if re.search(r"\bunauthorized\b", low):
        return False
    if re.search(r"\bnot\s+authorized\b", low):
        return False
    if re.search(r"\bunauthoriz(?:ed|ation)\b", low):
        return False
    if re.search(r"\bnot\s+log(?:ged)?\s*in\b", low):
        return False
    # 再找肯定
    m = re.search(r"status\s*[:=]\s*([a-z_]+)", low)
    if m:
        val = m.group(1)
        if "unauth" in val or "expired" in val or "not" in val:
            return False
        if "auth" in val or "ok" in val or "login" in val:
            return True
    if re.search(r"\bauthorized\b", low):
        return True
    if re.search(r"\blogged\s*in\b", low):
        return True
    return None


def _json_from(out):
    """从 CLI 输出里抽出 JSON。CLI 可能输出 NDJSON（每行一个 JSON）。"""
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        pass
    # NDJSON：逐行尝试
    objs = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except Exception:
            continue
    if objs:
        return objs
    # 从输出里抠出第一个 {...}
    i = out.find("{")
    j = out.rfind("}")
    if i >= 0 and j > i:
        try:
            return json.loads(out[i:j + 1])
        except Exception:
            pass
    return None


def _ts_any(v):
    """把各种时间格式转成 Unix 秒。"""
    if v is None or v == "":
        return 0
    if isinstance(v, (int, float)):
        t = int(v)
        if t > 1e12:
            t //= 1000
        return t if t > 0 else 0
    s = str(v).strip()
    if s.isdigit():
        t = int(s)
        if t > 1e12:
            t //= 1000
        return t if t > 0 else 0
    # "2026-03-10 00:00:00" / "2026-03-10T00:00:00+08:00"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return int(time.mktime(time.strptime(s[:len(fmt) + 6], fmt)))
        except Exception:
            continue
    try:
        return int(time.mktime(time.strptime(s[:19], "%Y-%m-%d %H:%M:%S")))
    except Exception:
        return 0


# =====================================================================
#  基类
# =====================================================================

class PlatformAdapter:
    key = ""          # 平台标识（写进 cloudstore）
    label = ""        # 中文名
    cli_name = ""     # 可执行文件名
    empty_hint = ""   # 未安装/未授权时的提示

    def __init__(self):
        self.cli = _find_cli(self.cli_name)

    # ---- 可用性 ----
    def installed(self):
        return bool(self.cli)

    def status(self):
        """返回 {ok, installed, authorized, detail}

        注意：authorized 必须真的跑一次 auth_check，否则永远返回 None，
        看板上三个平台的"已登录"标识就一直是空的。
        auth_check 失败（超时/CLI 异常）不该让整个状态探测崩掉，
        这里降级成 authorized=False + 保留 detail。
        """
        if not self.installed():
            return {"ok": False, "installed": False, "authorized": False,
                    "detail": self.empty_hint}
        try:
            auth, detail = self.auth_check()
        except Exception as e:  # noqa: BLE001
            return {"ok": True, "installed": True, "authorized": False,
                    "detail": "授权状态探测失败：%s" % str(e)[:200]}
        return {"ok": True, "installed": True, "authorized": bool(auth),
                "detail": detail or ""}

    # ---- 子类实现 ----
    def auth_check(self):
        """检查授权状态，返回 (authorized: bool, detail: str)"""
        raise NotImplementedError

    def login(self):
        """触发登录流程，返回 {method, url, code, qrcode_path, hint}。

        默认不支持，平台子类覆写。登录只写 CLI 自己的凭据存储，
        不碰任何聊天数据。
        """
        return {"ok": False, "error": "该平台暂不支持从看板直接登录"}

    def fetch_conversations(self, begin, end):
        """返回 [{id, name, chat_type}]"""
        raise NotImplementedError

    def fetch_messages(self, cid, begin, end):
        """返回 [{msg_id, ts, content, sender_id, sender_name, is_self, msg_type}]"""
        raise NotImplementedError

    # ---- 通用同步 ----
    def sync(self, days=7, limit_convs=50, progress=None):
        """拉取最近 N 天的会话与消息，写入本地仓库。

        返回统计字典。失败时 ok=False 且带 reason。
        """
        if not self.installed():
            return {"ok": False, "reason": self.empty_hint, "platform": self.key}
        auth, detail = self.auth_check()
        if not auth:
            return {"ok": False, "reason": detail or "未授权", "platform": self.key}

        end = time.time()
        begin = end - days * 86400
        bt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(begin))
        et = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end))

        try:
            convs = self.fetch_conversations(bt, et)
        except Exception as e:
            return {"ok": False, "reason": f"拉取会话列表失败：{e}", "platform": self.key}

        convs = convs[:limit_convs]
        total_msgs = 0
        conv_done = 0
        for i, cv in enumerate(convs):
            try:
                msgs = self.fetch_messages(cv["id"], bt, et)
            except Exception:
                msgs = []
            if msgs:
                cloudstore.add_messages(self.key, cv["id"], msgs)
                total_msgs += len(msgs)
            cloudstore.upsert_conversation(
                self.key, cv["id"], cv.get("name") or cv["id"],
                cv.get("chat_type") or "", max([m["ts"] for m in msgs] or [0]))
            conv_done += 1
            if progress:
                progress(conv_done, len(convs), cv.get("name") or cv["id"])
        return {
            "ok": True, "platform": self.key, "label": self.label,
            "conversations": conv_done, "messages": total_msgs,
            "days": days,
        }


# =====================================================================
#  企业微信
# =====================================================================

class WeComAdapter(PlatformAdapter):
    key = "wecom"
    label = "企业微信"
    cli_name = "wecom-cli"
    empty_hint = "未找到 wecom-cli，请在连接器面板安装并登录企业微信"

    # ── 能力边界（重要，别踩坑）─────────────────────────────
    # wecom-cli 是**机器人视角**的 CLI：
    #   · chat groups list  —— "仅支持查询最近 7 天" 且 "目前仅群聊"，
    #     只能列出**这个机器人所在的群**，且群里有消息才会出现。
    #     机器人没被拉进任何群 → chats_count = 0，这是真实情况，不是 bug。
    #   · message           —— 只有 send，没有历史消息拉取。
    #   · doc / sheet / calendar / contact —— 这些正常可用。
    # 所以「机器人没进群」时同步 0 条属于预期；想拉聊天记录得让机器人进群。
    #
    # 与飞书对比：飞书 CLI 有 +chat-list / +chat-messages-list（用户身份），
    # 能拉到个人会话历史，所以飞书的数据更全。

    def auth_check(self):
        ok, out, err = _run(self.cli, ["auth", "show"])
        st = _auth_state(out + err)
        if st is True:
            return True, ""
        return False, "企业微信未授权（Status: unauthorized），请在连接器面板完成登录"

    def login(self):
        """企微扫码登录：非交互模式跑一次 auth init，把扫码链接取出来。

        注意：wecom-cli 的 --output-qrcode 在文件已存在时会直接报
        "Failed to create output file ... (os error 80) AlreadyExists"，
        所以每次登录都要用一个新的文件名。
        """
        import re as _re
        import time as _time
        # 旧二维码先清掉，避免 CLI 拒绝覆盖；再用带时间戳的路径保证唯一
        try:
            old = os.path.join(BASE, "wecom_qr.png")
            if os.path.exists(old):
                os.remove(old)
        except Exception:
            pass
        qr = os.path.join(BASE, "wecom_qr_%d.png" % int(_time.time()))
        # wait_for_exit=False：CLI 会一直等用户扫码才退出，
        # 不能让 HTTP 请求等它。给 12 秒让它把链接和二维码写出来就返回。
        ok, out, err = _run_bg(self.cli, [
            "auth", "init", "--noninteractive", "--no-browser",
            "--output-qrcode", qr,
        ], timeout=300, wait_for_exit=False, grace=12.0, bg_key=self.key)
        txt = out + err
        m = _re.search(r"https://work\.weixin\.qq\.com/[^\s\"']+", txt)
        # 二维码可能比 stdout 晚落盘，最多再等 8 秒
        if not (os.path.exists(qr) and os.path.getsize(qr) > 0):
            deadline = _time.time() + 8.0
            while _time.time() < deadline:
                if os.path.exists(qr) and os.path.getsize(qr) > 0:
                    break
                _time.sleep(0.4)
        # CLI 可能把链接写在 stdout，也可能只生成图片；两种都算成功
        has_qr = os.path.exists(qr) and os.path.getsize(qr) > 0
        if has_qr:
            self._last_qrcode = qr
        return {
            "ok": bool(m or has_qr),
            "method": "qrcode",
            "url": m.group(0) if m else "",
            "qrcode": qr if has_qr else "",
            "hint": ("用企业微信扫码完成授权（有效期约 5 分钟）"
                     if (m or has_qr)
                     else "未能生成二维码：" + (err or out)[-200:]),
            "raw": txt[-600:],
        }

    def fetch_conversations(self, begin, end):
        ok, out, err = _run(self.cli, ["chat", "groups", "list",
                                       "--begin-time", begin, "--end-time", end,
                                       "--page-count", "20"])
        data = _json_from(out)
        if not isinstance(data, dict):
            return []
        chats = data.get("chats") or data.get("items") or []
        out_list = []
        for c in chats:
            if not isinstance(c, dict):
                continue
            cid = c.get("chat_id") or c.get("chatid") or c.get("id")
            if not cid:
                continue
            out_list.append({
                "id": cid,
                "name": c.get("chat_name") or c.get("name") or cid,
                "chat_type": c.get("chat_type") or "group",
            })
        return out_list

    def fetch_messages(self, cid, begin, end):
        ok, out, err = _run(self.cli, ["chat", "messages", "list",
                                       "--chat-id", cid,
                                       "--begin-time", begin, "--end-time", end,
                                       "--page-count", "20"])
        data = _json_from(out)
        if not isinstance(data, dict):
            return []
        msgs = data.get("messages") or []
        res = []
        for i, m in enumerate(msgs):
            if not isinstance(m, dict):
                continue
            text = ""
            mt = m.get("msg_type") or ""
            t = m.get("text")
            if isinstance(t, dict):
                text = t.get("content") or ""
            elif isinstance(t, str):
                text = t
            if not text:
                mixed = m.get("mixed")
                if isinstance(mixed, dict):
                    parts = mixed.get("items") or []
                    text = " ".join((p.get("text") or {}).get("content", "")
                                    for p in parts if isinstance(p, dict))
            if not text:
                continue
            ts = _ts_any(m.get("send_time"))
            res.append({
                "msg_id": m.get("msg_id") or m.get("msgid") or f"{cid}_{ts}_{i}",
                "ts": ts,
                "content": text,
                "sender_id": m.get("userid") or m.get("user_id") or "",
                "sender_name": m.get("user_name") or m.get("username") or "",
                "is_self": 0,
                "msg_type": mt,
            })
        return res


# =====================================================================
#  飞书
# =====================================================================

class FeishuAdapter(PlatformAdapter):
    key = "feishu"
    label = "飞书"
    cli_name = "lark-cli"
    empty_hint = "未找到 lark-cli，请在连接器面板安装并登录飞书"

    def auth_check(self):
        # lark-cli auth status 返回 {"ok":false,"error":{"subtype":"not_configured"}}
        # 注意：它把 JSON 打到 stderr，不是 stdout。
        #
        # 登录成功后的实际结构（不是顶层 ok 字段）：
        #   {"identities":{"bot":{"status":"ready","available":true},
        #                   "user":{"status":"ready","tokenStatus":"valid", ...}}, ...}
        # 所以这里要按 identities 逐个判，而不是只看顶层 ok。
        ok, out, err = _run(self.cli, ["auth", "status"])
        txt = out + err
        data = _json_from(out) or _json_from(err)
        if isinstance(data, dict):
            # 1) 明确的错误结构
            if data.get("ok") is False:
                sub = ""
                e = data.get("error")
                if isinstance(e, dict):
                    sub = e.get("subtype") or e.get("type") or ""
                if sub == "not_configured":
                    return False, "飞书未配置：需运行 lark-cli config init --new 完成应用与账号配置"
                return False, "飞书未授权：" + (sub or "auth check failed")
            # 2) identities 结构：任一身份 ready 且 token 有效即视为已授权
            ids = data.get("identities")
            if isinstance(ids, dict):
                ready = []
                states = []
                for name, info in ids.items():
                    if not isinstance(info, dict):
                        continue
                    st = (info.get("status") or "?").lower()
                    tk = (info.get("tokenStatus") or "").lower()
                    states.append("%s=%s" % (name, st))
                    if st in ("ready", "authorized", "logged_in") or tk == "valid":
                        ready.append(name)
                if ready:
                    return True, ""
                return False, "飞书未授权（身份状态：" + ",".join(states) + "）"
            if data.get("ok") is True:
                return True, ""
        st = _auth_state(txt)
        if st is True:
            return True, ""
        return False, "飞书未授权（未检测到登录配置），请在连接器面板完成登录"

    def login(self):
        """飞书登录：config init 是设备流，输出验证 URL 需要浏览器完成。"""
        import re as _re
        # 设备流会一直等用户在浏览器里完成，不能阻塞 HTTP 请求
        ok, out, err = _run_bg(self.cli, ["config", "init", "--new"],
                               timeout=300, wait_for_exit=False, grace=12.0,
                               bg_key=self.key)
        txt = out + err
        m = _re.search(r"https://[^\s\"']+", txt)
        url = m.group(0) if m else ""
        # lark-cli 输出里带 ANSI 背景色的「字符画二维码」，网页 <pre> 里会被
        # 主题色渲染成一片灰蓝花块（看着像乱码）。统一渲染成标准黑白二维码 PNG，
        # 前端 <img> 直接显示这张图即可扫码；raw 仍保留纯文字链接做备份。
        qr = _render_qr(url, "飞书授权") if url else ""
        if qr:
            self._last_qrcode = qr
        # 去掉 CLI 输出里的 ANSI 颜色码和纯方块字符行（字符画二维码），
        # 否则网页 <pre> 里显示成灰蓝花块，看着像乱码。
        import re as _re2
        _ansi = _re2.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        _clean = _ansi.sub("", txt[-600:])
        _clean = "\n".join(
            ln for ln in _clean.splitlines()
            if not _re2.fullmatch(r"[\s█▀▄▌▐■□▪▫]*", ln)
        )
        return {
            "ok": bool(m),
            "method": "device_flow",
            "url": url,
            "qrcode": qr,
            "hint": ("打开链接或扫码完成飞书应用与账号配置" if m
                     else "未能获取飞书验证链接：" + (err or out)[-200:]),
            "raw": _clean,
        }

    def fetch_conversations(self, begin, end):
        # `im +chat-list` 的实际结构是：
        #   {"ok":true,"identity":"user","data":{"chats":[{...}], "page_token": ...}}
        # 注意 chats 嵌在 **data** 里（不是顶层），早先读顶层导致一直返回 0 条。
        ok, out, err = _run(self.cli, ["im", "+chat-list"], timeout=120)
        data = _json_from(out)
        if not isinstance(data, dict):
            return []
        items = []
        for src in (data.get("data"), data):
            if isinstance(src, dict):
                got = src.get("chats") or src.get("items") or src.get("list")
                if isinstance(got, list):
                    items = got
                    break
        res = []
        for c in items:
            if not isinstance(c, dict):
                continue
            cid = c.get("chat_id") or c.get("id")
            if not cid:
                continue
            res.append({
                "id": cid,
                "name": c.get("name") or c.get("chat_name") or cid,
                "chat_type": c.get("chat_mode") or c.get("chat_type") or "group",
            })
        return res

    def fetch_messages(self, cid, begin, end):
        ok, out, err = _run(self.cli, [
            "im", "+chat-messages-list", "--chat-id", cid,
            "--start", begin[:10], "--end", end[:10],
            "--page-size", "50", "--page-all", "--page-limit", "10",
            "--no-reactions", "--format", "json",
        ], timeout=300)
        data = _json_from(out)
        if not isinstance(data, dict):
            return []
        # 实际结构：{"ok":true,"data":{"messages":[...], "has_more":...}}
        # messages 嵌在 data 里，早先只读顶层导致恒为 0 条。
        items = []
        for src in (data.get("data"), data):
            if isinstance(src, dict):
                got = src.get("messages") or src.get("items")
                if isinstance(got, list):
                    items = got
                    break
        res = []
        for i, m in enumerate(items):
            if not isinstance(m, dict):
                continue
            body = m.get("body") or {}
            content = ""
            if isinstance(body, dict):
                content = body.get("content") or ""
            if not content:
                content = m.get("content") or ""
            if isinstance(content, dict):
                content = content.get("text") or ""
            content = str(content)
            # 飞书的 content 是 JSON 字符串：{"text":"..."}
            if content.startswith("{"):
                try:
                    inner = json.loads(content)
                    if isinstance(inner, dict) and inner.get("text"):
                        content = inner["text"]
                except Exception:
                    pass
            if not content.strip():
                continue
            ts = _ts_any(m.get("create_time"))
            sender = m.get("sender") or {}
            sid = sname = ""
            if isinstance(sender, dict):
                sid = sender.get("id") or sender.get("id_type") or ""
                sname = sender.get("name") or sender.get("sender_id") or ""
            res.append({
                "msg_id": m.get("message_id") or m.get("msg_id") or f"{cid}_{ts}_{i}",
                "ts": ts,
                "content": content,
                "sender_id": sid,
                "sender_name": sname,
                "is_self": 0,
                "msg_type": m.get("msg_type") or "",
            })
        return res


# =====================================================================
#  钉钉
# =====================================================================

class DingTalkAdapter(PlatformAdapter):
    key = "dingtalk"
    label = "钉钉"
    cli_name = "dws"
    empty_hint = "未找到 dws，请在连接器面板安装并登录钉钉"

    def auth_check(self):
        ok, out, err = _run(self.cli, ["auth", "status"])
        txt = out + err
        data = _json_from(out) or _json_from(err)
        if isinstance(data, dict):
            if "authenticated" in data:
                return bool(data["authenticated"]), ("" if data["authenticated"] else "钉钉未授权，请在连接器面板完成登录")
            if data.get("ok") is True:
                return True, ""
            if data.get("ok") is False:
                return False, "钉钉未授权：" + str(data.get("message") or data.get("error") or "")[:160]
        st = _auth_state(txt)
        if st is True:
            return True, ""
        return False, "钉钉未授权，请在连接器面板完成登录"

    def login(self):
        """钉钉登录。

        两种流程：
          A) **OAuth Loopback（默认，优先）** —— dws 在本机起 127.0.0.1 监听，
             浏览器授权后回调回写 token。**链接永久有效**，不受 900 秒限制。
             手机钉钉打开该链接同样能完成授权（回调打到本机）。
          B) **设备流 --device（兜底）** —— 显示 user_code + 短链接，
             但设备码**只有 900 秒**，超时即失败。

        之前只用设备流，结果扫码时码已过期，授权静默失败。
        这里改成优先 loopback，把「限时码」降级为备选。

        dws 两种流程都**只吐文字链接**，不生成二维码图片，
        所以自己渲染 PNG，让大屏能像企微那样直接显示可扫码的图。
        """
        import re as _re
        import time as _time

        # ── A) loopback 流：链接永久有效，优先用 ──
        # grace 给足：dws 启动 loopback 监听 + 打印链接要十几秒，
        # 12 秒经常读到空输出，导致"拿不到链接"。
        ok_lb, out_lb, err_lb = _run_bg(self.cli, ["auth", "login"],
                                        timeout=900, wait_for_exit=False,
                                        grace=30.0, bg_key=self.key)
        txt_lb = out_lb + err_lb
        url_lb = ""
        m = _re.search(r"https://login\.dingtalk\.com/oauth2/auth[^\s\"']+", txt_lb)
        if m:
            url_lb = m.group(0)

        # ── B) 设备流兜底 ──
        ok_dv, out_dv, err_dv = ("", "", "")
        code = ""
        url_dv = ""
        if not url_lb:
            ok_dv, out_dv, err_dv = _run_bg(self.cli, ["auth", "login", "--device"],
                                            timeout=300, wait_for_exit=False,
                                            grace=18.0, bg_key=self.key)
            txt_dv = out_dv + err_dv
            md = _re.search(r"https://login\.dingtalk\.com/[^\s\"']+", txt_dv)
            if md:
                url_dv = md.group(0)
            # dws 输出形如：authorization code: XXXX-XXXX
            m2 = _re.search(r"authorization code:\s*([A-Za-z0-9\-]{4,})",
                            txt_dv, _re.I)
            if m2:
                code = m2.group(1)
            else:
                m3 = _re.search(r"user_code=([A-Za-z0-9\-]{4,})", txt_dv)
                if m3:
                    code = m3.group(1)

        url = url_lb or url_dv
        scan_url = url
        if url_dv and code and "user_code=" not in url_dv:
            scan_url = url_dv + "&user_code=" + code
        qr = ""
        if scan_url:
            qr = _render_qr(scan_url, "钉钉授权", code)
        if qr:
            self._last_qrcode = qr
        if url_lb:
            hint = ("用钉钉 App 打开下方链接完成授权（永久有效，不限时）"
                    if qr else "打开链接完成钉钉授权")
        elif url_dv or code:
            hint = "用钉钉 App 扫码完成授权（有效期约 15 分钟）"
        else:
            hint = "未能获取钉钉授权链接：" + (err_lb or out_lb or err_dv or out_dv)[-200:]
        return {
            "ok": bool(url or code),
            "method": "oauth_loopback" if url_lb else "device_flow",
            "url": url,
            "scan_url": scan_url,
            "code": code,
            "qrcode": qr,
            "hint": hint,
            "raw": (txt_lb or out_dv + err_dv)[-600:],
        }

    def fetch_conversations(self, begin, end):
        """列出当前用户加入的会话（群聊 + 单聊）。

        坑（接口选错 → 只拿到 1 个空群）：
          · `chat group list-my-groups` 返回的是「我创建/管理的组织群」，
            刚授权完只有一个「XX公司」组织群，**真正的业务群不在里面**；
          · `chat +chat-list` 才是「我加入的所有会话」，
            群聊 + 单聊都覆盖，还支持 --page-all 自动翻页。
        实际项目群（如「项目群104」，350 人）只能通过 +chat-list 拿到。

        结构：{"chats":[...], "count":N, "hasMore":bool, "nextCursor":...}
        注意 chats 在**顶层**。
        """
        res = []
        seen = set()

        def _add(c):
            if not isinstance(c, dict):
                return
            cid = (c.get("openConversationId") or c.get("conversation_id")
                   or c.get("id"))
            if not cid or cid in seen:
                return
            seen.add(cid)
            ctype = (c.get("conversationType") or c.get("chatMode")
                     or c.get("groupType") or "")
            res.append({
                "id": cid,
                "name": c.get("name") or c.get("title") or cid,
                "chat_type": "group" if "group" in str(ctype).lower() else "direct",
                "member_count": c.get("memberCount") or 0,
                "last_msg_at": c.get("lastMsgCreateAt") or "",
            })

        # 主路径：+chat-list（含群聊 + 单聊，自动翻页）
        ok, out, err = _run(self.cli, [
            "chat", "+chat-list", "--types", "group,p2p",
            "--page-all", "--page-limit", "50",
        ], timeout=300)
        data = _json_from(out)
        if isinstance(data, dict):
            items = data.get("chats") or data.get("items") or []
            if not items:
                for src in (data.get("result"), data.get("data")):
                    if isinstance(src, dict):
                        items = (src.get("chats") or src.get("groups")
                                 or src.get("items") or [])
                        if items:
                            break
                    elif isinstance(src, list):
                        items = src
                        break
            for c in items:
                _add(c)

        # 兜底：list-my-groups（+chat-list 失败时才用）
        if not res:
            ok, out, err = _run(self.cli, ["chat", "group", "list-my-groups",
                                           "--limit", "50"])
            data = _json_from(out)
            if isinstance(data, dict):
                items = data.get("groups") or data.get("items") or []
                if not items:
                    for src in (data.get("result"), data.get("data")):
                        if isinstance(src, dict):
                            items = (src.get("groups") or src.get("items")
                                     or src.get("list") or [])
                            if items:
                                break
                        elif isinstance(src, list):
                            items = src
                            break
                if isinstance(items, dict):
                    items = items.get("items") or items.get("groups") or []
                for c in items:
                    _add(c)
        return res
        return res

    def fetch_messages(self, cid, begin, end):
        # 坑（dws 对 --output 有三层限制）：
        #   1) 只接受 .json 文件扩展名，传 "-" 报「必须使用 .json 文件扩展名」；
        #   2) 只接受**工作目录内的相对路径**，传绝对路径报「只接受工作目录内的相对路径」；
        #   3) 文件名不能含中文/特殊字符。
        # 所以：在 BASE 目录下写一个纯 ASCII 临时文件名，跑完再读回来删掉。
        import tempfile
        out_name = "dwsmsg_%d.json" % int(time.time() * 1000)
        out_path = os.path.join(BASE, out_name)
        try:
            ok, out, err = _run(self.cli, [
                "chat", "+chat-messages", "--group", cid,
                "--time", begin[:19], "--page-all",
                "--max-results", "500", "--output", out_name,
            ], timeout=300)
            raw = ""
            try:
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
            except OSError:
                raw = ""
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
        data = _json_from(raw) or _json_from(out)
        items = []
        if isinstance(data, dict):
            items = data.get("messages") or data.get("items") or []
            if not items:
                for src in (data.get("result"), data.get("data")):
                    if isinstance(src, dict):
                        items = (src.get("messages") or src.get("items")
                                 or src.get("list") or [])
                        if items:
                            break
                    elif isinstance(src, list):
                        items = src
                        break
        elif isinstance(data, list):
            items = data
        res = []
        for i, m in enumerate(items):
            if not isinstance(m, dict):
                continue
            content = m.get("content") or m.get("text") or ""
            if isinstance(content, dict):
                content = content.get("text") or content.get("content") or ""
            content = str(content).strip()
            # 去掉零宽字符 / 软换行（钉钉富文本里大量 U+200B、U+FEFF），
            # 否则词频统计和展示都会出现看不见的噪声。
            # 用码点拼接构造正则，避免源码里出现不可见字符被编辑器吞掉。
            _zw = "[" + "".join("\\u%04x" % c for c in
                                (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060)) + "]"
            content = re.sub(_zw, "", content)
            content = re.sub(r"[ \t]+", " ", content).strip()
            # 去掉媒体占位文本：钉钉把图片/视频/文件渲染成
            #   [图片消息](mediaId=@xxx) / [视频消息](mediaId=@xxx fileName=...)
            # 这些不是人话，会污染词频（mediaId、fileName、"图片消息"切词残留等）。
            content = re.sub(r"\[(图片消息|视频消息|语音消息|文件消息|表情消息|动画表情)\]"
                             r"\([^)]*\)", "", content)
            content = re.sub(r"\(mediaId=[^)]*\)", "", content)
            content = re.sub(r"\bmediaId\b", "", content, flags=re.I)
            content = re.sub(r"\bfileName=[^\s]*", "", content)
            content = re.sub(r"\bfileid\b", "", content, flags=re.I)
            content = re.sub(r"\burl:\s*\S+", "", content)
            content = re.sub(r"[ \t]{2,}", " ", content).strip()
            if not content:
                continue
            ts = _ts_any(m.get("createTime") or m.get("create_time"))
            res.append({
                "msg_id": m.get("messageId") or m.get("msg_id") or f"{cid}_{ts}_{i}",
                "ts": ts,
                "content": content,
                "sender_id": m.get("senderId") or m.get("sender_staff_id") or "",
                # 坑：dws 的发送者展示名在 **sender** 字段（不是 senderNick），
                # 之前只认 senderNick → 大屏上所有消息的发送人都是空的。
                "sender_name": (m.get("sender") or m.get("senderNick")
                                or m.get("sender_name") or ""),
                "is_self": 0,
                "msg_type": m.get("msgtype") or m.get("msg_type") or "",
            })
        return res


# =====================================================================

_ADAPTERS = {}
_ALL = [WeComAdapter, FeishuAdapter, DingTalkAdapter]


def all_adapters():
    """返回全部适配器实例（按注册顺序）。"""
    global _ADAPTERS
    if not _ADAPTERS:
        for cls in _ALL:
            _ADAPTERS[cls.key] = cls()
    return [_ADAPTERS[c.key] for c in _ALL]


def get_adapter(key):
    for a in all_adapters():
        if a.key == key:
            return a
    return None


def platform_status():
    """每个平台的可用性 + 已同步的数据量。"""
    stats = cloudstore.platform_stats()
    out = []
    for a in all_adapters():
        st = a.status()
        if st.get("authorized") is None:
            try:
                auth, detail = a.auth_check()
                st["authorized"] = bool(auth)
                st["detail"] = detail
            except Exception as e:
                st["authorized"] = False
                st["detail"] = str(e)
        s = stats.get(a.key) or {}
        out.append({
            "key": a.key, "label": a.label,
            "installed": st.get("installed"),
            "authorized": st.get("authorized"),
            "detail": st.get("detail") or "",
            "conversations": s.get("conversations", 0),
            "messages": s.get("messages", 0),
            "updated_at": s.get("updated_at", ""),
        })
    return out
