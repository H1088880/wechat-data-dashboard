# -*- coding: utf-8 -*-
"""
密钥仓库：跨平台通用的「账号 → 解密密钥」记忆层。

设计要点（回答「一个账号解密一次后还需不需要再解密」）：
    · 密钥一旦拿到就永久记下来。之后该账号退出登录、重新登录、客户端重装，
      只要密钥还在，就不必再从运行中的进程里提取。
    · 密钥按「资源指纹」细分存储。不同平台的加密粒度不同：
        - 微信 4.x：每个 .db 有独立的 salt + 独立的 32 字节 raw key，
          因此以 salt 作为资源指纹，一条记录存多个 key。
        - 其它平台/单库加密：以账号级 key 存（salt=None）。
    · salt 是文件自带的、随内容而变的标识；因此同一账号在重新登录后
      产生的新库会有新 salt，仓库里新旧 key 并存，历史数据永远可读。

记录格式（keyring.json）：
{
  "accounts": {
    "wechat:<账号目录名>": {
      "platform": "wechat",
      "account":  "<账号目录名>",
      "keys": {
         "<salt_hex>": {"key": "<64hex>", "source": "process-memory", "updated_at": "..."}
      },
      "level_key": "<64hex>",          # 账号级 key（单库加密平台用）
      "updated_at": "..."
    }
  }
}

密钥来源优先级：
    1. 本仓库 keyring.json（自己记住的，最高优先级）
    2. 进程内存实时提取（仅在缺失时触发一次，成功后即写入本仓库）
    3. 第三方工具遗留的密钥文件（只读导入，作为补充）
"""
import os
import json
import glob
import re
import time

import env as _env

BASE = os.path.dirname(os.path.abspath(__file__))
# 密钥仓库默认放在用户状态目录（避免明文密钥混进项目目录 / 被误提交）
# 跨平台：Windows -> %USERPROFILE%\.wb_analyzer（WorkBuddy 池下为池目录）
#         macOS/Linux -> ~/.wb_analyzer
# 可用 WB_KEYRING_PATH / WX_KEYRING_PATH 覆盖。
KEYRING_PATH = os.environ.get("WX_KEYRING_PATH") or _env.keyring_path()

# 已知第三方工具的密钥文件位置（只读，跨平台；由 env.py 统一生成）
_THIRD_PARTY_KEY_FILES = _env.third_party_key_files()

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _norm(a):
    return str(a or "").strip().lower()


def ident_of(platform, account):
    return "%s:%s" % (platform, _norm(account))


# ---------------- 读写 ----------------
def load_all():
    """读取整个仓库（原始结构）。"""
    try:
        with open(KEYRING_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"accounts": {}}
    if not isinstance(data, dict):
        return {"accounts": {}}
    data.setdefault("accounts", {})
    # 兼容旧版扁平结构 {"keys": {"wechat:acc": {...}}}
    legacy = data.get("keys")
    if isinstance(legacy, dict):
        for k, rec in legacy.items():
            if isinstance(rec, dict) and rec.get("key"):
                ident = k
                acct = data["accounts"].setdefault(ident, {
                    "platform": rec.get("platform", "wechat"),
                    "account": rec.get("account", ident.split(":", 1)[-1]),
                    "keys": {},
                })
                acct.setdefault("level_key", rec["key"])
                acct.setdefault("keys", {})
    return data


def save_all(data):
    try:
        d = os.path.dirname(KEYRING_PATH)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = KEYRING_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, KEYRING_PATH)
        return True
    except Exception:
        return False


# ---------------- 记住 / 查询 ----------------
def remember(platform, account, key, salt=None, source="manual", hint=""):
    """
    记住一个密钥。
      salt 非空 -> 按资源指纹（每库独立 key 的平台，如微信4.x）存储
      salt 为空 -> 作为账号级 key 存储
    """
    if not account or not key:
        return False
    key = str(key).strip().lower()
    if not _HEX64.match(key):
        return False
    data = load_all()
    ident = ident_of(platform, account)
    rec = data["accounts"].setdefault(ident, {
        "platform": platform,
        "account": account,
        "keys": {},
    })
    rec["platform"] = platform
    rec["account"] = account
    rec.setdefault("keys", {})
    if salt:
        rec["keys"][str(salt).lower()] = {
            "key": key, "source": source, "hint": hint, "updated_at": _now()
        }
    else:
        rec["level_key"] = key
        rec["level_source"] = source
        rec["level_hint"] = hint
    rec["updated_at"] = _now()
    return save_all(data)


def remember_many(platform, account, salt_key_map, source="manual", hint=""):
    """批量记住：{salt_hex: key_hex}"""
    data = load_all()
    ident = ident_of(platform, account)
    rec = data["accounts"].setdefault(ident, {
        "platform": platform, "account": account, "keys": {},
    })
    rec.setdefault("keys", {})
    n = 0
    for salt, key in (salt_key_map or {}).items():
        key = str(key).strip().lower()
        if not _HEX64.match(key):
            continue
        rec["keys"][str(salt).lower()] = {
            "key": key, "source": source, "hint": hint, "updated_at": _now()
        }
        n += 1
    rec["updated_at"] = _now()
    save_all(data)
    return n


def lookup(platform, account, salt=None):
    """查密钥，返回 (key_hex, source)；查不到返回 (None, None)。"""
    data = load_all()
    rec = data["accounts"].get(ident_of(platform, account))
    if rec:
        if salt:
            item = (rec.get("keys") or {}).get(str(salt).lower())
            if item and item.get("key"):
                return item["key"], item.get("source", "keyring")
        if rec.get("level_key"):
            return rec["level_key"], rec.get("level_source", "keyring")
    # 第三方文件
    for p in _THIRD_PARTY_KEY_FILES:
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data2 = json.load(f)
        except Exception:
            continue
        if not isinstance(data2, dict):
            continue
        for acct, r in data2.items():
            if not isinstance(r, dict):
                continue
            k = r.get("db_key") or r.get("key") or r.get("dbKey")
            if not k:
                continue
            if _norm(acct) == _norm(account) or (
                    _norm(acct) and (_norm(account).startswith(_norm(acct))
                                     or _norm(acct).startswith(_norm(account)))):
                return str(k).strip().lower(), os.path.basename(p)
    return None, None


def keys_for(platform, account):
    """返回该账号已记住的全部 {salt: key}"""
    data = load_all()
    rec = data["accounts"].get(ident_of(platform, account))
    if not rec:
        return {}
    out = {s: v.get("key") for s, v in (rec.get("keys") or {}).items() if v.get("key")}
    if rec.get("level_key"):
        out.setdefault("", rec["level_key"])
    return out


def accounts():
    """列出仓库中所有账号及状态。"""
    data = load_all()
    out = []
    for ident, rec in (data.get("accounts") or {}).items():
        out.append({
            "ident": ident,
            "platform": rec.get("platform", "?"),
            "account": rec.get("account", ident),
            "keys": len(rec.get("keys") or {}),
            "level_key": bool(rec.get("level_key")),
            "updated_at": rec.get("updated_at", ""),
        })
    return out


def forget(platform, account):
    data = load_all()
    ident = ident_of(platform, account)
    if ident in data["accounts"]:
        del data["accounts"][ident]
        save_all(data)
        return True
    return False


# ---------------- 第三方密钥文件导入（只读补充） ----------------
def _third_party_files(platform="wechat"):
    """返回存在的第三方密钥文件路径列表（跨平台，由 env.py 提供候选）。"""
    files = list(_THIRD_PARTY_KEY_FILES)
    out, seen = [], set()
    for f in files:
        rp = os.path.normpath(f)
        if rp in seen or not os.path.exists(rp):
            continue
        seen.add(rp)
        out.append(rp)
    return out


def import_third_party(platform="wechat"):
    """
    从第三方工具遗留的密钥文件导入密钥（只读源文件）。
    返回导入条数。
    """
    data = load_all()
    n = 0
    for path in _third_party_files(platform):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        for acct, r in raw.items():
            if not isinstance(r, dict):
                continue
            ident = ident_of(platform, acct)
            rec = data["accounts"].setdefault(ident, {
                "platform": platform, "account": acct, "keys": {},
            })
            rec.setdefault("keys", {})
            k = r.get("db_key") or r.get("key") or r.get("dbKey")
            if k and _HEX64.match(str(k).strip()):
                rec.setdefault("level_key", str(k).strip().lower())
                rec.setdefault("level_source", os.path.basename(path))
                n += 1
            for salt, kk in (r.get("keys") or {}).items():
                if isinstance(kk, dict):
                    kk = kk.get("key")
                if kk and _HEX64.match(str(kk).strip()):
                    rec["keys"][str(salt).lower()] = {
                        "key": str(kk).strip().lower(),
                        "source": os.path.basename(path),
                        "hint": "", "updated_at": _now(),
                    }
                    n += 1
            rec["updated_at"] = _now()
    save_all(data)
    return n
