# -*- coding: utf-8 -*-
"""
账号管理：多微信账号的发现、密钥状态、解密产物与加载。

核心承诺（回答「一个账号解密一次后还需不需要再解密」）：
    · 密钥一旦提取即永久记入 keyring。账号退出登录、重新登录、客户端重装，
      密钥依然在 → **不需要再解密一次**。
    · salt 是文件自带的随机量；同一账号重登后新产生的库会有新 salt，
      仓库里新旧 key 并存，因此历史数据永远可读，新数据只需补一个新 key。
    · 若某库缺密钥且微信正在运行，可随时从进程内存补提取（一次几秒）。

多账号隔离：每个账号的解密产物独立存放在 decrypted/<account>/ 下，
切换账号 = 切换当前加载的目录，绝不混读。
"""
import os

import autodetect as admod
import decrypt as decmod
import keyring
import env as _env

BASE = os.path.dirname(os.path.abspath(__file__))
# 解密产物目录统一由 env 决定（代码目录只读时自动回落 ~/.wb_analyzer/decrypted）
DECRYPTED_DIR = _env.decrypted_dir()

# 非账号目录（微信自建的公共/组件目录）
_SKIP_ACCOUNTS = {"old_backup", "wmpf", "all users", "all_users",
                   "applet", "favtemp", "mmkv", "backup"}


def decrypted_dir(account):
    """某账号的解密产物目录"""
    return os.path.join(DECRYPTED_DIR, account)


def _account_nick_candidates(account):
    """账号目录名是 <wxid>_<随机后缀>，而联系人表里存的是**去掉后缀**的 wxid。

    微信的数据目录形如 `wxid_<随机串>_<后缀>` / `<账号>_<后缀>`，
    真正的微信号是去掉目录名后缀后的那一段。
    所以按「整串 → 剥一段 → 再剥一段」依次去联系人表里找。
    """
    cands = [account]
    a = account
    for _ in range(2):
        if "_" not in a:
            break
        a = a.rsplit("_", 1)[0]
        if a:
            cands.append(a)
    return cands


def _nick_from_contact_dirs(dirs, account):
    """在给定的解密目录（含 contact.db）里查账号昵称。"""
    import db as _dbmod
    for d in dirs:
        if not d:
            continue
        p = os.path.join(d, "contact.db")
        if not os.path.isfile(p):
            continue
        try:
            idx = _dbmod._build_contact_index(p)
        except Exception:
            continue
        if not idx:
            continue
        for c in _account_nick_candidates(account):
            nm = (idx.get(c) or "").strip()
            if nm:
                return nm
    return ""


def account_nick(account, pdir="", extra_dirs=()):
    """账号显示昵称。查不到返回空串（前端会退到短微信号）。

    已解密账号查自己的联系人表；未解密账号则借当前已解密账号的表试一次
    （多开账号互为好友时能命中）。
    """
    return _nick_from_contact_dirs([pdir] + list(extra_dirs), account)


def list_accounts():
    """
    返回本机所有微信账号及其状态。
    每个条目：
      account       账号标识（目录名）
      msg_dir       加密源库目录
      db_count      源库数量
      has_message   是否含消息库（真正的账号 vs 组件目录）
      encrypted     源库是否加密
      key_count     keyring 里已记住的该账号密钥条数
      key_known     是否已具备解密所需密钥（全部库都有）
      decrypted     明文产物目录是否就绪
      decrypted_dir 明文产物目录
      status        human readable 状态
    """
    out = []
    seen = set()
    for a in admod.scan_encrypted_accounts():
        acct = (a.get("account") or "").strip()
        if not acct or acct.lower() in _SKIP_ACCOUNTS or acct in seen:
            continue
        seen.add(acct)
        msg_dir = a.get("msg_dir") or ""
        dbs = decmod.recursive_find_dbs(msg_dir) if msg_dir else []
        enc_dbs = [d for d in dbs if decmod.is_encrypted_db(d)]
        keys = keyring.keys_for("wechat", acct)
        # 已知密钥数 vs 需要密钥的库数
        need = 0
        have = 0
        for d in enc_dbs:
            salt = decmod.db_salt(d)
            if salt is None:
                continue
            need += 1
            if salt.hex() in keys:
                have += 1
        pdir = decrypted_dir(acct)
        is_dec = os.path.isdir(pdir) and bool(os.listdir(pdir))
        if not a.get("has_message"):
            status = "非账号目录（微信组件）"
        elif is_dec and have >= need and need > 0:
            status = "已解密 · 无需再解密"
        elif is_dec:
            status = "部分解密 · 可增量补齐"
        elif have >= need and need > 0:
            status = "密钥已记住 · 待解密"
        elif have > 0:
            status = "密钥不完整 · 需补提取"
        else:
            status = "需从微信进程提取密钥"
        out.append({
            "platform": "wechat",
            "account": acct,
            "msg_dir": msg_dir,
            "db_count": len(dbs),
            "encrypted_db_count": len(enc_dbs),
            "has_message": bool(a.get("has_message")),
            "key_count": have,
            "key_needed": need,
            "key_known": bool(need) and have >= need,
            "decrypted": is_dec,
            "decrypted_dir": pdir,
            "status": status,
        })
    # 账号昵称：已解密账号查自己的联系人表；
    # 未解密账号借所有已解密目录试一次（多开账号互为好友时能命中）。
    # 查不到就留空，前端退到「短微信号」显示。
    dec_dirs = [r["decrypted_dir"] for r in out if r["decrypted"]]
    for r in out:
        try:
            r["nick"] = account_nick(r["account"], r["decrypted_dir"], dec_dirs)
        except Exception:
            r["nick"] = ""
    # 有消息库的账号排前面
    out.sort(key=lambda x: (not x["has_message"], -x["db_count"]))
    return out


def ensure_keys(account, progress=None):
    """
    确保该账号的密钥已记入 keyring。
    已在仓库里的直接复用；缺的才从运行中的微信进程补提取。
    返回 {ok, added, total, need, error}
    """
    rows = [r for r in list_accounts() if r["account"] == account]
    if not rows:
        return {"ok": False, "error": "未找到该账号", "added": 0, "total": 0, "need": 0}
    row = rows[0]
    if not row["msg_dir"]:
        return {"ok": False, "error": "该账号无数据库目录", "added": 0,
                "total": row["key_count"], "need": row["key_needed"]}
    if row["key_known"]:
        return {"ok": True, "added": 0, "total": row["key_count"],
                "need": row["key_needed"], "note": "密钥已记住，无需再解密"}
    res = decmod.extract_keys_v4(row["msg_dir"], platform="wechat",
                                 account=account, progress=progress)
    return {"ok": bool(res.get("ok")), "added": res.get("count", 0),
            "total": row["key_count"] + res.get("count", 0),
            "need": row["key_needed"],
            "error": res.get("error")}


def decrypt_account(account, progress=None):
    """
    解密某账号的全部加密库到 decrypted/<account>/。
    密钥来源：keyring（已记住的）→ 缺失则自动从进程补提取。
    返回 {ok, out_dir, ok_count, missing, error}
    """
    rows = [r for r in list_accounts() if r["account"] == account]
    if not rows:
        return {"ok": False, "error": "未找到该账号", "ok_count": 0}
    row = rows[0]
    if not row["msg_dir"]:
        return {"ok": False, "error": "该账号无数据库目录", "ok_count": 0}
    # 缺密钥则先补提取
    if not row["key_known"]:
        ek = ensure_keys(account, progress=progress)
        if not ek.get("ok") and not ek.get("added"):
            return {"ok": False, "error": ek.get("error") or "密钥缺失", "ok_count": 0}
    out_dir = decrypted_dir(account)
    res = decmod.decrypt_account_v4(row["msg_dir"], out_dir,
                                    platform="wechat", account=account,
                                    progress=progress)
    return {
        "ok": bool(res.get("ok")),
        "out_dir": out_dir,
        "ok_count": sum(1 for r in res.get("results", []) if r.get("ok")),
        "cached": res.get("cached", 0),
        "db_count": res.get("db_count", 0),
        "missing": res.get("missing", []),
        "error": None if res.get("ok") else "解密失败",
    }
