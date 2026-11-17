#!/usr/bin/env python3
"""对任意目录做隐私回归扫描：检测账号ID、绝对路径、密钥/token、聊天标识。

用法: python privacy_scan.py <目录> [更多目录...]
退出码 0=干净，1=发现疑似隐私（并逐条打印位置）。
只读扫描，不修改文件。

豁免：在命中行前 3 行内（含当行）写 `privacy-ok: 原因` 注释即可跳过。
只用于"确实不是隐私的公开常量"（如 WCDB 的 codec 结构前缀）；
真实的密钥/账号**不要**加豁免，改了它别处也会用到。
"""
import os
import re
import sys

TEXT_EXT = {".py", ".html", ".htm", ".md", ".json", ".txt", ".js",
            ".css", ".bat", ".sh", ".yaml", ".yml", ".toml", ".ini"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", "decrypted", "_auth",
             "memdump", "memclue", "_backup", "dist"}

# 疑似隐私的正则（通用特征，不绑定具体账号）
PATTERNS = {
    "Windows用户绝对路径": re.compile(r"[A-Za-z]:\\Users\\", re.I),
    "磁盘绝对路径": re.compile(r"[A-Za-z]:[\\/](?:Program Files|Users|[A-Za-z]*[Aa]nalyzer|Work[Bb]uddy)", re.I),
    "xwechat账号目录": re.compile(r"xwechat_files[\\/][A-Za-z0-9_]{6,}_[A-Za-z0-9]{4,}"),
    "wxid账号": re.compile(r"wxid_[a-z0-9]{8,}"),
    "群ID": re.compile(r"[0-9]{9,}@chatroom"),
    "QQ号串": re.compile(r"(?<!\d)qq\d{6,}(?!\d)", re.I),
    "密钥十六进制长串": re.compile(r"\b[0-9a-fA-F]{64,}\b"),
    "token赋值": re.compile(r"(token|access_key|secret|password)\s*[:=]\s*[\"'][^\"'\s]{12,}", re.I),
}


def scan_file(path):
    hits = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return hits
    for ln, line in enumerate(lines, 1):
        # 豁免窗口：命中行前 3 行到当行内出现 privacy-ok 就不报告
        window = "".join(lines[max(0, ln - 4):ln])
        waived = "privacy-ok" in window
        for name, pat in PATTERNS.items():
            if pat.search(line):
                if waived:
                    continue
                snippet = line.strip()[:100]
                hits.append((name, ln, snippet))
    return hits


def main(dirs):
    total = 0
    for root in dirs:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                    continue
                fp = os.path.join(dp, fn)
                hits = scan_file(fp)
                for name, ln, snippet in hits:
                    total += 1
                    print(f"[疑似隐私] {name}\n  {fp}:{ln}\n    {snippet}")
    if total:
        print(f"\n发现 {total} 处疑似隐私，请人工确认并清理后再上传。")
        return 1
    print("扫描完成：未发现疑似隐私信息。")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("用法: python privacy_scan.py <目录> [更多目录...]")
        raise SystemExit(2)
    raise SystemExit(main(args))
