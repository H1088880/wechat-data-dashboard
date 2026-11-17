# -*- coding: utf-8 -*-
"""包完整性自检（发布前 / 安装后都跑一遍）。

回答一个问题：**这个 clone 下来的包，能不能真的跑起来？**

只查三件事，全是"缺了就会在用户那边炸"的：
  1. 清单：该在的文件在不在（模块、模板、启动器、文档）。
  2. 引用：包内 `import xxx` 的每一个本地模块，文件是否存在（防"漏打包"）。
  3. 导入：每个模块单独起子进程 import 一次（防循环引用、语法错、拼错符号）。

第三方库只报告不判失败 —— 缺了降级或有替代路径的（jieba / Pillow / qrcode）不影响主流程，
真正必须的（pycryptodome）单独标红。

用法：
    python scripts/preflight.py            # 只检查
    python scripts/preflight.py --imports  # 额外做逐模块 import（慢约 5s）

退出码：0 全通过；1 有致命问题（缺文件 / 缺模块 / 导入失败）。
"""
import argparse
import ast
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "assets", "app")

# 必须是这个包的骨架，任何一个不见都说明打包不完整
REQUIRED_FILES = [
    "SKILL.md",
    "README.md",
    "install.sh",
    "install.ps1",
    os.path.join("assets", "app", "launch.py"),
    os.path.join("assets", "app", "server.py"),
    os.path.join("assets", "app", "boot.py"),
    os.path.join("assets", "app", "db.py"),
    os.path.join("assets", "app", "decrypt.py"),
    os.path.join("assets", "app", "env.py"),
    os.path.join("assets", "app", "keyring.py"),
    # ↓↓↓ 这几个最容易在打包时被漏掉，但少了就直接跑不起来 ↓↓↓
    os.path.join("assets", "app", "keycap.py"),        # 跨平台密钥捕获入口
    os.path.join("assets", "app", "wcdb_ctx.py"),      # SQLCipher codec 上下文解析
    os.path.join("assets", "app", "wxkey_extract.py"),  # Windows ReadProcessMemory 后端
    os.path.join("assets", "app", "sample.py"),         # 示例库生成（/api/sample）
    os.path.join("assets", "app", "search_fts.py"),
    os.path.join("assets", "app", "digest_docx.py"),
    os.path.join("assets", "app", "templates", "index.html"),
    os.path.join("assets", "app", "templates", "bigscreen.html"),
    os.path.join("references", "architecture.md"),
    os.path.join("references", "pitfalls.md"),
    os.path.join("scripts", "env_probe.py"),
]

# 第三方依赖：(import 名, pip 名, 必须?, 缺失影响)
THIRD_PARTY = [
    ("Crypto", "pycryptodome", True, "SQLCipher 解密，缺了完全无法解密"),
    ("zstandard", "zstandard", False, "微信 4.x 部分消息体是 zstd 压缩，缺了这类消息读不出内容"),
    ("jieba", "jieba", False, "中文分词退化为 bigram，词频里会出现「碗碗」「吃碗」这类碎片"),
    ("qrcode", "qrcode", False, "飞书设备码二维码改用纯文字链接"),
    ("PIL", "Pillow", False, "部分图片类导出不可用"),
    ("openpyxl", "openpyxl", False, "Excel 导出不可用（Word 整理不受影响）"),
]

# 这些名字出现在 import 里但解析不到时，按"依赖缺失"报，不算"漏打包"
DEP_NAMES = {x[0] for x in THIRD_PARTY}

def iter_app_modules():
    """返回 (模块名, 路径) —— assets/app 下所有顶层 .py。"""
    out = []
    if not os.path.isdir(APP):
        return out
    for fn in sorted(os.listdir(APP)):
        if fn.endswith(".py"):
            out.append((fn[:-3], os.path.join(APP, fn)))
    return out


def scan_local_imports(modules):
    """扫包内所有 .py 的 import，找出「引用了、但既没文件也 import 不到」的模块。

    判定不靠"记住标准库有哪些"（记不全就会误报），而是问解释器：
    这个 import 名到底能不能解析出来？解析不到，才是真的缺。
    """
    names = {m for m, _ in modules}
    if APP not in sys.path:
        sys.path.insert(0, APP)

    def resolvable(name):
        try:
            return importlib.util.find_spec(name) is not None
        except (ImportError, ValueError, AttributeError):
            return False

    missing = {}
    for mod, path in modules:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                tree = ast.parse(fp.read())
        except (SyntaxError, OSError) as e:
            missing.setdefault("__parse_error__", []).append(f"{mod}: {e}")
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    targets = [node.module.split(".")[0]]
            for t in targets:
                if t in names or t in DEP_NAMES or resolvable(t):
                    continue
                missing.setdefault(t, []).append(mod)
    return missing


def try_import(mod):
    code = "import %s" % mod
    try:
        p = subprocess.run([sys.executable, "-c", code], cwd=APP,
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "导入超时（60s）"
    if p.returncode == 0:
        return True, ""
    tail = (p.stderr or "").strip().splitlines()
    return False, tail[-1] if tail else "退出码 %d" % p.returncode


def check_deps():
    """第三方依赖：必须的判失败，可选的只提示。"""
    rows = []
    for imp_name, pip_name, required, impact in THIRD_PARTY:
        p = subprocess.run([sys.executable, "-c", "import " + imp_name],
                           capture_output=True, text=True, timeout=60)
        rows.append((imp_name, pip_name, required, p.returncode == 0, impact))
    return rows


def main():
    ap = argparse.ArgumentParser(description="包完整性自检")
    ap.add_argument("--imports", action="store_true",
                    help="逐模块 import 验证（更慢，但能抓到符号错误）")
    args = ap.parse_args()

    fatal = 0
    print("包根目录：%s" % ROOT)
    print()

    # 1) 清单
    print("[1/4] 必需文件")
    for rel in REQUIRED_FILES:
        ok = os.path.exists(os.path.join(ROOT, rel))
        print("  %s %s" % ("✓" if ok else "✗", rel))
        if not ok:
            fatal += 1
    print()

    # 2) 模块清单
    modules = iter_app_modules()
    print("[2/4] 模块清单：assets/app 下共 %d 个 .py" % len(modules))
    names = sorted(m for m, _ in modules)
    print("  " + ", ".join(names))
    print()

    # 3) 引用完整性
    print("[3/4] 引用完整性（包内 import 是否都能找到文件）")
    missing = scan_local_imports(modules)
    if not missing:
        print("  ✓ 没有悬空引用")
    else:
        for name, users in sorted(missing.items()):
            if name == "__parse_error__":
                for u in users:
                    print("  ✗ 语法错误 %s" % u)
                fatal += 1
                continue
            print("  ✗ 缺模块 %-14s 被 %s 引用" % (name, ", ".join(sorted(set(users)))))
            fatal += 1
    print()

    # 4) 导入（可选）
    print("[4/4] 逐模块导入%s" % ("" if args.imports else "（--imports 可开启）"))
    if args.imports:
        for mod, _ in modules:
            ok, err = try_import(mod)
            print("  %s %-16s %s" % ("✓" if ok else "✗", mod, "" if ok else err))
            if not ok:
                fatal += 1
    else:
        print("  跳过")
    print()

    # 依赖（只报告）
    print("第三方依赖：")
    for imp_name, pip_name, required, ok, impact in check_deps():
        tag = "必须" if required else "可选"
        mark = "✓" if ok else ("✗" if required else "○")
        print("  %s %-12s %-14s %s" % (mark, imp_name, "(%s)" % tag,
                                       "已安装" if ok else "未安装 —— " + impact))
        if required and not ok:
            fatal += 1
    print()

    if fatal:
        print("结论：✗ 发现 %d 处致命问题，先修好再发布/安装。" % fatal)
        print("      最常见原因：打包时只 copy 了部分 .py（keycap.py / wcdb_ctx.py 曾这样丢过）。")
        return 1
    print("结论：✓ 包是完整的，可以运行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
