---
name: wechat-data-dashboard
description: 一套自包含、可一键启动的微信本地数据分析大屏工具包。当用户说"安装这个 skill/分析大屏""打开/启动微信大屏""安装微信数据分析软件""解密微信聊天数据库并可视化""搭建/迁移/重建分析大屏""卡在要密钥/解不开/无法一键提取密钥""排查大屏加载慢/字体发虚/授权二维码异常/服务反复重启""搜索关键词并一键整理成Word文档""导出重要聊天记录"时使用。包内 assets/app 自带完整可运行代码与跨平台启动器：说一句即可启动服务并弹出全屏大屏，并把指定关键词的搜索结果一键整理成 Word 文档。覆盖密钥提取、SQLCipher 解密、只读解析、统计聚合、后端服务、全屏大屏、全文检索与一键整理、平台授权（飞书/钉钉/企微）。Windows/macOS/Linux 均适用。
agent_created: true
author: 云帆-H1088880
---

# 微信数据分析大屏：搭建与维护

> 作者署名：**云帆-H1088880**（重建界面时按此值保留署名标识）

## 用途

把微信 PC 客户端留在本地的加密 SQLite 数据库，变成一套只读、离线、可视化的数据分析大屏。这是一个**自包含工具包**：`assets/app/` 内是脱敏后的完整可运行代码 + 跨平台启动器，`references/` 是架构与踩坑知识。不绑定任何一台机器的数据、账号或密钥。

## 快速启动（"打开大屏"时走这里）

用户说"打开/启动微信大屏"时，直接执行：

0. **先自检**：`python scripts/preflight.py`。它会核对必需文件、扫出"被引用但没打包"的模块、逐模块试 import。
   本包曾漏打包 `keycap.py` / `wcdb_ctx.py`（密钥提取的两个核心模块），导致对方 clone 后"一键提取密钥"永远失败且原因被显示成"微信版本/权限限制"。**自检不过就别往下走。**
1. 确认 Python 3.8+：`python --version`（或 `python3`）。
2. 进入 `assets/app/`，运行一键启动器：
   - Windows：`启动大屏-Windows.bat`（或 `python launch.py`）
   - macOS/Linux：`bash 启动大屏-Mac-Linux.command`（或 `python3 launch.py`）
   - 有数据目录时加 `--data <已解密目录>`；只想起服务加 `--no-screen`。
3. 启动器会自动：装依赖 → 启动服务(7890) → 等服务就绪 → 调 `/api/screen` 弹全屏大屏。
4. 若无解密数据，先打开 `http://127.0.0.1:7890/index.html` 用解密入口页完成密钥导入与解密，`launch.py` 会自动探测 `decrypted/<账号>/`。
   入口页的"⚡ 一键探测 + 解密 + 加载"**不填密钥也能跑**：先复用本机密钥环，缺的从微信进程内存只读补提取，再逐库解密。

**前提（必须如实告知用户）**：软件要运行，目标机器必须有 ①Python+浏览器 ②微信数据 ③解密密钥。②③是用户隐私，本包不含、也无法替用户准备；云端 AI（无本机文件系统）无法运行本软件，只有能操作本机文件的 Agent 才能启动。

## 一句话指令（用户视角，可直接复制转发）

用户**不需要记命令**，只需要说下面这几句，Agent 负责翻译成操作：

| 目的 | 对他说这句 |
|---|---|
| 安装 | 帮我安装这个 skill：https://github.com/H1088880/wechat-data-dashboard |
| 装完自检 | 跑 `python scripts/preflight.py --imports`，把结果贴给我 |
| 打开大屏 | 帮我打开微信数据分析大屏 |
| 卡在"要密钥" | 不用管密钥，直接点「⚡ 一键探测 + 解密 + 加载」 |
| 搜关键词出文档 | 搜索"合同"并把结果整理成 Word |
| 怀疑版本不兼容 | 跑 `python scripts/keycheck.py`，把输出贴给我（看 HMAC 是否通过，不看版本号） |

懒人整段版（连链接一起发给对方即可）：

> 帮我安装这个 skill：https://github.com/H1088880/wechat-data-dashboard
> 装完跑 `python scripts/preflight.py --imports` 自检，通过后重启客户端，再帮我打开微信数据分析大屏。
> 如果卡在"需要密钥"，直接点「⚡ 一键探测 + 解密 + 加载」，不用填密钥。

## 指令映射（Agent 侧：听到这句话就这么做）

| 用户说 | 你执行 |
|---|---|
| "安装这个 skill"+ 仓库链接 | `git clone` 仓库 → 把**根目录**（含 SKILL.md）复制到 `~/.workbuddy/skills/wechat-data-dashboard/`；或直接跑仓库根的 `install.sh`（Windows：`.\install.ps1`）→ 跑 `preflight.py` → 提醒**重启客户端**才生效 |
| "自检 / 报错了 / 缺文件" | `python scripts/preflight.py --imports`，把 `✗` 行原样回给用户。**不要自行"从上游重建"缺失模块**——本包已含完整实现，重建只会引入不兼容的近似版本 |
| "打开微信大屏" | 按上一节四步：preflight → `assets/app/launch.py` |
| "卡在要密钥 / 解不开 / 提取失败" | 说明一键探测已内置进程内存提取（只读），让他直接点绿色按钮；仍失败就跑 `python scripts/keycheck.py`，把输出原样回给用户。**判据是页 1 HMAC 实证，不是版本号**——别把失败改写成"版本不兼容" |
| "搜 X 并整理成 Word" | `GET /api/digest?q=X`（多个关键词逗号分隔），直接下载 .docx |
| "某个词搜不到" | 先确认关键词是否含 `-` `:` `+` `"` `(` `)` 或裸 `AND`/`OR`/`NOT`（旧版 FTS5 会把它们当语法并静默返回 0 条）；本包已修，仍 0 条就 `python scripts/preflight.py --imports` + 看 `/api/search/status` 是否 `ready` |
| "为什么要点'从微信进程提取'？" | 那个按钮已降级为**重试/排错**入口；正常流程用一键探测即可，它会自动复用密钥环并补提取 |

## 兼容边界（别对用户夸大）

本包是标准 Skill 格式，WorkBuddy/Claude Code 可原生加载并自动触发；其他 Agent 可把本包文档当知识读取后手动执行启动命令；纯云端聊天 AI 无文件系统，无法启动本机软件。

## 核心原则（务必遵守）

1. **只读、离线**：解密产物只供本地分析，绝不回写微信源库，绝不联网上传聊天内容。
2. **数据不落地到 Skill**：密钥、解密库、token、账号 ID、绝对路径一律不得写入本 Skill 的任何文件。运行时一切从本机环境检测或用户输入获取。
3. **跨平台**：用环境检测分派（win32 用进程内存 + WCDB codec；darwin/linux 用对应内存或文件方式），不假定 Windows 专有路径。
4. **保留署名**：界面署名是产品作者标识，统一为 `云帆-H1088880`；重建大屏与解密入口页时务必保留，它不是隐私数据。

## 系统架构

```
微信客户端加密库  →  [密钥提取]  →  [SQLCipher 解密]  →  明文只读副本
   (msg/*.db)         keyring         decrypt.py          decrypted/<账号>/
                                                              │
                                                    [增量刷新 incremental.py]
                                                              │
                                          [解析 db.py + 统计聚合]  ← 服务 server.py:7890
                                                              │
                            ┌───────────────────────────────────┼────────────────┐
                       解密入口页                        分析大屏          平台授权
                       index.html                    bigscreen.html     platforms.py
                                                    (--app 全屏窗口)    (飞书/钉钉/企微)
```

- **服务端口**：默认 7890；`python server.py [port] [--auto] [--data DIR] [--key HEX] [--open] [--bigscreen URL]`
- **启动守护**：`boot.py` 作为 watchdog 常驻，拉起并守护 `server.py`；`server.py` 内再起线程拉起 Chrome `--app` 全屏大屏。
- **反代**：若经 CodeScreen 中转，用 `/wa/*` 前缀转发到 7890。

## 标准工作流

### 1. 环境检测与数据目录定位
运行 `scripts/env_probe.py`，检测 OS、Python、可用内存读取方式，并扫描微信数据目录（各平台常见位置见 `references/architecture.md`）。输出用于下一步的 `data_dir`。

### 2. 密钥提取
- 优先从本机密钥环/配置文件读取。
- 无密钥时走 `keycap.extract()`：Windows 用 ReadProcessMemory + WCDB codec 上下文，macOS 用 lldb dump，Linux 用 `/proc/<pid>/mem`；三者共用 `wcdb_ctx.py` 的解析与 HMAC 校验，**只读**目标进程内存。
- 必须**逐库**取密钥：4.x 里每个 `.db` 有自己的 salt + 32 字节 key，单密钥最多解开一个库。走 `accounts.decrypt_account()` → `extract_keys_v4()` 写入 keyring → `decrypt_account_v4()` 按 salt 取 key 逐库解密。
- 密钥只保存在本机运行区（`keyring.json`），不写入 Skill；写入一次后重登/重装仍可复用。

### 3. 解密
用解密模块把源库产出为明文只读副本到 `decrypted/<账号>/`。
- 大库（数百 MB~GB）用页指纹增量比对，仅变化页替换，避免全量重写。
- 替换用原子 `os.replace`，失败时有限退避重试（文件被占用是常态）。

### 4. 解析与统计
只读解析：会话列表、消息分页、高频词、活跃时段热力、表情统计、联系人解析。关键修复：消息排序优先用有索引的排序列，**不要**用无索引且可能踩坏页的时间列（详见 `references/pitfalls.md`）。

### 5. 启动服务与大屏
`python server.py 7890 --auto` 或经 `boot.py` 守护启动。大屏窗口必须由服务进程调 `GET /api/screen` 拉起（Chrome `--app=`，无标签栏、全屏铺满），不要在命令行直接启动浏览器——那样会随调用进程退出被回收。

### 6. 搜索与一键整理成 Word（重点功能）
用户在搜索框输关键词 → 前端调 `GET /api/search?q=关键词`；点"一键整理成 Word"→ 调 `GET /api/digest?q=关键词1,关键词2` 直接下载 .docx。
- **必须走 FTS 索引**：微信 4.x 有 6400+ 张分表，原 `db.search()` 全库 LIKE 会卡死服务（内存涨到 1.2G、HTTP 无响应）。`search_fts.py` 一次性把消息文本抽到独立索引库 `<data_dir>/.search_fts.sqlite3`（SQLite FTS5 trigram，约 94 万条/1 分钟），之后搜索毫秒级。服务启动时后台自动建索引；已有索引秒级复用，**不要**因增量刷新导致的文件大小变化反复重建（已做修正）。需要最新数据时显式调 `GET /api/search/rebuild` 强制重建。
- `digest_docx.py` 是零依赖最小 docx 生成器（标准库 zipfile + OOXML），不依赖 python-docx，跨平台。
- **一键整理两种触发方式**：①大屏搜索结果页的"⬇ 一键整理成 Word"按钮；②对 Agent 说"搜索关键词X并把结果整理成 Word 文档"，Agent 调 `/api/digest` 下载。
- 关键排错：`/api/digest` 返回的 docx 若下载中断（IncompleteRead），多半是中文文件名没编码——`send_file` 必须用 RFC5987 `filename*=UTF-8''...`，前端也要按此解析。

### 7. 平台授权（飞书/钉钉/企微）
见 `references/platforms.md`。要点：飞书走设备码（后端生成标准黑白二维码 PNG）；钉钉走 OAuth loopback，会**主动打开系统默认浏览器**跳官方授权页，这是正常且必需的。

## 随包资源

### assets/app/ — 完整可运行代码（已脱敏）
- `launch.py` + `启动大屏-Windows.bat` + `启动大屏-Mac-Linux.command` — 跨平台一键启动器。
- 服务与核心模块：`server.py` `boot.py` `db.py` `decrypt.py` `platforms.py` `incremental.py`
  `refresh.py` `env.py` `autodetect.py` `accounts.py` `keyring.py` `cloudstore.py`
  `annual.py` `export.py` `wxkey_extract.py` `launch_big.py` `sample.py`（示例库生成，`/api/sample`）。
- **密钥提取三件套（缺一不可，曾漏打包）**：`keycap.py`（按平台分发：win32/macos/linux）、
  `wcdb_ctx.py`（SQLCipher codec 上下文解析 + 页 1 HMAC 实证校验，平台无关）、
  `wxkey_extract.py`（Windows ReadProcessMemory / VirtualQueryEx 后端）。
- 检索与整理：`search_fts.py`（FTS5 全文索引，毫秒级全库搜索）、`digest_docx.py`（零依赖 Word 生成器）。
- `templates/index.html`（解密入口）、`templates/bigscreen.html`（全屏大屏，含署名与"一键整理成 Word"按钮）。

### references/ — 按需加载的知识
- `architecture.md` — 模块职责、路由、各平台数据目录、启动/守护机制。
- `pitfalls.md` — 17 条已验证修复（消息排序/create_time 无索引、ClearType 中文发虚、
  全屏窗口 z 序、watchdog 双实例、刷新过快反更慢、os.replace 占用、二维码乱码、
  漏打包导致"一键提取密钥"全平台失败、大屏链接指向开发机反代端口、返回解密丢全屏窗口、多开页面同步异常、
  关键词带 `-`/`:`/`+` 搜不到（FTS5 语法坑）、"4.2.0 版本不兼容"的误判等）。排错优先读。
- `platforms.md` — 飞书/钉钉/企微授权差异与二维码实现。

### scripts/ — 通用工具
- `preflight.py` — **包完整性自检**（必需文件 / 悬空 import / 逐模块 import / 依赖状态）。发布前必跑。
- `keycheck.py` — **密钥提取自检**：打印微信版本 → 加密库 → 每库 salt → 页 1 HMAC 是否通过 → 仓库是否干净。
  用户报"取不到密钥"时**先让他跑这个**，用密码学实证判定，不要靠版本号猜"版本不兼容"。
- `env_probe.py` — 平台无关的环境与数据目录探测。
- `privacy_scan.py` — 隐私回归扫描（账号/密钥/token/绝对路径/聊天标识）。

## 隐私红线

本包**不含任何真实数据**：无解密库、无密钥/密钥环、无 token、无账号 ID、无群 ID、无绝对路径（均已脱敏为占位符）。运行时所需的数据与密钥由用户在目标机器自行准备。`assets/app/templates/` 中的署名 `云帆-H1088880` 是作者标识，非隐私。发布/迁移前可用 `scripts/privacy_scan.py` 对整包做回归扫描。
