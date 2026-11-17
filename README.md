# 微信数据分析大屏 · 自包含工具包

作者署名：**云帆-H1088880**

一套只读、离线、跨平台的微信本地数据分析工具：从加密数据库解密，到可视化分析大屏。

## 一分钟启动

前置：Python 3.8+（需联网装一次 `pycryptodome`）、Chrome/Edge/Chromium、以及**你自己的**微信数据和解密密钥。

- **Windows**：双击 `assets/app/启动大屏-Windows.bat`
- **macOS / Linux**：在 `assets/app/` 运行 `bash 启动大屏-Mac-Linux.command`

也可手动：`cd assets/app && python launch.py`（macOS/Linux 用 `python3`）。

启动器会自动装依赖 → 起服务(7890) → 等服务就绪 → 弹全屏大屏。
打开 `http://127.0.0.1:7890/index.html` 可导入密钥、完成解密。

## 给 AI 使用

对能操作本机文件的 Agent（WorkBuddy / Claude Code / Cursor 等）说：

> 帮我安装并打开这个微信数据分析大屏

它应读取 `SKILL.md` → 检查 Python → 运行 `assets/app/launch.py` → 拉起大屏。

纯云端聊天 AI（无本机文件系统）无法运行本机软件，只能把本包当文档参考。

## 通过 Git 仓库安装（推荐，最接近"发链接即装"）

把本目录作为一个 Git 仓库 push 到你自己的库（GitHub / Gitee / CNB / GitLab 均可）。**仓库根目录就是 Skill 根目录**（含 `SKILL.md`），这样 Agent 看到链接就能直接识别。之后把仓库链接发给对方，让他对能操作本机文件的 Agent 说：

> 帮我安装这个 skill：<你的仓库链接>
> 请 clone 仓库，把根目录（含 SKILL.md）复制到 `~/.workbuddy/skills/wechat-data-dashboard/`，完成后告诉我怎么触发。

这是目前最标准、最省事的分发方式：WorkBuddy / Claude Code 等能操作本机文件的 Agent 原生理解"给仓库链接 → 安装 Skill"。对方不用 Agent 也可以手动一键装：

- macOS / Linux：`git clone <仓库链接> && bash <仓库目录>/install.sh`
- Windows：`git clone <仓库链接>` 后用 PowerShell 运行 `.\install.ps1`

一键脚本会把 Skill 装到 `~/.workbuddy/skills/wechat-data-dashboard/`，重启客户端即可生效。

**仍要如实说明的边界**：Git 链接把"安装 Skill 包"标准化了，但"打开软件"需要对方本机有 ①Python + 浏览器 ②微信数据 ③解密密钥。这些属于隐私，仓库里没有、也无法替对方准备。纯云端聊天 AI（无本机文件系统）即使拿到链接也打不开本机软件——这是物理边界，不是打包方式能绕过的。

## 从资料库/分享链接安装（重要边界）

**资料库链接本身不会自动安装技能**。它只是文件的查看/下载入口，不是技能安装器。收到链接的一方，需要让一个**能读写本机文件的 Agent** 做这几步：

1. 下载 `wechat-data-dashboard.zip` 并解压；
2. 把解压出的 `wechat-data-dashboard/` 文件夹放到本机技能目录：
   - WorkBuddy 用户级：`~/.workbuddy/skills/wechat-data-dashboard/`
   - WorkBuddy 项目级：`<项目目录>/.workbuddy/skills/wechat-data-dashboard/`
   - 其他 Agent：放到它自己识别的 skills 目录；
3. 确认该目录根部有 `SKILL.md`；
4. 对这个 Agent 说"帮我安装并打开微信数据分析大屏"，它会读取 `SKILL.md` → 检查 Python → 运行 `assets/app/launch.py` 拉起大屏。

可以把上面 4 步连同链接一起发给对方，让对方的 Agent 照做——这是目前最接近"给链接就能用"的方式。纯云端聊天 AI（不能访问你的电脑）即使拿到链接也打不开本机软件。

## 目录

```
SKILL.md                 技能入口 / 触发词 / 启动流程
README.md                本文件
assets/app/              完整可运行代码（已脱敏）
  launch.py              一键启动器（跨平台）
  启动大屏-Windows.bat      Windows 双击入口
  启动大屏-Mac-Linux.command Mac/Linux 入口
  server.py 等            服务与核心模块
  templates/              解密入口页 + 全屏大屏页
references/              架构 / 踩坑 / 平台授权
scripts/                 环境探测 / 隐私扫描
```

## 隐私声明

本包不含任何真实数据：无解密库、无密钥、无 token、无账号、无群 ID、无绝对路径。
运行时所需的数据与密钥由使用者在本机自行准备。发布前可运行 `scripts/privacy_scan.py <目录>` 复检。
