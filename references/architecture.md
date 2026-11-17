# 架构参考（平台无关）

## 模块职责

| 模块 | 职责 |
|---|---|
| `env.py` | 平台检测（`sys.platform` → win32/darwin/linux）、微信数据目录扫描、内存读取方式分派、路径工具 |
| `autodetect.py` | 自动探测账号、数据目录、可用解密路径 |
| `wxkey_extract.py` / `keyring.py` | 从进程内存/密钥环提取并管理 SQLCipher 密钥 |
| `decrypt.py` | SQLCipher 4 解密核心：页加解密、HMAC 校验、缺页重建、密钥验证、进程内存密钥扫描、自动解密入口 |
| `incremental.py` / `refresh.py` | 增量刷新：页指纹比对，仅替换变化库文件；守护线程定时增量解密源库 |
| `db.py` | 明文库只读解析：会话/消息/联系人/统计/搜索/表情/热力；连接代理与文件闸门 |
| `accounts.py` | 多账号管理（数据目录、密钥的注册与切换） |
| `platforms.py` | 钉钉/飞书/企微 授权与数据拉取（登录、二维码、会话、消息、同步、统计） |
| `annual.py` / `export.py` / `cloudstore.py` | 年度总结、导出、可选云存储 |
| `server.py` | HTTP 服务（默认 7890，ThreadingHTTPServer）+ 全部 API 路由 + 统计缓存 + 自动刷新 |
| `boot.py` | watchdog 守护：单例锁、清理残留实例、拉起并守护 server.py |
| `launch_big.py` | Chrome `--app` 全屏大屏窗口拉起 |
| `templates/index.html` | 解密入口（工具页） |
| `templates/bigscreen.html` | 数据分析大屏（深色主题、全屏） |

## 目录约定

```
<project>/
  decrypted/<账号>/       明文只读副本（运行时生成，禁止入库）
  templates/              两个 HTML 页面
  config.json             本机配置（含路径/账号，禁止入库原样）
  <账号>/ 相关密钥文件     禁止入库
```

## 各平台微信数据目录（探测依据）

- **Windows 3.x**：`<用户目录>\Documents\WeChat Files\<账号>\Msg`
- **Windows 4.x**：`<系统盘>\Program Files\Tencent\xwechat_files\<账号>\db_storage\message`（源码会扫多个盘符）
- **macOS**：`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files`、`~/Documents/xwechat_files`、Group Containers 下同名目录
- **Linux**：`~/.config/xwechat_files`、`~/.local/share/xwechat_files`、`~/Documents/xwechat_files`

探测逻辑：`env.py` 的 `_win_roots()` / `_mac_roots()` / `_linux_roots()`，按平台返回候选根，再找 `db_storage`/`Msg` 下的 `*.db`。

## 关键 API 路由（server.py）

```
解密/配置： /api/detect  /api/detect  /api/setdir  /api/config  /api/keys/import
            /api/account/decrypt  /api/account/ensure-keys  /api/account/use  /api/accounts
            /api/decrypt  /api/decrypt-progress  /api/key-extract  /api/load  /api/status
分析展示： /api/dash  /api/stats/rebuild  /api/conversations  /api/messages  /api/search
            /api/analyze  /api/annual  /api/export  /api/favorites  /api/moments  /api/sample
            /api/snapshot  /api/refresh  /api/refresh/status  /api/auto
界面/控制： /api/screen（拉起全屏大屏）
平台授权： /api/platforms  /api/platform/login  /api/platform/qr
            /api/platform/stats  /api/platform/recent  /api/platform/conversations
            /api/platform/messages  /api/platform/sync
```

## 启动与守护机制

1. `boot.py` 先拿**单例锁**（同一机器只允许一个 watchdog）。否则 Windows 上 `SO_REUSEADDR` 允许两个实例同时绑 7890，会造成"双 server.py + 双增量刷新"的静默冲突与无限重启风暴。
2. 按命令行全量清理残留 `server.py` 实例。
3. 用 `subprocess.Popen([PY, '-u', 'server.py', '7890'])` 拉起服务。
4. watchdog 循环守护：`p.wait()` 异常绝不能退出 watchdog；非正常退出码（非 3/4）自动重启，带退避与端口等待。
5. 大屏 Chrome 进程挂在项目进程链上（计划任务/脚本），否则调用进程退出会回收窗口。

## 依赖

Python 3 + `pycryptodome`（`Crypto.Cipher.AES`）。其余为标准库（`http.server`、`sqlite3`、`threading`、`subprocess` 等）。图形界面需本机有 Chrome/Edge。
