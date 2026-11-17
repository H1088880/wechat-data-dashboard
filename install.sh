#!/usr/bin/env bash
# 微信数据分析大屏 · WorkBuddy Skill 一键安装（macOS / Linux）
# 在 git clone 后的仓库根目录运行：bash install.sh
set -e

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.workbuddy/skills/wechat-data-dashboard"

if [ ! -f "$SRC/SKILL.md" ]; then
  echo "错误：当前目录没有 SKILL.md，请在 Skill 仓库根目录运行本脚本。" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
if [ -e "$DEST" ]; then
  BAK="$DEST.bak.$(date +%Y%m%d%H%M%S)"
  mv "$DEST" "$BAK"
  echo "已备份旧版本：$BAK"
fi
cp -R "$SRC" "$DEST"
echo "已安装到：$DEST"
echo "重启 WorkBuddy 后，说一句：帮我打开微信数据分析大屏"
