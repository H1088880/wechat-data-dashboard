#!/bin/bash
cd "$(dirname "$0")"
echo "正在启动 微信数据分析大屏..."
python3 launch.py "$@"
if [ $? -ne 0 ]; then
  echo ""
  echo "启动失败，检查 Python3 是否已安装。"
  read -p "按回车键退出..."
fi
