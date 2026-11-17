@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动 微信数据分析大屏...
python launch.py %*
if errorlevel 1 (
  echo.
  echo 启动失败，检查 Python 是否已安装并加入 PATH。
  pause
)
