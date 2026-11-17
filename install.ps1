# 微信数据分析大屏 · WorkBuddy Skill 一键安装（Windows）
# 在 git clone 后的仓库根目录，用 PowerShell 运行：.\install.ps1
$ErrorActionPreference = "Stop"

$Src = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = Join-Path $env:USERPROFILE ".workbuddy\skills\wechat-data-dashboard"

if (-not (Test-Path (Join-Path $Src "SKILL.md"))) {
  Write-Error "错误：当前目录没有 SKILL.md，请在 Skill 仓库根目录运行本脚本。"
  exit 1
}

$Parent = Split-Path -Parent $Dest
New-Item -ItemType Directory -Force -Path $Parent | Out-Null
if (Test-Path $Dest) {
  $Bak = "$Dest.bak." + (Get-Date -Format "yyyyMMddHHmmss")
  Move-Item -Path $Dest -Destination $Bak
  Write-Host "已备份旧版本：$Bak"
}
Copy-Item -Recurse -Force -Path $Src -Destination $Dest
Write-Host "已安装到：$Dest"
Write-Host "重启 WorkBuddy 后，说一句：帮我打开微信数据分析大屏"
