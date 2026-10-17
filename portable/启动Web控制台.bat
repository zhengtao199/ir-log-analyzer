@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist evidence\ mkdir evidence
if not exist output\ mkdir output
echo ============================================
echo   应急响应日志分析工具 - Web 控制台
echo ============================================
echo   正在启动服务...
start "" http://127.0.0.1:8611
echo   浏览器应自动打开；若未打开请手动访问:
echo   http://127.0.0.1:8611
echo.
echo   关闭本窗口即停止服务。
echo ============================================
python\python.exe -m irlog serve --evidence-dir evidence --workdir output
pause
