@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist output\ mkdir output

if "%~1"=="" goto :manual
rem ---- 拖拽模式: 每个参数单独加引号, 支持多选 ----
set ARGS=
:build
if "%~1"=="" goto :run
set ARGS=%ARGS% "%~1"
shift
goto :build

:manual
echo ============================================
echo   应急响应日志分析工具 - 取证问答
echo ============================================
echo   用法: 将日志文件或文件夹拖到本图标上
echo   或直接在下方输入路径 (可含空格):
echo.
set /p TARGET=日志路径:
if "%TARGET%"=="" goto :eof
set ARGS="%TARGET%"

:run
echo.
echo 正在求解: %ARGS%
echo.
python\python.exe -m irlog quiz %ARGS% --json "output\quiz-result.json"
echo.
echo ============================================
echo   完整结果已导出: output\quiz-result.json
echo ============================================
pause
