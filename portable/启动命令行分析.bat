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
goto :eof

:manual
echo ============================================
echo   应急响应日志分析工具 - 命令行分析
echo ============================================
echo   用法: 将日志文件或文件夹拖到本图标上
echo   或直接在下方输入路径 (可含空格):
echo.
set /p TARGET=证据路径:
if "%TARGET%"=="" goto :eof
set ARGS="%TARGET%"

:run
echo.
echo 正在分析: %ARGS%
echo.
python\python.exe -m irlog scan %ARGS% --workdir output --operator "%USERNAME%"
echo.
echo ============================================
echo   分析完成, 报告已生成在 output 目录
echo   (HTML 报告可用浏览器直接打开)
echo ============================================
pause
