@echo off
rem ============================================================================
rem  LocalBoost 发布脚本（自包含单文件，目标机器不需要装 .NET 运行时）
rem
rem  用法：
rem    publish.cmd                  发布 win-x64，结束时暂停
rem    publish.cmd win-arm64        发布 ARM64 版
rem    publish.cmd win-x64 --no-pause   不暂停（给 CI / 其它脚本调用）
rem
rem  用 PowerShell 的话见同目录的 build.ps1。
rem ============================================================================
chcp 65001 >nul
setlocal

cd /d "%~dp0"

set "RID=win-x64"
set "NOPAUSE="

if /i "%~1"=="win-arm64"   set "RID=win-arm64"
if /i "%~1"=="win-x64"     set "RID=win-x64"
if /i "%~1"=="--no-pause"  set "NOPAUSE=1"
if /i "%~2"=="--no-pause"  set "NOPAUSE=1"

rem 版本号向 MSBuild 要，不去文本解析 props 文件 —— 后者一旦格式变了就会静默取错
set "VERSION="
for /f "usebackq tokens=*" %%v in (`dotnet msbuild LocalBoost.csproj -getProperty:Version -nologo`) do set "VERSION=%%v"
if "%VERSION%"=="" set "VERSION=unknown"

echo ============================================
echo  LocalBoost 发布
echo  版本 %VERSION%    运行时 %RID%
echo  自包含单文件，目标机器不需要装 .NET
echo ============================================
echo.

dotnet publish LocalBoost.csproj ^
  -c Release ^
  -r %RID% ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -o publish

if errorlevel 1 (
  echo.
  echo [失败] 发布未完成，请检查上面的错误信息。
  echo        常见原因：publish\LocalBoost.exe 正在运行，文件被占用。
  if defined NOPAUSE exit /b 1
  pause
  exit /b 1
)

echo.
echo ============================================
echo  完成
echo  产物：%~dp0publish\LocalBoost.exe
echo.
echo  发版时建议把产物重命名成带版本号的名字再上传：
echo    LocalBoost-%VERSION%-%RID%.exe
echo.
echo  双击运行会请求管理员权限；命令行用法：LocalBoost.exe probe github.com
echo ============================================

if defined NOPAUSE exit /b 0
pause
