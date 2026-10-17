<#
.SYNOPSIS
    发布 LocalBoost 自包含单文件。

.DESCRIPTION
    publish.cmd 的 PowerShell 版本。cmd 里的 ^ 续行在 PowerShell / bash 下不可用，
    所以另给一份，避免非 cmd 用户只能手敲命令。

.PARAMETER Runtime
    目标架构：win-x64（默认）或 win-arm64。

.PARAMETER NoPause
    结束时不等待按键。给 CI 或其它脚本调用时用。

.EXAMPLE
    ./build.ps1
    ./build.ps1 -Runtime win-arm64
    ./build.ps1 -NoPause
#>
[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64',

    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# 版本号向 MSBuild 要，不去文本解析 props 文件
$version = (dotnet msbuild LocalBoost.csproj -getProperty:Version -nologo | Select-Object -Last 1)
if ([string]::IsNullOrWhiteSpace($version)) { $version = 'unknown' }

Write-Host '============================================'
Write-Host " LocalBoost 发布"
Write-Host " 版本 $version    运行时 $Runtime"
Write-Host ' 自包含单文件，目标机器不需要装 .NET'
Write-Host '============================================'
Write-Host ''

dotnet publish LocalBoost.csproj `
    -c Release `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -o publish

if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Error '[失败] 发布未完成。常见原因：publish\LocalBoost.exe 正在运行，文件被占用。'
    exit 1
}

# Web SDK 会把项目目录下的文件当内容收集，历史上踩过产物自我嵌套的坑，这里兜一道
if (Test-Path 'publish\publish') {
    Write-Warning '产物出现嵌套目录 publish\publish，请检查 csproj 的 Content Remove 是否还在。'
}

Write-Host ''
Write-Host '============================================'
Write-Host ' 完成'
Write-Host " 产物：$(Join-Path $PSScriptRoot 'publish\LocalBoost.exe')"
Write-Host ''
Write-Host ' 发版时建议把产物重命名成带版本号的名字再上传：'
Write-Host "   LocalBoost-$version-$Runtime.exe"
Write-Host '============================================'

if (-not $NoPause) {
    Read-Host '按回车键退出'
}
