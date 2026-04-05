param(
    [string[]]$Accounts = @(),
    [int]$Count = 30,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$WorkspaceRoot = Split-Path -Parent $RepoRoot
$InternetSettingsReg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Resolve-FirstExistingPath {
    param([string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    return $null
}

$Python = Resolve-FirstExistingPath @(
    (Join-Path $RepoRoot '.venv\Scripts\python.exe'),
    (Join-Path $WorkspaceRoot '.venv\Scripts\python.exe')
)

if (-not $Python) {
    throw '未找到 python.exe，请先激活或创建虚拟环境。'
}

$Mitmdump = Resolve-FirstExistingPath @(
    (Join-Path (Split-Path -Parent $Python) 'mitmdump.exe'),
    (Join-Path $RepoRoot '.venv\Scripts\mitmdump.exe'),
    (Join-Path $WorkspaceRoot '.venv\Scripts\mitmdump.exe')
)

if (-not $Mitmdump) {
    throw '未找到 mitmdump.exe，请先安装 mitmproxy。'
}

$Scheduler = Join-Path $ScriptDir 'scheduler.py'
$Interceptor = Join-Path $ScriptDir 'interceptor.py'
$LogsDir = Join-Path $RepoRoot 'logs'
$MitmOutLog = Join-Path $LogsDir 'wechat_mitmdump.out.log'
$MitmErrLog = Join-Path $LogsDir 'wechat_mitmdump.err.log'

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
}

function Refresh-InternetSettings {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
"@ | Out-Null

    [void][NativeInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][NativeInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

function Get-ProxyState {
    $current = Get-ItemProperty $InternetSettingsReg -ErrorAction SilentlyContinue
    return @{
        Enabled = [bool]($current.ProxyEnable)
        Server = [string]($current.ProxyServer)
    }
}

function Set-SystemProxy {
    param(
        [string]$Host,
        [int]$Port
    )

    Set-ItemProperty $InternetSettingsReg ProxyServer "$Host`:$Port"
    Set-ItemProperty $InternetSettingsReg ProxyEnable 1
    Refresh-InternetSettings
    Write-Host "系统代理 -> $Host`:$Port" -ForegroundColor Green
}

function Restore-SystemProxy {
    param([hashtable]$Snapshot)

    Set-ItemProperty $InternetSettingsReg ProxyServer ($Snapshot.Server ?? '')
    Set-ItemProperty $InternetSettingsReg ProxyEnable ([int]([bool]$Snapshot.Enabled))
    Refresh-InternetSettings
    if ($Snapshot.Enabled -and $Snapshot.Server) {
        Write-Host "系统代理已恢复 -> $($Snapshot.Server)" -ForegroundColor Green
    } else {
        Write-Host '系统代理已恢复为关闭状态' -ForegroundColor Green
    }
}

$originalProxy = Get-ProxyState
$mitmProcess = $null

try {
    Write-Host "Python: $Python"
    Write-Host "mitmdump: $Mitmdump"
    Write-Host "Scheduler: $Scheduler"
    Write-Host "Interceptor: $Interceptor"
    Write-Host "当前代理: $($originalProxy.Server) (Enabled=$($originalProxy.Enabled))"

    $mitmProcess = Start-Process -FilePath $Mitmdump `
        -ArgumentList @('-s', $Interceptor) `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $MitmOutLog `
        -RedirectStandardError $MitmErrLog `
        -PassThru

    Start-Sleep -Seconds 2
    Write-Host "mitmdump 已启动，PID=$($mitmProcess.Id)"

    Set-SystemProxy -Host '127.0.0.1' -Port 8080

    Write-Host ''
    Write-Host '请确认 PC 微信已登录，并重启微信使其走系统代理。完成后按任意键开始 scheduler crawl。' -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

    $schedulerArgs = @($Scheduler, 'crawl', '--count', $Count)
    if ($Force.IsPresent) {
        $schedulerArgs += '--force'
    }
    if ($Accounts.Count -gt 0) {
        $schedulerArgs += '--accounts'
        $schedulerArgs += $Accounts
    }

    & $Python @schedulerArgs
}
finally {
    Restore-SystemProxy -Snapshot $originalProxy

    if ($mitmProcess -and -not $mitmProcess.HasExited) {
        Stop-Process -Id $mitmProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host 'mitmdump 已停止' -ForegroundColor Green
    }
}
