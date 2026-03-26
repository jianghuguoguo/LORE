param(
    [string]$accounts = "",
    [int]$count = 30
)

$REG  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$PY   = "d:\渗透测试相关\语料库\语料\.venv\Scripts\python.exe"
$SCH  = "d:\渗透测试相关\语料库\语料\LORE\crawlers\wechat_crawler\scheduler.py"

function Set-Proxy($port) {
    Set-ItemProperty $REG ProxyServer "127.0.0.1:$port"
    Set-ItemProperty $REG ProxyEnable 1
    Write-Host "Proxy -> 127.0.0.1:$port"
}

$origEnable = (Get-ItemProperty $REG -EA 0).ProxyEnable
$origServer = (Get-ItemProperty $REG -EA 0).ProxyServer
Write-Host "Current: $origServer (Enable=$origEnable)"

try {
    Set-Proxy 8080
    Write-Host ""
    Write-Host "Please restart WeChat, then press any key..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    if ($accounts -ne "") {
        Write-Host "Crawling: $accounts  count=$count"
        & $PY $SCH crawl --accounts $accounts --count $count
    } else {
        Write-Host "Crawling all accounts, count=$count"
        & $PY $SCH crawl --count $count
    }
} finally {
    if ($origEnable -eq 1 -and $origServer) {
        Set-ItemProperty $REG ProxyServer $origServer
        Set-ItemProperty $REG ProxyEnable 1
        Write-Host "Restored: $origServer"
    } else {
        Set-ItemProperty $REG ProxyEnable 0
        Write-Host "Proxy disabled"
    }
}
