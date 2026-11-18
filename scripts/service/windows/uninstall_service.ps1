﻿param(
    [string]$Dir = "",
    [string]$ServiceName = "VPNSpoofProxy"
)

[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = if ($Dir) { (Resolve-Path $Dir).Path } else { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)) }
$cfgFile = Join-Path $repoDir "data\config.json"

Write-Host "[*] Остановка и удаление автозапуска $ServiceName..." -ForegroundColor Yellow

# 1. Удаление ярлыка из папки автозагрузки (Startup)
try {
    $startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
    $shortcutPath = Join-Path $startupFolder "$ServiceName.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Ярлык автозапуска удален из папки Startup." -ForegroundColor Green
    }
} catch {}

# 2. Удаление из Планировщика задач (если осталась старая задача)
try {
    schtasks.exe /Delete /TN $ServiceName /F 2>$null
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue 2>$null
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue 2>$null
} catch {}

# 3. Завершение работающих процессов прокси
try {
    $killed = $false
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ($_.CommandLine -like "*$cfgFile*") -or ($ServiceName -eq "VPNSpoofProxy" -and -not $Dir -and $_.CommandLine -like "*main.py*proxy*")
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $killed = $true
    }
    if ($killed) {
        Write-Host "[+] Фоновые процессы прокси остановлены." -ForegroundColor Green
    }
} catch {}

Write-Host "[+] Автозапуск $ServiceName успешно отключен и следы службы удалены." -ForegroundColor Green
