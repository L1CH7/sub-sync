[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$taskName = "VPNSpoofProxy"
Write-Host "[*] Остановка и удаление автозапуска $taskName..." -ForegroundColor Yellow

# 1. Удаление ярлыка из папки автозагрузки (Startup)
try {
    $startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
    $shortcutPath = Join-Path $startupFolder "$taskName.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Ярлык автозапуска удален из папки Startup." -ForegroundColor Green
    }
} catch {}

# 2. Удаление из Планировщика задач (если осталась старая задача)
try {
    schtasks.exe /Delete /TN $taskName /F 2>$null
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue 2>$null
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue 2>$null
} catch {}

# 3. Завершение работающих процессов прокси
try {
    $killed = $false
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { 
        $_.CommandLine -like "*main.py proxy*" 
    } | ForEach-Object { 
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $killed = $true
    }
    if ($killed) {
        Write-Host "[+] Фоновые процессы прокси остановлены." -ForegroundColor Green
    }
} catch {}

Write-Host "[+] Автозапуск успешно отключен и все следы службы удалены." -ForegroundColor Green
