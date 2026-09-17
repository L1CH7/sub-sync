# Registers VPN Spoof background proxy in Windows User Startup (no admin rights needed)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$taskName = "VPNSpoofProxy"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$vbsPath = Join-Path $scriptPath "run_background.vbs"
$repoDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath))

Write-Host "[*] Настройка автозапуска VPN Spoof Proxy..." -ForegroundColor Cyan

# 1. Если осталась старая задача в планировщике, пробуем ее убрать
try {
    schtasks.exe /Delete /TN $taskName /F 2>$null
} catch {}

# 2. Создаем ярлык в папке автозагрузки пользователя (не требует прав администратора)
$startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
$shortcutPath = Join-Path $startupFolder "$taskName.lnk"

try {
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "wscript.exe"
    $shortcut.Arguments = "`"$vbsPath`""
    $shortcut.WorkingDirectory = $repoDir
    $shortcut.Description = "VPN Spoof Proxy Daemon"
    $shortcut.WindowStyle = 7 # Minimized
    $shortcut.Save()
    Write-Host "[+] Автозапуск успешно настроен в папке автозагрузки пользователя (Startup)!" -ForegroundColor Green
} catch {
    Write-Host "[-] Ошибка настройки автозапуска: $_" -ForegroundColor Red
}

# 3. Запуск фоновой службы прямо сейчас
Write-Host "[*] Запуск фоновой службы прокси..." -ForegroundColor Cyan
Start-Process "wscript.exe" -ArgumentList "`"$vbsPath`"" -WorkingDirectory $repoDir

Write-Host "[+] Фоновая служба VPN Spoof Proxy активна и готова к работе!" -ForegroundColor Green
Write-Host "[*] Локальный эндпоинт прокси: http://127.0.0.1:54321/sub" -ForegroundColor White
