﻿param(
    [string]$Dir = "",
    [int]$Port = 0,
    [string]$ServiceName = "VPNSpoofProxy"
)

# Registers SubSync background proxy in Windows User Startup (no admin rights needed)
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$vbsPath = Join-Path $scriptPath "run_background.vbs"
$repoDir = if ($Dir) { (Resolve-Path $Dir).Path } else { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)) }
$cfgFile = Join-Path $repoDir "data\config.json"

if ($Port -le 0 -and (Test-Path $cfgFile)) {
    try {
        $cfg = Get-Content $cfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cfg.listen_port) { $Port = [int]$cfg.listen_port }
    } catch {}
}
if ($Port -le 0) { $Port = 54321 }

Write-Host "[*] Настройка автозапуска $ServiceName (каталог: $repoDir, порт: $Port)..." -ForegroundColor Cyan

# 1. Если осталась старая задача в планировщике, пробуем ее убрать
try {
    schtasks.exe /Delete /TN $ServiceName /F 2>$null
} catch {}

# 2. Создаем ярлык в папке автозагрузки пользователя (без прав администратора)
$startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
$shortcutPath = Join-Path $startupFolder "$ServiceName.lnk"

$vbsArgs = "`"$vbsPath`" --port $Port --config `"$cfgFile`""

try {
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "wscript.exe"
    $shortcut.Arguments = $vbsArgs
    $shortcut.WorkingDirectory = $repoDir
    $shortcut.Description = "SubSync Proxy Daemon ($ServiceName)"
    $shortcut.WindowStyle = 7
    $shortcut.Save()
    Write-Host "[+] Автозапуск успешно настроен в папке Startup ($shortcutPath)!" -ForegroundColor Green
} catch {
    Write-Host "[-] Ошибка настройки автозапуска: $_" -ForegroundColor Red
}

# 3. Остановка прежних процессов именно этого экземпляра перед новым запуском
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ($_.CommandLine -like "*$cfgFile*") -or ($ServiceName -eq "VPNSpoofProxy" -and $_.CommandLine -like "*main.py*proxy*")
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
} catch {}

# 4. Запуск фоновой службы прямо сейчас
Write-Host "[*] Запуск фоновой службы прокси..." -ForegroundColor Cyan
Start-Process "wscript.exe" -ArgumentList $vbsArgs -WorkingDirectory $repoDir

Write-Host "[+] Фоновая служба $ServiceName активна и готова к работе!" -ForegroundColor Green
Write-Host "[*] Локальный эндпоинт прокси: http://127.0.0.1:$Port/sub" -ForegroundColor White
