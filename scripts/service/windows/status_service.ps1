﻿param(
    [string]$Dir = "",
    [int]$Port = 0,
    [string]$ServiceName = "VPNSpoofProxy"
)

[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = if ($Dir) { (Resolve-Path $Dir).Path } else { (Get-Item "$scriptDir\..\..\..").FullName }
$cfgFile = Join-Path $repoDir "data\config.json"

if ($Port -le 0 -and (Test-Path $cfgFile)) {
    try {
        $cfg = Get-Content $cfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cfg.listen_port) { $Port = [int]$cfg.listen_port }
    } catch {}
}
if ($Port -le 0) { $Port = 54321 }

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      СТАТУС СЛУЖБЫ SUBSYNC ($ServiceName)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Автозапуск
$startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
$shortcutPath = Join-Path $startupFolder "$ServiceName.lnk"
$hasStartup = Test-Path $shortcutPath

$hasTask = $false
try {
    $task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue 2>$null
    if ($task) { $hasTask = $true }
} catch {}

if ($hasStartup) {
    Write-Host "[+] Автозапуск: УСТАНОВЛЕН (Папка Автозагрузка пользователя)" -ForegroundColor Green
} elseif ($hasTask) {
    Write-Host "[+] Автозапуск: УСТАНОВЛЕН (Планировщик задач)" -ForegroundColor Green
} else {
    Write-Host "[-] Автозапуск: НЕ УСТАНОВЛЕН" -ForegroundColor Yellow
}

# 2. Запущенный процесс
$procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*main.py*proxy*" -and $_.ProcessId -ne $PID })
$isProxyRunning = ($procs.Count -gt 0)
$proxyPids = @()
if ($isProxyRunning) {
    $proxyPids = @($procs | ForEach-Object { $_.ProcessId })
    $pidsStr = $proxyPids -join ", "
    Write-Host "[+] Процесс прокси: РАБОТАЕТ (PID: $pidsStr)" -ForegroundColor Green
} else {
    Write-Host "[-] Процесс прокси: ОСТАНОВЛЕН" -ForegroundColor Yellow
}

# 3. Проверка порта
$portOwnerPid = $null
$portOwnerName = $null

try {
    $conns = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue 2>$null)
    if ($conns.Count -gt 0) {
        $portOwnerPid = $conns[0].OwningProcess
        $portOwnerName = (Get-Process -Id $portOwnerPid -ErrorAction SilentlyContinue 2>$null).ProcessName
    }
} catch {
    try {
        $netstatLine = netstat -ano | Select-String ":$Port\s.*LISTENING" | Select-Object -First 1
        if ($netstatLine -match '\s+(\d+)$') {
            $portOwnerPid = [int]$matches[1]
            $portOwnerName = (Get-Process -Id $portOwnerPid -ErrorAction SilentlyContinue 2>$null).ProcessName
        }
    } catch {}
}

if ($portOwnerPid) {
    if ($isProxyRunning -and ($proxyPids -contains $portOwnerPid)) {
        Write-Host "[+] Порт $Port - АКТИВЕН (Служба proxy принимает подключения)" -ForegroundColor Green
        Write-Host "[*] Эндпоинт подписки: http://127.0.0.1:$Port/sub" -ForegroundColor White
    } else {
        Write-Host "[!] Порт $Port - ЗАНЯТ другим процессом ($portOwnerName, PID: $portOwnerPid)" -ForegroundColor Red
        Write-Host "    (Для работы службы требуется освободить порт $Port)" -ForegroundColor DarkGray
    }
} else {
    if ($isProxyRunning) {
        Write-Host "[!] Порт $Port - НЕ ОТКРЫТ (хотя процесс запущен - возможен сбой при старте)" -ForegroundColor Red
    } else {
        Write-Host "[i] Порт $Port - СВОБОДЕН (служба выключена)" -ForegroundColor Gray
    }
}

Write-Host "==========================================" -ForegroundColor Cyan
