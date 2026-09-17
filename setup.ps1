# PowerShell Setup & Launcher for Windows
$ErrorActionPreference = "Stop"

# UTF-8 Console Support
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$repoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoDir

# 1. Проверяем наличие uv
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
$localBin = Join-Path $env:USERPROFILE ".local\bin"
$localUv = Join-Path $localBin "uv.exe"

if (-not $uvCmd -and -not (Test-Path $localUv)) {
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "VPN Spoof - Setup" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "[!] Requires Astral uv package manager." -ForegroundColor Yellow
    $choice = Read-Host "Download and install uv automatically? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "Y" }
    if ($choice -match "^[Yy]") {
        Write-Host "[*] Installing Astral uv..." -ForegroundColor Cyan
        powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
        $env:Path = "$env:Path;$localBin"
    } else {
        Write-Host "[-] Cancelled by user. Please install uv manually: https://astral.sh/uv" -ForegroundColor Red
        exit 1
    }
} else {
    if (Test-Path $localUv) {
        $env:Path = "$env:Path;$localBin"
    }
}

# 2. Настройка брандмауэра Windows (порты для связи с телефоном)
New-NetFirewallRule -DisplayName "VPN-Spoof-Ports" -Direction Inbound -LocalPort 8080,8443,54321 -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# 3. Первичная настройка зависимостей
if (-not (Test-Path ".venv")) {
    Write-Host "[*] Setting up dependencies with uv sync..." -ForegroundColor Cyan
    uv sync
}

# 4. Запуск интерактивного меню
uv run main.py
