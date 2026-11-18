param(
    [string]$Dir = $(if ($env:SUBSYNC_DIR) { $env:SUBSYNC_DIR } else { "" }),
    [int]$Port = $(if ($env:SUBSYNC_PORT) { [int]$env:SUBSYNC_PORT } else { 0 }),
    [string]$ServiceName = $(if ($env:SUBSYNC_SERVICE_NAME) { $env:SUBSYNC_SERVICE_NAME } else { "VPNSpoofProxy" }),
    [string]$Branch = $(if ($env:SUBSYNC_BRANCH) { $env:SUBSYNC_BRANCH } else { "master" }),
    [string]$RepoUrl = $(if ($env:SUBSYNC_REPO_URL) { $env:SUBSYNC_REPO_URL } else { "https://github.com/L1CH7/sub-sync.git" }),
    [switch]$NoTui = ($env:SUBSYNC_NO_TUI -eq "1"),
    [switch]$Tui
)

$ErrorActionPreference = "Stop"
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

$stateHome = Join-Path $env:LOCALAPPDATA "subsync"
$pointerFile = Join-Path $stateHome "$ServiceName.path"

function Detect-ExistingDir {
    if (Test-Path $pointerFile) {
        $saved = (Get-Content $pointerFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($saved -and (Test-Path (Join-Path $saved "main.py"))) { return $saved }
    }
    try {
        $startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
        $lnk = Join-Path $startupFolder "$ServiceName.lnk"
        if (Test-Path $lnk) {
            $wsh = New-Object -ComObject WScript.Shell
            $wd = $wsh.CreateShortcut($lnk).WorkingDirectory
            if ($wd -and (Test-Path (Join-Path $wd "main.py"))) { return $wd }
        }
    } catch {}
    if ((Test-Path (Join-Path $PWD "main.py")) -and (Test-Path (Join-Path $PWD "pyproject.toml"))) {
        return $PWD.Path
    }
    return $null
}

if (-not $Dir) {
    $detected = Detect-ExistingDir
    if ($detected) {
        $Dir = $detected
    } else {
        $Dir = Join-Path $env:LOCALAPPDATA "sub-sync"
    }
}
$targetParent = Split-Path -Parent $Dir
if ($targetParent -and -not (Test-Path $targetParent)) {
    New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
}
$Dir = [System.IO.Path]::GetFullPath($Dir)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  SubSync - Установка и обновление" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "[*] Целевой каталог : $Dir"
Write-Host "[*] Служба          : $ServiceName"
Write-Host "[*] Источник        : $RepoUrl ($Branch)"

# 1. Проверка / установка uv
$localBin = Join-Path $env:USERPROFILE ".local\bin"
if (Test-Path (Join-Path $localBin "uv.exe")) {
    $env:Path = "$localBin;$env:Path"
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Установка пакетного менеджера uv..." -ForegroundColor Cyan
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$localBin;$env:Path"
}
$uvCmd = (Get-Command uv).Source

# 2. Фиксация прошлой версии и бэкап data/
$oldVersion = ""
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("subsync-inst-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null

try {
    $stagingDir = Join-Path $tmpRoot "repo"
    $dataBackup = Join-Path $tmpRoot "data_backup"

    if (Test-Path $Dir) {
        $verFile = Join-Path $Dir "VERSION"
        if (Test-Path $verFile) {
            $oldVersion = (Get-Content $verFile -Raw).Trim()
        } elseif (Test-Path (Join-Path $Dir "main.py")) {
            $oldVersion = "legacy"
        }
        if ($oldVersion) {
            Write-Host "[*] Найдена предыдущая версия: $oldVersion — сохраняем data/ и обновляем." -ForegroundColor Yellow
        }
        $existingData = Join-Path $Dir "data"
        if (Test-Path $existingData) {
            New-Item -ItemType Directory -Path $dataBackup -Force | Out-Null
            Copy-Item (Join-Path $existingData "*") $dataBackup -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # 3. Загрузка свежей копии
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Host "[*] Клонирование репозитория..." -ForegroundColor Cyan
        & git clone --depth 1 --branch $Branch $RepoUrl $stagingDir
        if ($LASTEXITCODE -ne 0) { throw "Ошибка git clone" }
    } elseif ($RepoUrl -match "https://github.com/([^/]+/[^/.]+)(\.git)?$") {
        $slug = $Matches[1]
        $zipUrl = "https://github.com/$slug/archive/refs/heads/$Branch.zip"
        $zipPath = Join-Path $tmpRoot "repo.zip"
        $extractDir = Join-Path $tmpRoot "extract"
        Write-Host "[*] git не найден, скачиваем архив $zipUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $inner = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
        Move-Item $inner.FullName $stagingDir
    } else {
        throw "Для загрузки $RepoUrl требуется git."
    }

    # 4. Восстановление data/
    $stageData = Join-Path $stagingDir "data"
    New-Item -ItemType Directory -Path $stageData -Force | Out-Null
    if (Test-Path $dataBackup) {
        Get-ChildItem -Path $dataBackup -Force | Where-Object {
            $_.Name -notin @("config.example.json", ".gitkeep")
        } | ForEach-Object {
            Copy-Item $_.FullName $stageData -Recurse -Force
        }
    }

    # 5. Обновление listen_port при передаче -Port
    $cfgFile = Join-Path $stageData "config.json"
    if ($Port -gt 0) {
        $cfgData = @{}
        if (Test-Path $cfgFile) {
            try {
                $parsed = Get-Content $cfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($p in $parsed.PSObject.Properties) { $cfgData[$p.Name] = $p.Value }
            } catch {}
        }
        $cfgData["listen_port"] = $Port
        $cfgData | ConvertTo-Json -Depth 12 | Set-Content -Path $cfgFile -Encoding UTF8
    }

    # 6. Остановка прежнего экземпляра и замена папки
    $uninst = Join-Path $Dir "scripts\service\windows\uninstall_service.ps1"
    if (Test-Path $uninst) {
        try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninst -Dir $Dir -ServiceName $ServiceName | Out-Null } catch {}
    }
    if (Test-Path $Dir) {
        Remove-Item $Dir -Recurse -Force
    }
    Move-Item $stagingDir $Dir

    # 7. Синхронизация окружения
    Write-Host "[*] Синхронизация окружения (uv sync)..." -ForegroundColor Cyan
    Push-Location $Dir
    try {
        & $uvCmd sync --no-dev
        if ($LASTEXITCODE -ne 0) { & $uvCmd sync }
    } finally {
        Pop-Location
    }

    $newVersion = if (Test-Path (Join-Path $Dir "VERSION")) { (Get-Content (Join-Path $Dir "VERSION") -Raw).Trim() } else { "0.0.0" }
    $effPort = $Port
    $liveCfg = Join-Path $Dir "data\config.json"
    if ($effPort -le 0 -and (Test-Path $liveCfg)) {
        try {
            $parsedCfg = Get-Content $liveCfg -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($parsedCfg.listen_port) { $effPort = [int]$parsedCfg.listen_port }
        } catch {}
    }
    if ($effPort -le 0) { $effPort = 54321 }

    $stateObj = @{
        version = $newVersion
        port = $effPort
        service_name = $ServiceName
        branch = $Branch
        installed_at = (Get-Date).ToString("o")
    }
    $stateObj | ConvertTo-Json | Set-Content -Path (Join-Path $Dir "data\.install_state.json") -Encoding UTF8

    if (-not (Test-Path $stateHome)) { New-Item -ItemType Directory -Path $stateHome -Force | Out-Null }
    Set-Content -Path $pointerFile -Value $Dir -Encoding UTF8

    try {
        New-NetFirewallRule -DisplayName "SubSync-$ServiceName-$effPort" -Direction Inbound -LocalPort $effPort -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    # 8. Переадресация установки службы на локальный скрипт
    $svcScript = Join-Path $Dir "scripts\service\windows\install_service.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $svcScript -Dir $Dir -Port $effPort -ServiceName $ServiceName

    Write-Host "==================================================" -ForegroundColor Green
    if ($oldVersion) {
        Write-Host "[+] Обновление завершено: $oldVersion -> $newVersion" -ForegroundColor Green
    } else {
        Write-Host "[+] Установка завершена: версия $newVersion" -ForegroundColor Green
    }
    Write-Host "[*] Каталог: $Dir" -ForegroundColor White
    Write-Host "[*] Адрес  : http://127.0.0.1:$effPort/sub" -ForegroundColor White
    Write-Host "==================================================" -ForegroundColor Green

    # 9. Запрос перехода в TUI
    $hasConfig = $false
    if (Test-Path $liveCfg) {
        try {
            $c = Get-Content $liveCfg -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($c.target_url) { $hasConfig = $true }
        } catch {}
    }

    if ($Tui) {
        Push-Location $Dir
        try { & $uvCmd run main.py } finally { Pop-Location }
    } elseif (-not $NoTui -and [Environment]::UserInteractive) {
        $prompt = if ($hasConfig) { "Открыть интерактивный TUI для настройки? [y/N]" } else { "Конфигурация не задана. Открыть TUI сейчас? [Y/n]" }
        $defaultYes = (-not $hasConfig)
        $ans = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($ans)) { $ans = if ($defaultYes) { "Y" } else { "N" } }
        if ($ans -match "^[Yy]") {
            Push-Location $Dir
            try { & $uvCmd run main.py } finally { Pop-Location }
        }
    }
} finally {
    if (Test-Path $tmpRoot) { Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
