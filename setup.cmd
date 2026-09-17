@echo off
title VPN Spoof Setup
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Произошла ошибка при выполнении скрипта.
    pause
)
