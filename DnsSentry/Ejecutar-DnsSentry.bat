@echo off
chcp 65001 >nul 2>&1
title WinAudit-DFIR - DnsSentry Launcher

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Solicitando elevacion de privilegios de Administrador para DnsSentry...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c ""%~f0""' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
cls
echo ===============================================================================
echo       WINAUDIT-DFIR - DNSSENTRY (DNS CACHE & HOSTS FORENSICS v3.0.0)
echo ===============================================================================
echo.

where python >nul 2>&1
if %errorlevel% equ 0 (
    python DnsSentry.py %*
) else (
    echo [*] Python no detectado. Iniciando motor nativo en PowerShell...
    powershell -NoProfile -ExecutionPolicy Bypass -File .\DnsSentry.ps1
)

echo.
pause
