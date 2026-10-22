@echo off
title Cerrar Ventanas de SocketSentry
chcp 65001 >nul
echo ==============================================================================
echo [i] Cerrando ventanas y procesos activos de SocketSentry...
echo ==============================================================================

powershell -NoProfile -Command "
Get-Process cmd, powershell, python -ErrorAction SilentlyContinue | Where-Object { 
    $_.MainWindowTitle -match 'SocketSentry|Auditoria de Red|Centinela de Red' 
} | Stop-Process -Force
"

echo [✓] Procesos detenidos correctamente.
timeout /t 2 >nul
exit /b 0
