@echo off
title Cerrar Ventanas de StartupSentry
chcp 65001 >nul
echo ==============================================================================
echo [i] Cerrando ventanas y procesos activos de StartupSentry...
echo ==============================================================================

powershell -NoProfile -Command "
Get-Process cmd, powershell, python -ErrorAction SilentlyContinue | Where-Object { 
    $_.MainWindowTitle -match 'StartupSentry|Persistencia en Inicio|Centinela de Inicio' 
} | Stop-Process -Force
"

echo [✓] Procesos detenidos correctamente.
timeout /t 2 >nul
exit /b 0
