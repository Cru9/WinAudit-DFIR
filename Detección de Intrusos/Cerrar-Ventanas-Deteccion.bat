@echo off
title Cerrar Ventanas de IntruderDetector
chcp 65001 >nul
echo ==============================================================================
echo [i] Cerrando ventanas y procesos activos de IntruderDetector...
echo ==============================================================================

powershell -NoProfile -Command "
Get-Process cmd, powershell, python -ErrorAction SilentlyContinue | Where-Object { 
    $_.MainWindowTitle -match 'IntruderDetector|Deteccion de Intrusos|Auditoria de Seguridad' 
} | Stop-Process -Force
"

echo [✓] Procesos detenidos correctamente.
timeout /t 2 >nul
exit /b 0
