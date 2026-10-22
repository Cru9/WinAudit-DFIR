@echo off
title Limpiador de Ventanas WiFiSentry
echo ==============================================================================
echo [i] Cerrando todas las ventanas de terminal huerfanas de WiFiSentry...
echo ==============================================================================
echo.

:: Cerrar cualquier proceso cmd que tenga el titulo de WiFiSentry
powershell -NoProfile -Command "Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*WiFiSentry*' } | Stop-Process -Force" 2>nul

echo [i] Ventanas de WiFiSentry cerradas.
timeout /t 2 >nul
exit /b
