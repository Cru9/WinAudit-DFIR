@echo off
:: ==============================================================================
:: Limpieza y Cierre Seguro de Ventanas - UsbSentry (Cru9)
:: ==============================================================================
chcp 65001 >nul
title UsbSentry - Detencion Segura de Procesos
echo ==============================================================================
echo [i] Deteniendo consolas y procesos de UsbSentry en background...
echo ==============================================================================
echo.

taskkill /F /FI "WINDOWTITLE eq UsbSentry*" /T >nul 2>&1

echo [✓] Procesos y ventanas de UsbSentry finalizados correctamente.
timeout /t 2 >nul
exit /b
