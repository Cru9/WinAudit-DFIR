@echo off
:: ==============================================================================
:: WiFiSentry - Lanzador Seguro sin Bucles de Ventanas
:: Autor: Ezequiel Diaz (Cru9) | Portafolio DFIR y Redes
:: ==============================================================================

chcp 65001 >nul
title WiFiSentry - Auditoria de Redes Wi-Fi y Manual Didactico DFIR
cd /d "%~dp0"

:: 1. PROTECCION ANTI-BUCLE: Si ya fue invocado con el parametro -elevated, no volver a elevar
if "%~1"=="-elevated" goto :RunApp

:: 2. Comprobar si ya tenemos privilegios de Administrador
net session >nul 2>&1
if %errorLevel% equ 0 goto :RunApp

:: 3. Intentar elevacion UNA SOLA VEZ. Si el usuario cancela, continuar normalmente sin abrir mas ventanas
echo [i] Solicitando permisos de Administrador para funciones completas...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '-elevated' -Verb RunAs } catch { exit 1 }" >nul 2>&1

:: Si se elevo con exito, cerrar esta ventana original para no duplicar
if %errorLevel% equ 0 exit /b

:: Si el usuario pulso "No" en el control de cuentas (UAC), avisar y ejecutar en esta misma ventana
echo [!] Permisos de Administrador omitidos. Ejecutando en modo estandar...
echo.

:RunApp
cls
echo ==============================================================================
echo [i] Iniciando WiFiSentry - Suite de Auditoria y Manual Didactico...
echo ==============================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFiSentry.ps1"

echo.
echo Presiona cualquier tecla para cerrar esta ventana...
pause >nul
