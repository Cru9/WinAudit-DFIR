@echo off
:: ==============================================================================
:: BrowserSentry - Lanzador Inteligente Multi-Runtime Forense de Navegadores Web
:: Autor: Ezequiel Diaz (Cru9) | WinAudit-DFIR Suite
:: ==============================================================================

chcp 65001 >nul
title BrowserSentry - Forense de Navegadores y Descargas (Cru9)
cd /d "%~dp0"

:: 1. PROTECCION ANTI-BUCLE: Si ya fue invocado con el parametro -elevated, no volver a elevar
if "%~1"=="-elevated" goto :CheckRuntime

:: 2. Comprobar si ya tenemos privilegios de Administrador
net session >nul 2>&1
if %errorLevel% equ 0 goto :CheckRuntime

:: 3. Intentar elevacion UNA SOLA VEZ
echo [i] Solicitando permisos de Administrador para auditoria de perfiles y carpetas protegidas...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '-elevated' -Verb RunAs } catch { exit 1 }" >nul 2>&1

:: Si se elevo con exito, cerrar esta ventana original para no duplicar
if %errorLevel% equ 0 exit /b

:: Si el usuario cancelo la elevacion UAC, continuar normalmente en modo estandar
echo [!] Permisos de Administrador omitidos. Iniciando con privilegios de usuario...
echo.

:CheckRuntime
cls
echo ==============================================================================
echo [i] Iniciando BrowserSentry - Forense de Descargas, Historial Web & Extensiones...
echo ==============================================================================
echo.

:: Detectar si Python 3 esta disponible en el PATH
where python >nul 2>&1
if %errorLevel% equ 0 (
    echo [*] Runtime detectado: Python 3
    python "%~dp0BrowserSentry.py"
    goto :FIN
)

:: Si no hay Python, ejecutar motor nativo en PowerShell
echo [!] Python no detectado en el PATH. Ejecutando motor nativo en PowerShell...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0BrowserSentry.ps1"

:FIN
echo.
echo Presiona cualquier tecla para cerrar esta ventana...
pause >nul
