@echo off
:: ==============================================================================
:: WinAudit-DFIR - Master Forensic & Incident Response Suite
:: Autor: Cru9 | Version: v1.2
:: ==============================================================================
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title WinAudit-DFIR Master Suite - Cru9

:: 1. Auto-elevacion a Administrador (UAC) para no duplicar ventanas ni perder permisos
if "%~1"=="-elevated" goto :MENU
net session >nul 2>&1
if %errorLevel% equ 0 goto :MENU

echo.
echo ==============================================================================
echo   [*] Solicitando privilegios de Administrador para la Suite Forense DFIR...
echo ==============================================================================
powershell -NoProfile -Command "try { Start-Process cmd -ArgumentList '/c \"\"%~f0\"\" -elevated' -Verb RunAs } catch { exit 1 }" >nul 2>&1
if %errorLevel% equ 0 exit /b
echo  [!] Permisos de Administrador omitidos. Ejecutando en modo estandar...
timeout /t 2 >nul

:MENU
cd /d "%~dp0"
cls
color 0B
echo ==============================================================================
echo   __          ___             __             _ _ _      _____  ______ _____ _____  
echo   \ \        / (_)           /\ \           ^| (_) ^|    ^|  __ \^|  ____^|_   _^|  __ \ 
echo    \ \  /\  / / _ _ __      /  \ \ _   _  __^| ^|_^| ^|_   ^| ^|  ^| ^| ^|__    ^| ^| ^| ^|__) ^|
echo     \ \/  \/ / ^| ^| '_ \    / /\ \ ^| ^| ^| ^|/ _` ^| ^| __^|  ^| ^|  ^| ^|  __^|   ^| ^| ^|  _  / 
echo      \  /\  /  ^| ^| ^| ^| ^|  / ____ \^| ^|_^| ^| (_^| ^| ^| ^|_   ^| ^|__^| ^| ^|     _^| ^|_^| ^| \ \ 
echo       \/  \/   ^|_^|_^| ^|_^| /_/    \_\\__,_^|\__,_^|_^|\__^|  ^|_____/^|_^|    ^|_____^|_^|  \_^|
echo.
echo                     DFIR CYBERSECURITY ECOSYSTEM v1.2
echo                                by Cru9
echo ==============================================================================
echo.
echo   Selecciona el modulo de auditoria y respuesta a incidentes:
echo.
echo   [1] [*] Deteccion de Intrusos
echo           - Triage forense de host y persistencia en Windows.
echo           - Analisis de Visor de Eventos de Seguridad (1102, 4625, 4624, 4720).
echo           - Deteccion de fuerza bruta RDP y cuentas privilegiadas.
echo.
echo   [2] [*] WiFiSentry
echo           - Auditoria forense de redes inalambricas 802.11.
echo           - Rogue AP Hunter (Deteccion en vivo de ataques Evil Twin).
echo           - Benchmark de Entropia y Estimacion de Crackeo PBKDF2 (GPU Hashcat).
echo           - Sensor de Proximidad y Mapa de Calor RF en tiempo real.
echo.
echo   [3] [*] SocketSentry
echo           - Framework forense de sockets de red y threat hunting en memoria.
echo           - Deteccion de balizas C2 (Beaconing) y servidores maliciosos (Feodo).
echo           - Inspeccion de binarios LOLBins en red (certutil, powershell, mshta).
echo           - Analisis heuristico de puertos no estandares y CommandLine.
echo.
echo   [0] [X] Salir
echo.
echo ==============================================================================
set "OPCION="
set /p "OPCION=  Ingrese una opcion [1, 2, 3, 0]: "

if "%OPCION%"=="1" goto RUN_DETECCION
if "%OPCION%"=="2" goto RUN_WIFISENTRY
if "%OPCION%"=="3" goto RUN_SOCKETSENTRY
if "%OPCION%"=="0" goto SALIR

echo.
echo   [!] Opcion invalida. Intenta nuevamente...
timeout /t 2 >nul
goto MENU

:RUN_DETECCION
cls
echo ==============================================================================
echo   Iniciando Deteccion de Intrusos (Auditoria Forense de Eventos de Seguridad)...
echo ==============================================================================
echo.
if exist "%~dp0Detección de Intrusos\Ejecutar-Deteccion.bat" (
    call "%~dp0Detección de Intrusos\Ejecutar-Deteccion.bat" -elevated
) else (
    call "%~dp0DETECC~1\Ejecutar-Deteccion.bat" -elevated
)
goto MENU

:RUN_WIFISENTRY
cls
echo ==============================================================================
echo   Iniciando WiFiSentry (Suite Forense Inalambrica & Sensor RF)...
echo ==============================================================================
echo.
call "%~dp0WiFiSentry\Ejecutar-WiFiSentry.bat" -elevated
goto MENU

:RUN_SOCKETSENTRY
cls
echo ==============================================================================
echo   Iniciando SocketSentry (Auditoria Forense de Sockets & C2 Hunter)...
echo ==============================================================================
echo.
call "%~dp0SocketSentry\Ejecutar-SocketSentry.bat" -elevated
goto MENU

:SALIR
cls
echo.
echo ==============================================================================
echo   Gracias por utilizar la Suite WinAudit-DFIR de Cru9.
echo ==============================================================================
timeout /t 2 >nul
exit /b 0
