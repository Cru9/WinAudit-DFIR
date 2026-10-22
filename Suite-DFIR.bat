@echo off
title WinAudit-DFIR Master Suite - Cru9
chcp 65001 >nul
color 0B

:MENU
cls
echo ==============================================================================
echo       ██╗    ██╗██╗███╗   ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
echo       ██║    ██║██║████╗  ██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
echo       ██║ █╗ ██║██║██╔██╗ ██║███████║██║   ██║██║  ██║██║   ██║   
echo       ██║███╗██║██║██║╚██╗██║██╔══██║██║   ██║██║  ██║██║   ██║   
echo       ╚███╔███╔╝██║██║ ╚████║██║  ██║╚██████╔╝██████╔╝██║   ██║   
echo        ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
echo                      DFIR CYBERSECURITY ECOSYSTEM
echo                              by Cru9
echo ==============================================================================
echo.
echo   Selecciona el modulo de auditoria y respuesta a incidentes:
echo.
echo   [1] 🛡️ Detección de Intrusos
echo       - Triage forense de host y persistencia en Windows.
echo       - Analisis de Visor de Eventos de Seguridad (1102, 4625, 4624, 4720).
echo       - Deteccion de fuerza bruta RDP y cuentas privilegiadas.
echo.
echo   [2] 📡 WiFiSentry
echo       - Auditoria forense de redes inalambricas 802.11.
echo       - Rogue AP Hunter (Deteccion en vivo de ataques Evil Twin).
echo       - Benchmark de Entropia y Estimacion de Crackeo PBKDF2 (GPU Hashcat).
echo       - Sensor de Proximidad y Mapa de Calor RF en tiempo real.
echo.
echo   [0] 🚪 Salir
echo.
echo ==============================================================================
set /p "OPCION=  Ingrese una opcion [1, 2, 0]: "

if "%OPCION%"=="1" goto RUN_DETECCION
if "%OPCION%"=="2" goto RUN_WIFISENTRY
if "%OPCION%"=="0" goto SALIR

echo.
echo   [!] Opcion invalida. Intenta nuevamente...
timeout /t 2 >nul
goto MENU

:RUN_DETECCION
cls
echo ==============================================================================
echo   Iniciando Detección de Intrusos (Auditoria Forense de Eventos de Seguridad)...
echo ==============================================================================
echo.
call "%~dp0Detección de Intrusos\Ejecutar-Auditoria.bat"
goto MENU

:RUN_WIFISENTRY
cls
echo ==============================================================================
echo   Iniciando WiFiSentry (Suite Forense Inalambrica & Sensor RF)...
echo ==============================================================================
echo.
call "%~dp0WiFiSentry\Ejecutar-WiFiSentry.bat"
goto MENU

:SALIR
cls
echo Gracias por utilizar la Suite WinAudit-DFIR de Cru9.
timeout /t 2 >nul
exit /b 0
