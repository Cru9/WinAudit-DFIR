@echo off
:: ==============================================================================
:: WinAudit-DFIR - Master Forensic & Incident Response Suite
:: Autor: Ezequiel Diaz (Cru9) | Version: v2.0.0
:: ==============================================================================
setlocal
chcp 65001 >nul 2>&1
mode con: cols=105 lines=38 >nul 2>&1
title WinAudit-DFIR Suite v2.0.0 [Cru9 DFIR Ecosystem]
cd /d "%~dp0"

:: -----------------------------------------------------------------------------
:: Inicializar tokens de formato ANSI (VT100)
:: -----------------------------------------------------------------------------
for /f %%A in ('powershell -NoProfile -Command "[char]27"') do set "ESC=%%A"
set "C_RESET=%ESC%[0m"
set "C_BOLD=%ESC%[1m"
set "C_DIM=%ESC%[2m"
set "C_CYAN=%ESC%[96m"
set "C_BLUE=%ESC%[94m"
set "C_GREEN=%ESC%[92m"
set "C_YELLOW=%ESC%[93m"
set "C_RED=%ESC%[91m"
set "C_MAGENTA=%ESC%[95m"
set "C_WHITE=%ESC%[97m"
set "C_GRAY=%ESC%[90m"

:: -----------------------------------------------------------------------------
:: Auto-elevacion con privilegios de Administrador (UAC)
:: -----------------------------------------------------------------------------
if "%~1"=="-elevated" goto :MENU
net session >nul 2>&1
if %errorLevel% equ 0 goto :MENU

cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CONTROL DE ACCESO FORENSE ^| WinAudit-DFIR                                                  %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
echo   %C_CYAN%[*]%C_WHITE% Solicitando privilegios de %C_BOLD%%C_GREEN%Administrador%C_RESET% para analisis de bajo nivel y Security Log...
echo   %C_GRAY%    (Confirme 'Si' en el cuadro de dialogo de elevacion UAC de Windows)%C_RESET%
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '-elevated' -Verb RunAs } catch { exit 1 }" >nul 2>&1
if %errorLevel% equ 0 exit /b

echo   %C_YELLOW%[!] Permisos de Administrador omitidos. Iniciando sesion con privilegios de usuario estandar...%C_RESET%
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul

:MENU
cd /d "%~dp0"
cls

:: Deteccion de estado de privilegios
net session >nul 2>&1
if %errorLevel% equ 0 (
    set "PRIV_LABEL=%C_BOLD%%C_GREEN%[ ADMINISTRADOR ]%C_RESET%"
) else (
    set "PRIV_LABEL=%C_BOLD%%C_YELLOW%[ USUARIO ESTANDAR ]%C_RESET%"
)

:: Deteccion de runtime activo (Python o PowerShell nativo)
where python >nul 2>&1
if %errorLevel% equ 0 (
    set "RUNTIME_LABEL=%C_BOLD%%C_CYAN%Python 3 Detectado%C_RESET%"
) else (
    set "RUNTIME_LABEL=%C_BOLD%%C_YELLOW%PowerShell Nativo%C_RESET%"
)

echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%__          ___             __             _ _ _      _____  ______ _____ _____                 %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%\ \        / (_)           /\ \           ^| (_) ^|    ^|  __ \^|  ____^|_   _^|  __ \                %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE% \ \  /\  / / _ _ __      /  \ \ _   _  __^| ^|_^| ^|_   ^| ^|  ^| ^| ^|__    ^| ^| ^| ^|__) ^|               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%  \ \/  \/ / ^| ^| '_ \    / /\ \ ^| ^| ^| ^|/ _` ^| ^| __^|  ^| ^|  ^| ^|  __^|   ^| ^| ^|  _  /                %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%   \  /\  /  ^| ^| ^| ^| ^|  / ____ \^| ^|_^| ^| (_^| ^| ^| ^|_   ^| ^|__^| ^| ^|     _^| ^|_^| ^| \ \                %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%    \/  \/   ^|_^|_^| ^|_^| /_/    \_\\__,_^|\__,_^|_^|\__^|  ^|_____/^|_^|    ^|_____^|_^|  \_^|               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|                                                                                                  ^|%C_RESET%
echo  %C_CYAN%^|             %C_BOLD%%C_CYAN%DFIR CYBERSECURITY ECOSYSTEM %C_GRAY%v2.0.0  %C_WHITE%^|  %C_MAGENTA%DEVELOPED BY CRU9                             %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo   %C_GRAY%[+] HOST:%C_WHITE% %COMPUTERNAME%  %C_GRAY%^|  USUARIO:%C_WHITE% %USERNAME%  %C_GRAY%^|  ESTADO: %PRIV_LABEL%  %C_GRAY%^|  MOTOR: %RUNTIME_LABEL%
echo.
echo  %C_BLUE%.--------------------------------------------------------------------------------------------------.%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[ MODULOS DE AUDITORIA ^& RESPUESTA A INCIDENTES ]                   %C_GRAY%[ WINDFIR ECOSYSTEM v2.0.0 ]%C_BLUE%  ^|%C_RESET%
echo  %C_BLUE%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[1]%C_RESET%  %C_BOLD%%C_CYAN%Deteccion de Intrusos %C_GRAY%(IntruderDetector v2.0.0)%C_RESET%                                             %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Triage forense de host, eventos de seguridad (Security Log) y fuerza bruta.               %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Analisis de Event IDs (1102, 4625, 4624, 4720), fuerza bruta RDP y LOLBins.              %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[2]%C_RESET%  %C_BOLD%%C_CYAN%WiFiSentry %C_GRAY%(Wireless Forensic Suite ^& RF Sensor v2.0.0)%C_RESET%                                     %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Rogue AP Hunter: deteccion en tiempo real de ataques Evil Twin y BSSID clonados.         %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Benchmark de entropia PBKDF2 (GPU Hashcat) y sensor de proximidad RF en vivo.            %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[3]%C_RESET%  %C_BOLD%%C_CYAN%SocketSentry %C_GRAY%(Network Sockets ^& Threat Hunter v2.0.0)%C_RESET%                                       %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Inspeccion forense de sockets TCP/UDP y procesos sospechosos en memoria.                 %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Deteccion de balizas C2 (Beaconing), servidores Feodo y LOLBins en red.                  %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[4]%C_RESET%  %C_BOLD%%C_CYAN%StartupSentry %C_GRAY%(Autostart ^& Task Persistence Hunter v2.0.0)%C_RESET%                                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Auditoria de programas de arranque, claves Run/RunOnce y firmas Authenticode.             %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Deteccion de tareas programadas raiz (\), gatillos recurrentes y masquerading.           %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[5]%C_RESET%  %C_BOLD%%C_CYAN%UsbSentry %C_GRAY%(USB Storage Forensics ^& BadUSB Hunter v2.0.0)%C_RESET%                                  %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Historial USBSTOR, correlacion de letras de unidad (MountedDevices) y seriales.          %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Deteccion de inyectores de pulsaciones BadUSB (Rubber Ducky, Flipper Zero, emuladores).   %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[6]%C_RESET%  %C_BOLD%%C_YELLOW%Explorador de Evidencias %C_GRAY%(Abrir Directorios de Reportes DFIR)%C_RESET%                               %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|       %C_GRAY%- Visualizar dashboards HTML interactivos, evidencias en JSON y tablas CSV.                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_RED%[0]%C_RESET%  %C_BOLD%%C_WHITE%Finalizar Sesion Forense %C_GRAY%(Cerrar Suite DFIR)%C_RESET%                                                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%'--------------------------------------------------------------------------------------------------'%C_RESET%
echo.

set "OPCION="
set /p "OPCION=  %C_BOLD%%C_CYAN%Cru9@WinAudit-DFIR%C_WHITE% [%C_GREEN%DFIR-CONSOLE%C_WHITE%] %C_CYAN%>> %C_RESET%"

if not defined OPCION goto MENU
set "OPCION=%OPCION: =%"

if "%OPCION%"=="1" goto RUN_DETECCION
if "%OPCION%"=="2" goto RUN_WIFISENTRY
if "%OPCION%"=="3" goto RUN_SOCKETSENTRY
if "%OPCION%"=="4" goto RUN_STARTUPSENTRY
if "%OPCION%"=="5" goto RUN_USBSENTRY
if "%OPCION%"=="6" goto RUN_REPORTES
if "%OPCION%"=="0" goto SALIR

echo.
echo   %C_YELLOW%[!] Opcion invalida '%OPCION%'. Por favor seleccione [1, 2, 3, 4, 5, 6 o 0]...%C_RESET%
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul
goto MENU

:RUN_DETECCION
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%IntruderDetector v2.0.0 (Deteccion de Intrusos)                               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando triage forense de host, persistencia y eventos de seguridad...                        %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
set "DETECCION_BAT="
for /d %%I in ("%~dp0*Intrusos") do (
    if exist "%%~fI\Ejecutar-Deteccion.bat" set "DETECCION_BAT=%%~fI\Ejecutar-Deteccion.bat"
)
if not defined DETECCION_BAT (
    for /d %%I in (*Intrusos) do (
        if exist "%%~fI\Ejecutar-Deteccion.bat" set "DETECCION_BAT=%%~fI\Ejecutar-Deteccion.bat"
    )
)
if not defined DETECCION_BAT if exist "%~dp0DETECC~1\Ejecutar-Deteccion.bat" (
    set "DETECCION_BAT=%~dp0DETECC~1\Ejecutar-Deteccion.bat"
)
if defined DETECCION_BAT (
    call "%DETECCION_BAT%" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-Deteccion.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_WIFISENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%WiFiSentry v2.0.0 (Auditoria Forense Inalambrica 802.11)                        %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando Rogue AP Hunter, benchmark PBKDF2 y sensor RF en tiempo real...                      %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0WiFiSentry\Ejecutar-WiFiSentry.bat" (
    call "%~dp0WiFiSentry\Ejecutar-WiFiSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-WiFiSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_SOCKETSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%SocketSentry v2.0.0 (Threat Hunting de Red ^& Sockets)                          %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando inspeccion de sockets, deteccion de balizas C2 y amenazas en red...                  %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0SocketSentry\Ejecutar-SocketSentry.bat" (
    call "%~dp0SocketSentry\Ejecutar-SocketSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-SocketSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_STARTUPSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%StartupSentry v2.0.0 (Persistencia, Tareas y Firmas Authenticode)              %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando triage de programas de arranque, tareas raiz y validacion criptografica...          %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0StartupSentry\Ejecutar-StartupSentry.bat" (
    call "%~dp0StartupSentry\Ejecutar-StartupSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-StartupSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_USBSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%UsbSentry v2.0.0 (Forense de Almacenamiento USB ^& BadUSB Hunter)               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando historial USBSTOR, MountedDevices y deteccion de inyectores de hardware...          %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0UsbSentry\Ejecutar-UsbSentry.bat" (
    call "%~dp0UsbSentry\Ejecutar-UsbSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-UsbSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_REPORTES
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%EXPLORADOR DE EVIDENCIAS Y REPORTES FORENSES                                                   %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
echo   %C_CYAN%[*]%C_WHITE% Accediendo a los directorios de evidencias y reportes forenses...%C_RESET%
set "OPENED=0"
for /d %%I in ("%~dp0*Intrusos\Reportes") do (
    if exist "%%~fI" (
        start "" explorer "%%~fI"
        set "OPENED=1"
    )
)
if exist "%~dp0WiFiSentry\Reportes" (
    start "" explorer "%~dp0WiFiSentry\Reportes"
    set "OPENED=1"
)
if exist "%~dp0SocketSentry\Reportes" (
    start "" explorer "%~dp0SocketSentry\Reportes"
    set "OPENED=1"
)
if exist "%~dp0StartupSentry\Reportes" (
    start "" explorer "%~dp0StartupSentry\Reportes"
    set "OPENED=1"
)
if exist "%~dp0UsbSentry\Reportes" (
    start "" explorer "%~dp0UsbSentry\Reportes"
    set "OPENED=1"
)
if "%OPENED%"=="0" (
    echo   %C_YELLOW%[i] Aun no se han generado reportes forenses. Abriendo carpeta principal del proyecto...%C_RESET%
    start "" explorer "%~dp0"
)
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul
goto MENU

:SALIR
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%WinAudit-DFIR Master Suite ^| Cru9 Cybersecurity Engineering                               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
echo   %C_GREEN%[+] Sesion finalizada correctamente.%C_RESET%
echo   %C_GRAY%Gracias por utilizar WinAudit-DFIR. Manteniendo la seguridad y custodia de evidencias.%C_RESET%
echo.
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul
exit /b 0
