@echo off
:: ==============================================================================
:: WinAudit-DFIR - Master Forensic & Incident Response Suite
:: Autor: Ezequiel Diaz (Cru9) | Version: v3.0.0
:: ==============================================================================
setlocal
chcp 65001 >nul 2>&1
mode con: cols=105 lines=56 >nul 2>&1
title WinAudit-DFIR Suite v3.0.0 [Cru9 DFIR Ecosystem]
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

:: Deteccion de runtime activo
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
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%    \/  \/   ^|_^|_^| ^|_^| /_/    \_\__,_^|\__,_^|_^|\__^|  ^|_____/^|_^|    ^|_____^|_^|  \_^|               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|                                                                                                  ^|%C_RESET%
echo  %C_CYAN%^|             %C_BOLD%%C_CYAN%DFIR CYBERSECURITY ECOSYSTEM %C_GRAY%v3.0.0  %C_WHITE%^|  %C_MAGENTA%DEVELOPED BY CRU9                             %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo   %C_GRAY%[+] HOST:%C_WHITE% %COMPUTERNAME%  %C_GRAY%^|  USUARIO:%C_WHITE% %USERNAME%  %C_GRAY%^|  ESTADO: %PRIV_LABEL%  %C_GRAY%^|  MOTOR: %RUNTIME_LABEL%
echo.
echo  %C_BLUE%.--------------------------------------------------------------------------------------------------.%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[ MODULOS FORENSES ESPECIALIZADOS INDIVIDUALES ]                                                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[1]%C_RESET%  %C_BOLD%%C_CYAN%Deteccion de Intrusos %C_GRAY%(Security Log, Fuerza Bruta ^& SIEM Live Radar)%C_RESET%                       %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[2]%C_RESET%  %C_BOLD%%C_CYAN%WiFiSentry %C_GRAY%(Wireless Forensic Suite, Rogue AP Hunter ^& Entropia PBKDF2)%C_RESET%                     %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[3]%C_RESET%  %C_BOLD%%C_CYAN%SocketSentry %C_GRAY%(Threat Hunter de Red, Sockets TCP/UDP ^& Feodo C2 Beaconing)%C_RESET%                  %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[4]%C_RESET%  %C_BOLD%%C_CYAN%DnsSentry %C_GRAY%(Cache DNS en Vivo, DGA, Tuneles C2 ^& Manipulacion de Hosts)%C_RESET%                       %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[5]%C_RESET%  %C_BOLD%%C_CYAN%StartupSentry %C_GRAY%(Persistencia en Arranque, Tareas Raiz ^& Firmas Authenticode)%C_RESET%                  %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[6]%C_RESET%  %C_BOLD%%C_CYAN%UsbSentry %C_GRAY%(Forense USBSTOR, MountedDevices ^& Inyectores Hardware BadUSB)%C_RESET%                    %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[7]%C_RESET%  %C_BOLD%%C_CYAN%ExecSentry %C_GRAY%(Evidencia de Ejecucion: Prefetch, UserAssist, BAM ^& Shimcache)%C_RESET%                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[8]%C_RESET%  %C_BOLD%%C_CYAN%BrowserSentry %C_GRAY%(SQLite Forensics Multi-Navegador, Descargas Web ^& Extensiones)%C_RESET%             %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[9]%C_RESET%  %C_BOLD%%C_CYAN%MemSentry %C_GRAY%(Procesos en RAM, Linaje Padre-Hijo, Masquerading ^& LSASS Guard)%C_RESET%                 %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_WHITE%[P]%C_RESET%  %C_BOLD%%C_GREEN%Consola Python Nativa %C_GRAY%(Lanzar Orquestador Maestro Suite-DFIR.py)%C_RESET%                 %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|  %C_BOLD%%C_RED%[0]%C_RESET%  %C_BOLD%%C_WHITE%Finalizar Sesion Forense %C_GRAY%(Cerrar Suite DFIR)%C_RESET%                                                %C_BLUE%^|%C_RESET%
echo  %C_BLUE%^|                                                                                                  ^|%C_RESET%
echo  %C_BLUE%'--------------------------------------------------------------------------------------------------'%C_RESET%
echo.

set "OPCION="
set /p "OPCION=  %C_BOLD%%C_CYAN%Cru9@WinAudit-DFIR%C_WHITE% [%C_GREEN%DFIR-CONSOLE%C_WHITE%] %C_CYAN%>> %C_RESET%"

if not defined OPCION goto MENU
set "OPCION=%OPCION: =%"

if /i "%OPCION%"=="P" goto RUN_PYTHON_SUITE
if "%OPCION%"=="1" goto RUN_DETECCION
if "%OPCION%"=="2" goto RUN_WIFISENTRY
if "%OPCION%"=="3" goto RUN_SOCKETSENTRY
if "%OPCION%"=="4" goto RUN_DNSSENTRY
if "%OPCION%"=="5" goto RUN_STARTUPSENTRY
if "%OPCION%"=="6" goto RUN_USBSENTRY
if "%OPCION%"=="7" goto RUN_EXECSENTRY
if "%OPCION%"=="8" goto RUN_BROWSERSENTRY
if "%OPCION%"=="9" goto RUN_MEMSENTRY
if "%OPCION%"=="0" goto SALIR

echo.
echo   %C_YELLOW%[!] Opcion invalida '%OPCION%'. Por favor seleccione [P, 1 al 9 o 0]...%C_RESET%
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul
goto MENU

:RUN_DETECCION
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%IntruderDetector v3.0.0 (Deteccion de Intrusos)                               %C_CYAN%^|%C_RESET%
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
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%WiFiSentry v3.0.0 (Auditoria Forense Inalambrica 802.11)                        %C_CYAN%^|%C_RESET%
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
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%SocketSentry v3.0.0 (Threat Hunting de Red ^& Sockets)                          %C_CYAN%^|%C_RESET%
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

:RUN_DNSSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%DnsSentry v3.0.0 (Forense de Cache DNS, DGA ^& Archivo Hosts)                  %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando auditoria de cache DNS, deteccion de tuneles C2 y sinkholes en Hosts...               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0DnsSentry\Ejecutar-DnsSentry.bat" (
    call "%~dp0DnsSentry\Ejecutar-DnsSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-DnsSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_STARTUPSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%StartupSentry v3.0.0 (Persistencia, Tareas y Firmas Authenticode)              %C_CYAN%^|%C_RESET%
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
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%UsbSentry v3.0.0 (Forense de Almacenamiento USB ^& BadUSB Hunter)               %C_CYAN%^|%C_RESET%
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

:RUN_EXECSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%ExecSentry v3.0.0 (Prefetch, UserAssist, BAM ^& Shimcache Forensics)            %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando triage de ejecucion, deteccion de LOLBins y binarios borrados en disco...            %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0ExecSentry\Ejecutar-ExecSentry.bat" (
    call "%~dp0ExecSentry\Ejecutar-ExecSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-ExecSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_BROWSERSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%BrowserSentry v3.0.0 (Descargas, Historial Web ^& Extensiones)               %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando auditoria SQLite en vivo, deteccion de payloads (ISO/EXE) y tuneles C2...        %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0BrowserSentry\Ejecutar-BrowserSentry.bat" (
    call "%~dp0BrowserSentry\Ejecutar-BrowserSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-BrowserSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU

:RUN_MEMSENTRY
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%CARGANDO ENTORNO: %C_CYAN%MemSentry v3.0.0 (Procesos en RAM, Inyeccion ^& LSASS Guard)                 %C_CYAN%^|%C_RESET%
echo  %C_CYAN%^|  %C_GRAY%Iniciando auditoria de procesos en vivo, linaje padre-hijo, RunAsPPL y Unquoted Paths... %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0MemSentry\Ejecutar-MemSentry.bat" (
    call "%~dp0MemSentry\Ejecutar-MemSentry.bat" -elevated
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Ejecutar-MemSentry.bat en el repositorio.%C_RESET%
    pause
)
goto MENU


:RUN_PYTHON_SUITE
cls
echo.
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo  %C_CYAN%^|  %C_BOLD%%C_WHITE%LANZANDO ORQUESTADOR FORENSE MAESTRO EN PYTHON: %C_YELLOW%Suite-DFIR.py%C_RESET%                           %C_CYAN%^|%C_RESET%
echo  %C_CYAN%+--------------------------------------------------------------------------------------------------+%C_RESET%
echo.
if exist "%~dp0Suite-DFIR.py" (
    python "%~dp0Suite-DFIR.py"
) else (
    echo   %C_RED%[!] Error: No se encontro el archivo Suite-DFIR.py en el directorio.%C_RESET%
    pause
)
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
