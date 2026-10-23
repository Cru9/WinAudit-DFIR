@echo off
:: ==============================================================================
:: Cerrar-Ventanas-ExecSentry - Cerrar ventanas y procesos de ExecSentry
:: Autor: Ezequiel Diaz (Cru9) | WinAudit-DFIR Suite
:: ==============================================================================

echo [*] Cerrando sesiones activas de ExecSentry...
taskkill /f /fi "WINDOWTITLE eq ExecSentry*" >nul 2>&1
taskkill /f /im ExecSentry.exe >nul 2>&1
echo [+] Ventanas de ExecSentry cerradas con exito.
timeout /t 2 >nul
