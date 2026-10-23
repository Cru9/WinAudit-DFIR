@echo off
:: ==============================================================================
:: Cerrar-Ventanas-BrowserSentry - Cerrar ventanas y procesos de BrowserSentry
:: Autor: Ezequiel Diaz (Cru9) | WinAudit-DFIR Suite
:: ==============================================================================

echo [*] Cerrando sesiones activas de BrowserSentry...
taskkill /f /fi "WINDOWTITLE eq BrowserSentry*" >nul 2>&1
taskkill /f /im BrowserSentry.exe >nul 2>&1
echo [+] Ventanas de BrowserSentry cerradas con exito.
timeout /t 2 >nul
