@echo off
:: ==============================================================================
:: Cerrar-Ventanas-MemSentry - Cerrar ventanas y procesos de MemSentry
:: Autor: Ezequiel Diaz (Cru9) | WinAudit-DFIR Suite
:: ==============================================================================

echo [*] Cerrando sesiones activas de MemSentry...
taskkill /f /fi "WINDOWTITLE eq MemSentry*" >nul 2>&1
taskkill /f /im MemSentry.exe >nul 2>&1
echo [+] Ventanas de MemSentry cerradas con exito.
timeout /t 2 >nul
