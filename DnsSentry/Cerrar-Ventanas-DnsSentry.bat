@echo off
title Cerrar Ventanas de DnsSentry
taskkill /F /FI "WINDOWTITLE eq *DnsSentry*" /T >nul 2>&1
echo [✓] Ventanas de DnsSentry cerradas correctamente.
timeout /t 2 >nul 2>&1 || ping 127.0.0.1 -n 3 >nul
exit /b 0
