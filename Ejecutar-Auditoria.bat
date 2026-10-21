@echo off
title Auditoria de Seguridad Windows
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Auditoria-Seguridad.ps1"
echo.
pause
