@echo off
:: ==============================================================================
:: Sincronizador Automatizado de GitHub Wiki - WinAudit-DFIR (Cru9)
:: ==============================================================================
chcp 65001 >nul
title WinAudit-DFIR - Sincronizador de GitHub Wiki
cd /d "%~dp0"

echo ==============================================================================
echo [i] Sincronizador de Documentación de GitHub Wiki - WinAudit-DFIR (Cru9)
echo ==============================================================================
echo.

:: 1. Verificar si git está instalado
where git >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: Git no está instalado o no se encuentra en el PATH.
    goto :FIN
)

echo [*] Repositorio Wiki destino: https://github.com/Cru9/WinAudit-DFIR.wiki.git
echo.
echo Recuerda que para que este script funcione:
echo 1. Debes haber activado la Wiki en GitHub (Settings -^> Features -^> Wikis).
echo 2. Debes haber hecho clic al menos una vez en 'Create the first page' en:
echo    https://github.com/Cru9/WinAudit-DFIR/wiki
echo.

set /p RESP="¿Deseas clonar y sincronizar todas las páginas de la Wiki ahora? (S/N): "
if /i not "%RESP%"=="S" (
    echo [!] Operación cancelada por el usuario.
    goto :FIN
)

echo.
echo [*] Clonando repositorio de la Wiki en carpeta temporal...
if exist "%TEMP%\WinAudit-DFIR.wiki" rmdir /s /q "%TEMP%\WinAudit-DFIR.wiki"

git clone https://github.com/Cru9/WinAudit-DFIR.wiki.git "%TEMP%\WinAudit-DFIR.wiki"
if %errorLevel% neq 0 (
    echo.
    echo [!] ERROR: No se pudo clonar el repositorio de la wiki.
    echo Asegúrate de haber entrado a https://github.com/Cru9/WinAudit-DFIR/wiki
    echo y haber pulsado 'Create the first page' al menos una vez.
    goto :FIN
)

echo.
echo [*] Copiando páginas Markdown de la Wiki...
xcopy /y /q "%~dp0*.md" "%TEMP%\WinAudit-DFIR.wiki\"

cd /d "%TEMP%\WinAudit-DFIR.wiki"
git add .
git status --short

git commit -m "docs(wiki): sync official manuals, architecture and forensic methodology"
if %errorLevel% equ 0 (
    echo.
    echo [*] Subiendo cambios a GitHub Wiki...
    git push origin master
    if %errorLevel% neq 0 (
        git push origin main
    )
    echo.
    echo [✓] ¡Wiki sincronizada con éxito en https://github.com/Cru9/WinAudit-DFIR/wiki!
) else (
    echo.
    echo [i] No se detectaron cambios pendientes para subir a la Wiki.
)

:: Limpieza
cd /d "%~dp0"
rmdir /s /q "%TEMP%\WinAudit-DFIR.wiki" 2>nul

:FIN
echo.
echo Presiona cualquier tecla para salir...
pause >nul
