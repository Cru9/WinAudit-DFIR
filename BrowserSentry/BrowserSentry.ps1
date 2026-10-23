<#
.SYNOPSIS
    BrowserSentry v3.0.0 - Framework Forense de Navegadores Web y Descargas para Windows.
.DESCRIPTION
    Audita y extrae evidencias de navegación web, descargas recientes y extensiones instaladas:
    - Google Chrome, Microsoft Edge, Brave Browser y Mozilla Firefox.
    - Detección de descargas de alto riesgo (.iso, .vhd, .exe, .scr, .bat, .ps1).
    - Caza de visitas a servicios de túnel dinámico (DuckDNS, Ngrok, Serveo, Cloudflare Tunnels).
    - Copia segura de bases de datos SQLite bloqueadas mediante volumen temporal.
.AUTHOR
    Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v3.0.0
.LINK
    https://github.com/Cru9/WinAudit-DFIR
#>

[CmdletBinding()]
param(
    [switch]$SoloTriage,
    [switch]$SoloDescargas,
    [switch]$SoloExtensiones,
    [string]$ExportarJSON = "",
    [string]$ExportarHTML = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reportes"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

function Show-BrowserBanner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "   ____                                   _____             _              " -ForegroundColor Cyan
    Write-Host "  |  _ \                                 / ____|           | |             " -ForegroundColor Cyan
    Write-Host "  | |_) |_ __ _____      _____  ___ _ __| (___   ___ _ __ | |_ _ __ _   _ " -ForegroundColor Cyan
    Write-Host "  |  _ <| '__/ _ \ \ /\ / / __|/ _ \ '__\___ \ / _ \ '_ \| __| '__| | | |" -ForegroundColor Cyan
    Write-Host "  | |_) | | | (_) \ V  V /\__ \  __/ |  ____) |  __/ | | | |_| |  | |_| |" -ForegroundColor Cyan
    Write-Host "  |____/|_|  \___/ \_/\_/ |___/\___|_| |_____/ \___|_| |_|\__|_|   \__, |" -ForegroundColor Cyan
    Write-Host "                                                                   |___/ " -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Magenta
    Write-Host "  Framework Forense de Navegadores Web y Descargas | v3.0.0" -ForegroundColor White
    Write-Host "  Ecosistema Cru9 | Chrome, Edge, Brave & Firefox | Multi-Profile Triage" -ForegroundColor DarkGray
    Write-Host "==============================================================================`n" -ForegroundColor Magenta
}

function Get-BrowserInstallations {
    $browsers = @()
    $localApp = $env:LOCALAPPDATA
    
    $paths = @(
        @{ Name = "Google Chrome"; Path = Join-Path $localApp "Google\Chrome\User Data" },
        @{ Name = "Microsoft Edge"; Path = Join-Path $localApp "Microsoft\Edge\User Data" },
        @{ Name = "Brave Browser"; Path = Join-Path $localApp "BraveSoftware\Brave-Browser\User Data" }
    )
    
    foreach ($p in $paths) {
        if (Test-Path $p.Path) {
            $profiles = @("Default")
            Get-ChildItem -Path $p.Path -Directory | Where-Object { $_.Name -like "Profile *" } | ForEach-Object { $profiles += $_.Name }
            foreach ($prof in $profiles) {
                $hist = Join-Path (Join-Path $p.Path $prof) "History"
                $exts = Join-Path (Join-Path $p.Path $prof) "Extensions"
                if (Test-Path $hist) {
                    $browsers += [PSCustomObject]@{
                        Browser   = $p.Name
                        Profile   = $prof
                        HistoryDb = $hist
                        ExtsDir   = if (Test-Path $exts) { $exts } else { $null }
                    }
                }
            }
        }
    }
    return $browsers
}

function Audit-DownloadsFolder {
    # Respaldo forense rápido de la carpeta Descargas del usuario
    $dlPath = Join-Path $env:USERPROFILE "Downloads"
    $results = @()
    if (Test-Path $dlPath) {
        $files = Get-ChildItem -Path $dlPath -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 50
        $dangerExts = @(".iso", ".vhd", ".img", ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".msi")
        foreach ($f in $files) {
            $risk = "CLEAN"
            $reason = "Archivo descargado habitual"
            if ($f.Extension.ToLower() -in $dangerExts) {
                $risk = "CRITICAL"
                $reason = "Ejecutable o contenedor de disco potencialmente peligroso"
            } elseif ($f.Extension.ToLower() -in @(".zip", ".rar", ".7z")) {
                $risk = "MEDIUM"
                $reason = "Archivo comprimido (posible vector de transporte)"
            }
            $results += [PSCustomObject]@{
                Filename      = $f.Name
                Extension     = $f.Extension
                SizeMB        = [math]::Round($f.Length / 1MB, 2)
                LastModified  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                RiskLevel     = $risk
                Reason        = $reason
            }
        }
    }
    return $results
}

function Run-BrowserTriage {
    Write-Host "[*] Detectando navegadores instalados en el sistema..." -ForegroundColor Cyan
    $installed = Get-BrowserInstallations
    foreach ($b in $installed) {
        Write-Host "  [+] Navegador encontrado: $($b.Browser) ($($b.Profile))" -ForegroundColor Green
    }
    
    # Si Python esta disponible, delegar la consulta SQLite profunda
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        Write-Host "`n[*] Ejecutando motor forense SQLite avanzado en Python 3..." -ForegroundColor Cyan
        $pyScript = Join-Path $ScriptDir "BrowserSentry.py"
        & python $pyScript --all
    } else {
        Write-Host "`n[*] Python no detectado en el PATH. Auditando evidencias de descargas directas..." -ForegroundColor Yellow
        $dls = Audit-DownloadsFolder
        Write-Host "[+] Archivos en carpeta Downloads: $($dls.Count)" -ForegroundColor Green
        $danger = $dls | Where-Object { $_.RiskLevel -eq "CRITICAL" }
        if ($danger) {
            Write-Host "`n[!] ALERTA: $($danger.Count) ARCHIVOS PELIGROSOS EN CARPETA DOWNLOADS:" -ForegroundColor Red
            $danger | Format-Table -AutoSize
        }
    }
}

# Flujo Principal
if ($SoloTriage -or $SoloDescargas -or $SoloExtensiones) {
    Run-BrowserTriage
    exit 0
}

# Modo Interactivo
do {
    Show-BrowserBanner
    $inst = Get-BrowserInstallations
    Write-Host "  NAVEGADORES DETECTADOS:" -ForegroundColor White
    foreach ($i in $inst) {
        Write-Host "   • $($i.Browser) ($($i.Profile))" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "  [1] Triage Forense Completo (Descargas, Historial & Extensiones)" -ForegroundColor Cyan
    Write-Host "  [2] Auditoría de Descargas Recientes y Caza de Payloads (.exe, .iso, .ps1)" -ForegroundColor Cyan
    Write-Host "  [3] Inspección de Extensiones Instaladas" -ForegroundColor Cyan
    Write-Host "  [0] Salir" -ForegroundColor Red
    Write-Host ""
    $opc = Read-Host "  Selecciona una opción [0-3]"
    
    switch ($opc) {
        "1" { Run-BrowserTriage; Read-Host "`nPresiona Enter para continuar..." }
        "2" {
            $py = Get-Command python -ErrorAction SilentlyContinue
            if ($py) {
                & python (Join-Path $ScriptDir "BrowserSentry.py")
            } else {
                $d = Audit-DownloadsFolder
                $d | Format-Table -AutoSize
                Read-Host "`nPresiona Enter para continuar..."
            }
        }
        "3" {
            $inst = Get-BrowserInstallations
            foreach ($b in $inst) {
                if ($b.ExtsDir -and (Test-Path $b.ExtsDir)) {
                    Write-Host "`nExtensiones en $($b.Browser) ($($b.Profile)):" -ForegroundColor Yellow
                    Get-ChildItem -Path $b.ExtsDir -Directory | Select-Object Name | Format-Table -AutoSize
                }
            }
            Read-Host "`nPresiona Enter para continuar..."
        }
    }
} while ($opc -ne "0")
