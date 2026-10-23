<#
.SYNOPSIS
    MemSentry v3.0.0 - Framework Forense de Procesos en RAM, Inyección & LSASS Guard para Windows.
.DESCRIPTION
    Audita procesos en ejecución, árbol padre-hijo, masquerading de binarios de sistema,
    protección de credenciales en LSASS (RunAsPPL) y rutas de servicio sin entrecomillar.
.AUTHOR
    Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v3.0.0
.LINK
    https://github.com/Cru9/WinAudit-DFIR
#>

[CmdletBinding()]
param(
    [switch]$SoloTriage,
    [switch]$SoloLSASS,
    [switch]$SoloServicios,
    [string]$ExportarJSON = "",
    [string]$ExportarHTML = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reportes"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

function Show-MemBanner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "  __  __                 _____             _              " -ForegroundColor Cyan
    Write-Host " |  \/  |               / ____|           | |             " -ForegroundColor Cyan
    Write-Host " | \  / | ___ _ __ ___ | (___   ___ _ __ | |_ _ __ _   _ " -ForegroundColor Cyan
    Write-Host " | |\/| |/ _ \ '_ ` _ \ \___ \ / _ \ '_ \| __| '__| | | |" -ForegroundColor Cyan
    Write-Host " | |  | |  __/ | | | | |____) |  __/ | | | |_| |  | |_| |" -ForegroundColor Cyan
    Write-Host " |_|  |_|\___|_| |_| |_|_____/ \___|_| |_|\__|_|   \__, |" -ForegroundColor Cyan
    Write-Host "                                                   |___/ " -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Magenta
    Write-Host "  Framework Forense de Procesos en RAM, Inyección & LSASS Guard | v3.0.0" -ForegroundColor White
    Write-Host "  Ecosistema Cru9 | Process Tree, Masquerading & Credential Protection" -ForegroundColor DarkGray
    Write-Host "==============================================================================`n" -ForegroundColor Magenta
}

function Audit-LSASSGuard {
    $results = @()
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ppl = Get-ItemProperty -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue
    $pplVal = if ($ppl) { $ppl.RunAsPPL } else { 0 }
    
    $status = if ($pplVal -ge 1) { "SECURE" } else { "VULNERABLE" }
    $results += [PSCustomObject]@{
        Check       = "LSASS RunAsPPL"
        Status      = $status
        Value       = $pplVal
        Description = if ($pplVal -ge 1) { "LSASS protegido contra inyección de DLL y volcados de memoria (Mimikatz bloqueado)." } else { "LSASS desprotegido. Se recomienda activar RunAsPPL." }
    }
    return $results
}

function Audit-UnquotedServices {
    $vulnerable = @()
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($s in $services) {
        $p = $s.PathName
        if ($p -and $p.Trim().Length -gt 0 -and (-not $p.StartsWith('"'))) {
            $m = [regex]::Match($p, '^([^.]+\.exe)')
            $exePart = if ($m.Success) { $m.Groups[1].Value } else { $p }
            if ($exePart.Contains(' ') -and (-not $exePart.ToLower().StartsWith('c:\windows\system32'))) {
                $vulnerable += [PSCustomObject]@{
                    ServiceName = $s.Name
                    PathName    = $p
                    Vulnerable  = $exePart
                }
            }
        }
    }
    return $vulnerable
}

function Run-MemTriage {
    Write-Host "[*] Auditando proteccion criptografica de LSASS en el registro..." -ForegroundColor Cyan
    $lsass = Audit-LSASSGuard
    foreach ($l in $lsass) {
        $color = if ($l.Status -eq "SECURE") { "Green" } else { "Red" }
        Write-Host "  [+] $($l.Check): $($l.Status) (Valor: $($l.Value))" -ForegroundColor $color
    }

    Write-Host "`n[*] Escaneando servicios en busca de rutas sin entrecomillar..." -ForegroundColor Cyan
    $unquoted = Audit-UnquotedServices
    Write-Host "  [+] Servicios vulnerables detectados: $($unquoted.Count)" -ForegroundColor $(if ($unquoted.Count -gt 0) { "Yellow" } else { "Green" })
    if ($unquoted.Count -gt 0) {
        $unquoted | Select-Object -First 10 ServiceName, Vulnerable | Format-Table -AutoSize
    }

    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        Write-Host "`n[*] Ejecutando análisis profundo de procesos en Python 3..." -ForegroundColor Cyan
        & python (Join-Path $ScriptDir "MemSentry.py") --all
    } else {
        Write-Host "`n[*] Python no detectado. Obteniendo procesos en ejecucion..." -ForegroundColor Yellow
        Get-CimInstance Win32_Process | Select-Object -First 25 ProcessId, ParentProcessId, Name, Path | Format-Table -AutoSize
    }
}

# Flujo Principal
if ($SoloTriage -or $SoloLSASS -or $SoloServicios) {
    Run-MemTriage
    exit 0
}

# Modo Interactivo
do {
    Show-MemBanner
    Write-Host "  [1] Triage Forense Completo (Procesos en RAM + LSASS + Servicios)" -ForegroundColor Cyan
    Write-Host "  [2] Inspección de Seguridad LSASS Guard (RunAsPPL & Credenciales)" -ForegroundColor Cyan
    Write-Host "  [3] Scanner de Rutas de Servicio sin Comillas (Unquoted Paths)" -ForegroundColor Cyan
    Write-Host "  [0] Salir" -ForegroundColor Red
    Write-Host ""
    $opc = Read-Host "  Selecciona una opción [0-3]"

    switch ($opc) {
        "1" { Run-MemTriage; Read-Host "`nPresiona Enter para continuar..." }
        "2" {
            $l = Audit-LSASSGuard
            $l | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
        "3" {
            $u = Audit-UnquotedServices
            Write-Host "[+] Servicios vulnerables: $($u.Count)" -ForegroundColor Yellow
            $u | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
    }
} while ($opc -ne "0")
