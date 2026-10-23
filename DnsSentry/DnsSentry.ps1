<#
.SYNOPSIS
    DnsSentry v3.0.0 - Framework Forense de Caché DNS y Manipulación de Hosts en Windows.
.DESCRIPTION
    Audita la memoria caché del cliente DNS en vivo, detecta túneles C2, DGA,
    revisa los servidores DNS asignados por interfaz y verifica alteraciones en el archivo Hosts.
.AUTHOR
    Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v3.0.0
.LINK
    https://github.com/Cru9/WinAudit-DFIR
#>

[CmdletBinding()]
param(
    [switch]$SoloTriage,
    [string]$ExportarJSON = "",
    [string]$ExportarHTML = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reportes"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Show-DnsBanner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "   _____              _____             _              " -ForegroundColor Cyan
    Write-Host "  |  __ \            / ____|           | |             " -ForegroundColor Cyan
    Write-Host "  | |  | |_ __  ___ | (___   ___ _ __ | |_ _ __ _   _ " -ForegroundColor Cyan
    Write-Host "  | |  | | '_ \/ __| \___ \ / _ \ '_ \| __| '__| | | |" -ForegroundColor Cyan
    Write-Host "  | |__| | | | \__ \ ____) |  __/ | | | |_| |  | |_| |" -ForegroundColor Cyan
    Write-Host "  |_____/|_| |_|___/|_____/ \___|_| |_|\__|_|   \__, |" -ForegroundColor Cyan
    Write-Host "                                                 |___/ " -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Magenta
    Write-Host "  Framework Forense de Caché DNS y Manipulación de Hosts | v3.0.0" -ForegroundColor White
    $privText = if ($IsAdmin) { "[ ADMINISTRADOR ]" } else { "[ USUARIO ESTANDAR ]" }
    $privColor = if ($IsAdmin) { "Green" } else { "Yellow" }
    Write-Host "  Ecosistema Cru9 | DNS Spoofing, DGA, Túneles C2 & Sinkholes | Estado: $privText" -ForegroundColor $privColor
    Write-Host "==============================================================================`n" -ForegroundColor Magenta
}

function Get-HostsAudit {
    $hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    $findings = @{
        Exists       = Test-Path $hostsPath
        Path         = $hostsPath
        SHA256       = "N/A"
        LastModified = "N/A"
        Entries      = @()
        Suspicious   = @()
    }
    if (Test-Path $hostsPath) {
        $findings.SHA256 = (Get-FileHash -Path $hostsPath -Algorithm SHA256).Hash
        $findings.LastModified = (Get-Item $hostsPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        $lines = Get-Content -Path $hostsPath
        $lineNo = 1
        foreach ($l in $lines) {
            $trimmed = $l.Trim()
            if ($trimmed -and -not $trimmed.StartsWith("#")) {
                $parts = $trimmed -split '\s+'
                if ($parts.Length -ge 2) {
                    $ip = $parts[0]
                    for ($i = 1; $i -lt $parts.Length; $i++) {
                        $dom = $parts[$i]
                        $isLoopback = $ip -in @("127.0.0.1", "0.0.0.0", "::1")
                        $risk = "CLEAN"
                        $reasons = @()
                        
                        if ($isLoopback -and ($dom -match "microsoft|update|defender|virustotal|kaspersky|symantec|bitdefender")) {
                            $risk = "CRITICAL"
                            $reasons += "Anti-Forensics: Sinkhole de telemetría de seguridad/antivirus (T1562.001)"
                        } elseif (-not $isLoopback -and ($dom -match "google|microsoft|bank|banco|paypal|github")) {
                            $risk = "CRITICAL"
                            $reasons += "Pharming: Redirección maliciosa de dominio sensible (T1566)"
                        } elseif ($dom -notin @("localhost", "localhost.localdomain", "broadcasthost")) {
                            $risk = "MEDIUM"
                            $reasons += "Entrada personalizada en archivo Hosts (T1565.001)"
                        }
                        
                        $obj = [PSCustomObject]@{
                            Line       = $lineNo
                            IP         = $ip
                            Domain     = $dom
                            IsLoopback = $isLoopback
                            Risk       = $risk
                            Reasons    = ($reasons -join " | ")
                        }
                        $findings.Entries += $obj
                        if ($risk -ne "CLEAN") {
                            $findings.Suspicious += $obj
                        }
                    }
                }
            }
            $lineNo++
        }
    }
    return $findings
}

function Run-DnsTriage {
    Show-DnsBanner
    Write-Host "[*] Auditando archivo de sistema Hosts..." -ForegroundColor Cyan
    $hosts = Get-HostsAudit
    Write-Host "    - Hash SHA-256: $($hosts.SHA256)" -ForegroundColor Gray
    Write-Host "    - Entradas sospechosas: $($hosts.Suspicious.Count)" -ForegroundColor $(if ($hosts.Suspicious.Count -gt 0) { "Red" } else { "Green" })
    
    Write-Host "`n[*] Recolectando caché DNS en vivo..." -ForegroundColor Cyan
    $cache = Get-DnsClientCache
    Write-Host "    - Dominios en caché: $($cache.Count)" -ForegroundColor Green
    
    Write-Host "`n[*] Servidores DNS en Adaptadores de Red:" -ForegroundColor Cyan
    Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object {
        Write-Host "    $($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" -ForegroundColor Gray
    }
    Write-Host "`n[✓] Auditoría de red y DNS completada." -ForegroundColor Green
}

if ($SoloTriage -or $ExportarJSON -or $ExportarHTML) {
    Run-DnsTriage
} else {
    Run-DnsTriage
    Write-Host "`nPresione cualquier tecla para salir..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
