<#
.SYNOPSIS
    ExecSentry v3.0.0 - Framework Forense de Evidencia de Ejecución en Windows.
.DESCRIPTION
    Extrae, correlaciona y analiza rastros forenses de programas ejecutados en el sistema operativo:
    - UserAssist (Claves de registro ofuscadas en ROT13, conteo de ejecuciones y fecha exacta).
    - BAM / DAM (Background & Desktop Activity Moderator en HKLM por SID de usuario).
    - Windows Prefetch (Metadatos de archivos .pf, hashes y marcas temporales de ejecución).
    - Detección heurística de LOLBins, herramientas ofensivas y binarios ejecutados desde rutas temporales.
.AUTHOR
    Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v3.0.0
.LINK
    https://github.com/Cru9/WinAudit-DFIR
#>

[CmdletBinding()]
param(
    [switch]$SoloTriage,
    [switch]$UserAssist,
    [switch]$BAM,
    [switch]$Prefetch,
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

function Show-ExecBanner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "   ______               _____             _              " -ForegroundColor Cyan
    Write-Host "  |  ____|             / ____|           | |             " -ForegroundColor Cyan
    Write-Host "  | |__  __  _____  __| (___   ___ _ __ | |_ _ __ _   _ " -ForegroundColor Cyan
    Write-Host "  |  __| \ \/ / _ \/ __\___ \ / _ \ '_ \| __| '__| | | |" -ForegroundColor Cyan
    Write-Host "  | |____ >  <  __/ (__ ____) |  __/ | | | |_| |  | |_| |" -ForegroundColor Cyan
    Write-Host "  |______/_/\_\___|\___|_____/ \___|_| |_|\__|_|   \__, |" -ForegroundColor Cyan
    Write-Host "                                                   |___/ " -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Magenta
    Write-Host "  Framework Forense de Evidencia de Ejecución en Windows | v3.0.0" -ForegroundColor White
    $privText = if ($IsAdmin) { "[ ADMINISTRADOR ]" } else { "[ USUARIO ESTANDAR ]" }
    $privColor = if ($IsAdmin) { "Green" } else { "Yellow" }
    Write-Host "  Ecosistema Cru9 | Prefetch, UserAssist (ROT13) & BAM | Estado: $privText" -ForegroundColor $privColor
    Write-Host "==============================================================================`n" -ForegroundColor Magenta
}

function ConvertFrom-Rot13 {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 65 -and $c -le 90) {
            $chars[$i] = [char]((($c - 65 + 13) % 26) + 65)
        } elseif ($c -ge 97 -and $c -le 122) {
            $chars[$i] = [char]((($c - 97 + 13) % 26) + 97)
        }
    }
    return -join $chars
}

function Get-UserAssistEvidence {
    $results = @()
    $basePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (Test-Path $basePath) {
        $subkeys = Get-ChildItem -Path $basePath
        foreach ($k in $subkeys) {
            $countPath = Join-Path $k.PSPath "Count"
            if (Test-Path $countPath) {
                $item = Get-Item -Path $countPath
                foreach ($valName in $item.GetValueNames()) {
                    $decoded = ConvertFrom-Rot13 $valName
                    if ($decoded -in @("UEME_CTLSESSION", "UEME_RUNPATH", "UEME_UIHOTPATH")) { continue }
                    
                    $data = $item.GetValue($valName)
                    $runCount = 0
                    $lastRun = $null
                    
                    if ($data -and $data.Length -ge 68) {
                        $runCount = [BitConverter]::ToInt32($data, 4)
                        $rawFt = [BitConverter]::ToInt64($data, 60)
                        if ($rawFt -gt 0) {
                            try { $lastRun = [DateTime]::FromFileTime($rawFt) } catch { $lastRun = $null }
                        }
                    }
                    
                    if ($runCount -gt 0 -or $lastRun) {
                        $results += [PSCustomObject]@{
                            Source         = "UserAssist"
                            User           = $env:USERNAME
                            Path           = $decoded
                            RunCount       = $runCount
                            LastExecution  = if ($lastRun) { $lastRun.ToString("yyyy-MM-dd HH:mm:ss") } else { "Desconocido" }
                            RawTimestamp   = if ($lastRun) { $lastRun.Ticks } else { 0 }
                        }
                    }
                }
            }
        }
    }
    return $results
}

function Get-BAMEvidence {
    $results = @()
    $bamPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    )
    foreach ($bp in $bamPaths) {
        if (Test-Path $bp) {
            $sids = Get-ChildItem -Path $bp
            foreach ($s in $sids) {
                $sidStr = $s.PSChildName
                $item = Get-Item -Path $s.PSPath
                foreach ($valName in $item.GetValueNames()) {
                    if ($valName -in @("SequenceNumber", "Version")) { continue }
                    $data = $item.GetValue($valName)
                    $lastRun = $null
                    if ($data -and $data.Length -ge 8) {
                        $rawFt = [BitConverter]::ToInt64($data, 0)
                        if ($rawFt -gt 0) {
                            try { $lastRun = [DateTime]::FromFileTime($rawFt) } catch { $lastRun = $null }
                        }
                    }
                    $cleanPath = $valName -replace '^\\Device\\HarddiskVolume\d+', 'C:'
                    $results += [PSCustomObject]@{
                        Source         = "BAM/DAM"
                        User           = $sidStr
                        Path           = $cleanPath
                        RunCount       = 1
                        LastExecution  = if ($lastRun) { $lastRun.ToString("yyyy-MM-dd HH:mm:ss") } else { "Desconocido" }
                        RawTimestamp   = if ($lastRun) { $lastRun.Ticks } else { 0 }
                    }
                }
            }
        }
    }
    return $results
}

function Get-PrefetchEvidence {
    $results = @()
    $pfDir = "C:\Windows\Prefetch"
    if (Test-Path $pfDir) {
        try {
            $files = Get-ChildItem -Path (Join-Path $pfDir "*.pf") -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $parts = $f.Name -split '-'
                $exeName = $parts[0]
                $results += [PSCustomObject]@{
                    Source         = "Prefetch"
                    User           = "SYSTEM (Host)"
                    Path           = "$($f.FullName) [$exeName]"
                    RunCount       = 1
                    LastExecution  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    RawTimestamp   = $f.LastWriteTime.Ticks
                }
            }
        } catch {}
    }
    return $results
}

function Get-ShimcacheEvidence {
    $results = @()
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    if (Test-Path $regPath) {
        try {
            $val = (Get-ItemProperty -Path $regPath).AppCompatCache
            if ($val) {
                $pos = 0
                while ($pos -lt ($val.Length - 20)) {
                    if ($val[$pos] -eq 0x31 -and $val[$pos+1] -eq 0x30 -and $val[$pos+2] -eq 0x74 -and $val[$pos+3] -eq 0x73) {
                        $pathLen = [BitConverter]::ToUInt16($val, $pos + 12)
                        if ($pathLen -gt 0 -and ($pos + 14 + $pathLen) -le $val.Length) {
                            $pathBytes = $val[($pos + 14)..($pos + 13 + $pathLen)]
                            $path = [System.Text.Encoding]::Unicode.GetString($pathBytes)
                            $cleanPath = $path -replace '^\\\?\?\\', ''
                            $exists = Test-Path -LiteralPath $cleanPath -ErrorAction SilentlyContinue
                            
                            $afterPath = $pos + 14 + $pathLen
                            $lastMod = $null
                            if (($afterPath + 8) -le $val.Length) {
                                $rawFt = [BitConverter]::ToInt64($val, $afterPath)
                                if ($rawFt -gt 0) {
                                    try { $lastMod = [DateTime]::FromFileTime($rawFt) } catch {}
                                }
                            }
                            
                            $results += [PSCustomObject]@{
                                Source        = "Shimcache"
                                User          = "SYSTEM (AppCompat)"
                                Path          = $cleanPath
                                RunCount      = 1
                                ExistsOnDisk  = $exists
                                LastExecution = if ($lastMod) { $lastMod.ToString("yyyy-MM-dd HH:mm:ss") } else { "Desconocido" }
                                RawTimestamp  = if ($lastMod) { $lastMod.Ticks } else { 0 }
                            }
                        }
                    }
                    $pos += 4
                }
            }
        } catch {}
    }
    return $results
}

function Get-PCAEvidence {
    $results = @()
    $pcaDir = "C:\Windows\appcompat\pca"
    if (Test-Path $pcaDir) {
        Get-ChildItem -Path (Join-Path $pcaDir "PcaGeneralDb*.txt") -ErrorAction SilentlyContinue | ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Encoding Unicode -ErrorAction SilentlyContinue | ForEach-Object {
                $parts = $_.Trim() -split '\|'
                if ($parts.Length -ge 3) {
                    $ts = $parts[0]
                    $exePath = $parts[2] -replace '%programdata%', $env:ProgramData -replace '%systemroot%', $env:SystemRoot -replace '%commonprogramfiles%', $env:CommonProgramFiles -replace '%programfiles%', $env:ProgramFiles
                    $appName = if ($parts.Length -ge 4) { $parts[3] } else { "" }
                    $results += [PSCustomObject]@{
                        Source        = "Amcache/PCA"
                        User          = "SYSTEM (PCA)"
                        Path          = "$exePath [$appName]"
                        RunCount      = 1
                        ExistsOnDisk  = (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)
                        LastExecution = $ts
                        RawTimestamp  = (Get-Date $ts).Ticks
                    }
                }
            }
        }
    }
    return $results
}

function Classify-Risk ($item) {
    $p = $item.Path.ToLower()
    $score = 0
    $reasons = @()
    
    $tools = @("mimikatz", "rubeus", "procdump", "sharp", "seatbelt", "bloodhound", "chisel", "ngrok", "fscan", "psexec", "lazagne")
    foreach ($t in $tools) {
        if ($p -match $t) {
            $score += 85
            $reasons += "Herramienta ofensiva / C2: '$t'"
            break
        }
    }
    
    $lolbins = @("certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "powershell.exe", "cmd.exe", "vssadmin.exe")
    foreach ($lb in $lolbins) {
        if ($p -match [regex]::Escape($lb)) {
            $score += 40
            $reasons += "LOLBin detectado: '$lb'"
            break
        }
    }
    
    $paths = @("appdata\\local\\temp", "appdata\\roaming", "\\downloads", "\\public", "\\perflogs")
    foreach ($sp in $paths) {
        if ($p -match $sp) {
            $score += 35
            $reasons += "Ruta de ejecucion sospechosa: '$sp'"
            break
        }
    }

    if ($item.ExistsOnDisk -eq $false -and $score -gt 0) {
        $score += 35
        $reasons += "Anti-Forensics: Binario ejecutado pero eliminado del disco (T1070.004)"
    }
    
    $level = if ($score -ge 75) { "CRITICAL" } elseif ($score -ge 50) { "HIGH" } elseif ($score -ge 25) { "MEDIUM" } else { "CLEAN" }
    
    $item | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $level -Force
    $item | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue $score -Force
    $item | Add-Member -NotePropertyName "Reasons" -NotePropertyValue ($reasons -join " | ") -Force
    return $item
}

function Run-FullTriage {
    Write-Host "[*] Recolectando evidencias forenses de ejecucion..." -ForegroundColor Cyan
    $all = @()
    $all += Get-UserAssistEvidence
    $all += Get-BAMEvidence
    $all += Get-PrefetchEvidence
    $all += Get-ShimcacheEvidence
    $all += Get-PCAEvidence
    
    foreach ($i in $all) {
        Classify-Risk $i | Out-Null
    }
    
    $sorted = $all | Sort-Object RawTimestamp -Descending
    Write-Host "[+] Total de evidencias recolectadas: $($sorted.Count)" -ForegroundColor Green
    
    $suspicious = $sorted | Where-Object { $_.RiskLevel -in @("CRITICAL", "HIGH", "MEDIUM") }
    if ($suspicious) {
        Write-Host "`n[!] ALERTA: $($suspicious.Count) EJECUCIONES SOSPECHOSAS DETECTADAS:" -ForegroundColor Red
        $suspicious | Select-Object -First 10 RiskLevel, LastExecution, Path, Reasons | Format-Table -AutoSize
    } else {
        Write-Host "`n[+] No se detectaron herramientas ofensivas criticas." -ForegroundColor Green
    }
    
    return $sorted
}

# Flujo Principal
if ($SoloTriage -or $UserAssist -or $BAM -or $Prefetch) {
    Run-FullTriage | Out-Null
    exit 0
}

# Modo Interactivo
do {
    Show-ExecBanner
    Write-Host "  [1] Triage Forense Completo de Ejecución" -ForegroundColor Cyan
    Write-Host "  [2] Inspección de UserAssist (ROT13 GUI Runs)" -ForegroundColor Cyan
    Write-Host "  [3] Auditoría de BAM / DAM (Background Activity Moderator)" -ForegroundColor Cyan
    Write-Host "  [4] Análisis de Archivos Prefetch (*.pf)" -ForegroundColor Cyan
    Write-Host "  [5] Caza de Binarios Sospechosos y LOLBins" -ForegroundColor Cyan
    Write-Host "  [0] Salir" -ForegroundColor Red
    Write-Host ""
    $opc = Read-Host "  Selecciona una opción [0-5]"
    
    switch ($opc) {
        "1" { Run-FullTriage; Read-Host "`nPresiona Enter para continuar..." }
        "2" {
            $ua = Get-UserAssistEvidence
            Write-Host "[+] Registros UserAssist: $($ua.Count)" -ForegroundColor Green
            $ua | Select-Object -First 15 LastExecution, RunCount, Path | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
        "3" {
            $bam = Get-BAMEvidence
            Write-Host "[+] Registros BAM/DAM: $($bam.Count)" -ForegroundColor Green
            $bam | Select-Object -First 15 LastExecution, User, Path | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
        "4" {
            $pf = Get-PrefetchEvidence
            Write-Host "[+] Archivos Prefetch: $($pf.Count)" -ForegroundColor Green
            $pf | Select-Object -First 15 LastExecution, Path | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
        "5" {
            $ev = Run-FullTriage
            $ev | Where-Object { $_.RiskLevel -ne "CLEAN" } | Select-Object -First 20 RiskLevel, LastExecution, Path, Reasons | Format-Table -AutoSize
            Read-Host "`nPresiona Enter para continuar..."
        }
    }
} while ($opc -ne "0")
