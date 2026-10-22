<#
.SYNOPSIS
    Auditar-Persistencia-Arranque.ps1 - Hunter de Persistencia en Inicio y Tareas Programadas
.DESCRIPTION
    Inspecciona vectores crÃ­ticos de persistencia en Windows:
    1. Programas y comandos de auto-arranque (Win32_StartupCommand / Registry Run Keys).
    2. Tareas programadas en la raÃ­z del sistema (\) que no pertenecen a Microsoft.
    3. Frecuencia e intervalos de repeticiÃ³n de tareas (Triggers.Repetition.Interval).
    4. ValidaciÃ³n de firmas digitales de binarios mediante Authenticode (Get-AuthenticodeSignature).
    5. HeurÃ­stica de detecciÃ³n de amenazas en rutas temporales (AppData, Temp, Public).
.NOTES
    Autor: Cru9 | Ecosistema WinAudit-DFIR v1.2.1
#>

[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$SoloSospechosos
)

function Resolve-BinaryPath {
    param([string]$raw)
    if (-not $raw) { return "" }
    $clean = $raw.Trim().Trim('"', "'", " ")
    if ($clean -match '(?i)^\s*"([^"]+)"') {
        $clean = $matches[1]
    } elseif ($clean -match '(?i)^\s*(.*?\.(?:exe|bat|cmd|vbs|ps1|dll|js|scr))') {
        $clean = $matches[1]
    } elseif ($clean -match '^\s*([^\s]+)') {
        $clean = $matches[1]
    }
    $clean = $clean.Trim('"', "'", " ")
    $clean = [System.Environment]::ExpandEnvironmentVariables($clean)
    return $clean
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# -----------------------------------------------------------------------------
# 1. AuditorÃ­a de Comandos de Inicio (Win32_StartupCommand)
# -----------------------------------------------------------------------------
try {
    $startups = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
    foreach ($s in $startups) {
        $rawCmd = $s.Command
        $binPath = Resolve-BinaryPath $rawCmd
        
        $sigStatus = "NoEncontrado"
        $signer = "-"
        if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
            $sigStatus = $sigObj.Status.ToString()
            if ($sigObj.SignerCertificate) {
                $signer = $sigObj.SignerCertificate.Subject
            }
        }

        $esSospechoso = $false
        $motivos = [System.Collections.Generic.List[string]]::new()
        $severidad = "BAJA"

        # Heuristica de rutas
        if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|programdata\\|\$recycle\.bin)') {
            $esSospechoso = $true
            $severidad = "MEDIA"
            $motivos.Add("Ejecucion desde carpeta de usuario/temporal")
        }

        # Masquerading de binarios de sistema
        $baseName = [System.IO.Path]::GetFileName($binPath)
        if ($baseName -match '(?i)^(svchost|explorer|csrss|taskhost|lsass|rundll32|services)\.exe$' -and $binPath -notmatch '(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)') {
            $esSospechoso = $true
            $severidad = "CRITICA"
            $motivos.Add("Masquerading: Nombre de proceso del sistema fuera de System32")
        }

        # Firma no valida o ausente
        if ($sigStatus -ne "Valid") {
            if ($esSospechoso) {
                $severidad = "ALTA"
                $motivos.Add("Binario sin firma digital valida ($sigStatus)")
            } elseif ($sigStatus -eq "HashMismatch") {
                $esSospechoso = $true
                $severidad = "CRITICA"
                $motivos.Add("Firma Digital Corrupta / Modificada (HashMismatch)")
            }
        }

        $item = [PSCustomObject]@{
            Categoria   = "AutoArranque"
            Nombre      = $s.Name
            Comando     = $rawCmd
            Ruta        = $binPath
            Firma       = $sigStatus
            Firmante    = $signer
            Ubicacion   = $s.Location
            Usuario     = $s.User
            Intervalo   = "Al Iniciar Sesion"
            Sospechoso  = $esSospechoso
            Severidad   = $severidad
            Motivo      = ($motivos -join " | ")
        }
        $results.Add($item)
    }
} catch {}

# -----------------------------------------------------------------------------
# 2. AuditorÃ­a de Tareas Programadas en RaÃ­z (\) No-Microsoft
# -----------------------------------------------------------------------------
try {
    $tasks = Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue | Where-Object {
        $_.Author -notmatch '(?i)Microsoft' -and $_.TaskName -notmatch '(?i)Microsoft'
    }
    foreach ($t in $tasks) {
        $exec = $t.Actions.Execute
        $args = $t.Actions.Arguments
        $binPath = Resolve-BinaryPath $exec
        
        $interval = "No recurrente"
        $esFrecuente = $false
        try {
            $reps = $t.Triggers | Where-Object { $_.Repetition.Interval }
            if ($reps) {
                $interval = ($reps | Select-Object -First 1).Repetition.Interval
                # Detectar repeticiones menores o iguales a 30 minutos (ej. PT5M, PT10M, PT15M)
                if ($interval -match '(?i)PT([1-9]|1[0-9]|2[0-9]|30)M') {
                    $esFrecuente = $true
                }
            }
        } catch {}

        $sigStatus = "N/A"
        $signer = "-"
        if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
            $sigStatus = $sigObj.Status.ToString()
            if ($sigObj.SignerCertificate) {
                $signer = $sigObj.SignerCertificate.Subject
            }
        }

        $esSospechoso = $false
        $motivos = [System.Collections.Generic.List[string]]::new()
        $severidad = "BAJA"

        # LOLBins y scripts en tareas
        if ($exec -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|regsvr32)') {
            $esSospechoso = $true
            $severidad = "MEDIA"
            $motivos.Add("Uso de binario LOLBin / Interprete de comandos")
        }

        # Rutas no estandar
        if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|programdata\\|\$recycle\.bin)') {
            $esSospechoso = $true
            $severidad = "ALTA"
            $motivos.Add("Ejecutable en carpeta temporal de usuario")
        }

        # Intervalo recurrente frecuente
        if ($esFrecuente) {
            $esSospechoso = $true
            $motivos.Add("Persistencia activa con reinicio recurrente frecuente ($interval)")
        }

        # Firma no valida
        if ($sigStatus -ne "Valid" -and $sigStatus -ne "N/A") {
            if ($esSospechoso) {
                $severidad = "ALTA"
                $motivos.Add("Binario sin firma digital valida ($sigStatus)")
            }
        }

        $fullCmd = "$exec $args".Trim()
        $item = [PSCustomObject]@{
            Categoria   = "TareaProgramada"
            Nombre      = $t.TaskName
            Comando     = $fullCmd
            Ruta        = $binPath
            Firma       = $sigStatus
            Firmante    = $signer
            Ubicacion   = $t.TaskPath
            Usuario     = $t.Principal.UserId
            Intervalo   = $interval
            Sospechoso  = $esSospechoso
            Severidad   = $severidad
            Motivo      = ($motivos -join " | ")
        }
        $results.Add($item)
    }
} catch {}

# Si se pide formato JSON para integracion directa
if ($Json) {
    $results | ConvertTo-Json -Depth 4 -Compress
    return
}

# -----------------------------------------------------------------------------
# PresentaciÃ³n en Terminal para Analista DFIR
# -----------------------------------------------------------------------------
Clear-Host
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  AUDITORIA FORENSE DE PERSISTENCIA Y ARRANQUE (WinAudit-DFIR v1.2.1)" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "  Inspeccion de Win32_StartupCommand, Tareas Programadas y Firmas Authenticode" -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

$filtrados = if ($SoloSospechosos) { $results | Where-Object { $_.Sospechoso } } else { $results }

$sospechosos = @($results | Where-Object { $_.Sospechoso })
Write-Host " [+] Total de elementos analizados: " -NoNewline -ForegroundColor Gray
Write-Host "$($results.Count)" -ForegroundColor White
Write-Host " [!] Elementos sospechosos detectados: " -NoNewline -ForegroundColor Gray
if ($sospechosos.Count -gt 0) {
    Write-Host "$($sospechosos.Count) ALERTA(S)" -ForegroundColor Red
} else {
    Write-Host "0 (Todo limpio)" -ForegroundColor Green
}
Write-Host ""

Write-Host ".-[ DETALLE DE ELEMENTOS DE PERSISTENCIA ]------------------------------------." -ForegroundColor Blue
foreach ($r in $filtrados) {
    $color = "Cyan"
    $badge = "[OK]"
    if ($r.Severidad -eq "CRITICA") {
        $color = "Red"
        $badge = "[CRITICO]"
    } elseif ($r.Severidad -eq "ALTA") {
        $color = "Yellow"
        $badge = "[ALTO]"
    } elseif ($r.Severidad -eq "MEDIA") {
        $color = "Magenta"
        $badge = "[SOSPECHOSO]"
    }

    Write-Host " $badge $($r.Categoria): $($r.Nombre)" -ForegroundColor $color
    Write-Host "      - Comando:   $($r.Comando)" -ForegroundColor Gray
    Write-Host "      - Ruta:      $($r.Ruta)" -ForegroundColor Gray
    Write-Host "      - Firma:     $($r.Firma)  |  Intervalo: $($r.Intervalo)" -ForegroundColor Gray
    if ($r.Motivo) {
        Write-Host "      - ALERTA:    $($r.Motivo)" -ForegroundColor Yellow
    }
    Write-Host ""
}
Write-Host "'----------------------------------------------------------------------------'" -ForegroundColor Blue
Write-Host ""
