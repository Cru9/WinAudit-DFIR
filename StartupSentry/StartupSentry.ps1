<#
.SYNOPSIS
    StartupSentry.ps1 v2.0.0 - Framework Forense de Persistencia en Inicio, Tareas Programadas y Firmas Authenticode.
.DESCRIPTION
    Herramienta avanzada de Threat Hunting y DFIR (Digital Forensics & Incident Response) para Windows.
    Inspecciona vectores de persistencia críticos:
    1. Comandos y programas de auto-arranque (Win32_StartupCommand y claves Registry Run/RunOnce).
    2. Tareas programadas en la raíz del sistema (\) que no pertenecen a Microsoft.
    3. Frecuencia e intervalos de repetición de tareas (Triggers.Repetition.Interval <= 30 min).
    4. Validación criptográfica de firmas digitales Authenticode (Get-AuthenticodeSignature).
    5. Heurísticas de evasión: ejecución desde AppData/Temp/Public, masquerading de binarios del sistema y LOLBins.
.NOTES
    Autor: Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v2.0.0
#>

[CmdletBinding()]
param(
    [switch]$SoloSospechosos,
    [switch]$Json,
    [string]$ExportarCSV = "",
    [string]$ExportarJSON = "",
    [string]$ExportarHTML = "",
    [string]$UmbralSeveridad = "TODAS" # TODAS, BAJA, MEDIA, ALTA, CRITICA
)

# -----------------------------------------------------------------------------
# Funciones Auxiliares
# -----------------------------------------------------------------------------

function Resolve-BinaryPath {
    param([string]$raw)
    if (-not $raw) { return "" }
    $clean = $raw.Trim().Trim('"', "'", " ")
    if ($clean -match '(?i)^\s*"([^"]+)"') {
        $clean = $matches[1]
    } elseif ($clean -match '(?i)^\s*(.*?\.(?:exe|bat|cmd|vbs|ps1|dll|js|scr|msi))') {
        $clean = $matches[1]
    } elseif ($clean -match '^\s*([^\s]+)') {
        $clean = $matches[1]
    }
    $clean = $clean.Trim('"', "'", " ")
    $clean = [System.Environment]::ExpandEnvironmentVariables($clean)
    return $clean
}

function Get-FriendlySigner {
    param($cert)
    if (-not $cert) { return "-" }
    $subject = $cert.Subject
    if ($subject -match '(?i)CN=([^,]+)') {
        return $matches[1].Trim()
    }
    return $subject
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$processedKeys = [System.Collections.Generic.HashSet[string]]::new()

# -----------------------------------------------------------------------------
# 1. Auditoría de Comandos de Inicio (Win32_StartupCommand)
# -----------------------------------------------------------------------------
try {
    $startups = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
    foreach ($s in $startups) {
        $rawCmd = $s.Command
        $binPath = Resolve-BinaryPath $rawCmd
        $dedupKey = "STARTUP:$($s.Name):$binPath"
        if ($processedKeys.Contains($dedupKey)) { continue }
        $processedKeys.Add($dedupKey) | Out-Null

        $sigStatus = "NoEncontrado"
        $signer = "-"
        $certSubject = "-"
        if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
            $sigStatus = $sigObj.Status.ToString()
            if ($sigObj.SignerCertificate) {
                $certSubject = $sigObj.SignerCertificate.Subject
                $signer = Get-FriendlySigner $sigObj.SignerCertificate
            }
        }

        $esSospechoso = $false
        $motivos = [System.Collections.Generic.List[string]]::new()
        $severidad = "BAJA"

        # Heuristica de rutas
        if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|programdata\\|\$recycle\.bin)') {
            $esSospechoso = $true
            $severidad = "MEDIA"
            $motivos.Add("Ejecución desde carpeta temporal o de usuario (AppData/Temp/Public)")
        }

        # Masquerading de binarios de sistema
        $baseName = [System.IO.Path]::GetFileName($binPath)
        if ($baseName -match '(?i)^(svchost|explorer|csrss|taskhost|lsass|rundll32|services|smss|winlogon)\.exe$' -and $binPath -notmatch '(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)') {
            $esSospechoso = $true
            $severidad = "CRITICA"
            $motivos.Add("Masquerading: Proceso de sistema legítimo simulado fuera de System32")
        }

        # Interpretes y scripts en arranque
        if ($rawCmd -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|regsvr32)') {
            $esSospechoso = $true
            if ($severidad -ne "CRITICA") { $severidad = "MEDIA" }
            $motivos.Add("Uso de intérprete de comandos o LOLBin en arranque")
        }

        # Argumentos ofuscados o descargas directas
        if ($rawCmd -match '(?i)(-enc|-encodedcommand|-w\s+hidden|downloadstring|curl|wget|iex)') {
            $esSospechoso = $true
            $severidad = "CRITICA"
            $motivos.Add("Comando ofuscado o descarga activa remota detectada")
        }

        # Firma digital no valida o ausente
        if ($sigStatus -ne "Valid") {
            if ($sigStatus -eq "HashMismatch") {
                $esSospechoso = $true
                $severidad = "CRITICA"
                $motivos.Add("Firma Digital Corrupta o Modificada (HashMismatch / Tampering)")
            } elseif ($sigStatus -eq "NotSigned") {
                if ($esSospechoso) {
                    $severidad = "ALTA"
                }
                $motivos.Add("Binario sin firma digital válida (NotSigned)")
            } else {
                if ($esSospechoso) { $severidad = "ALTA" }
                $motivos.Add("Estado de firma anómalo: $sigStatus")
            }
        }

        $item = [PSCustomObject]@{
            Id          = "ST-$($results.Count + 1)"
            Categoria   = "AutoArranque"
            Nombre      = $s.Name
            Comando     = $rawCmd
            Ruta        = $binPath
            Firma       = $sigStatus
            Firmante    = $signer
            Certificado = $certSubject
            Ubicacion   = $s.Location
            Usuario     = $s.User
            Intervalo   = "Al Iniciar Sesión"
            Sospechoso  = $esSospechoso
            Severidad   = $severidad
            Motivo      = ($motivos -join " | ")
        }
        $results.Add($item)
    }
} catch {}

# -----------------------------------------------------------------------------
# 2. Claves de Registro Run y RunOnce Directas
# -----------------------------------------------------------------------------
$regPaths = @(
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; Scope = "HKLM:Run" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "HKLM:RunOnce" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Scope = "HKCU:Run" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "HKCU:RunOnce" },
    @{ Path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope = "HKLM:Run(x86)" }
)

foreach ($rp in $regPaths) {
    if (Test-Path $rp.Path) {
        try {
            $key = Get-ItemProperty -Path $rp.Path -ErrorAction SilentlyContinue
            if ($key) {
                $propNames = $key.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider|PSComputerName)$'
                }
                foreach ($p in $propNames) {
                    $val = [string]$p.Value
                    if (-not $val) { continue }
                    $binPath = Resolve-BinaryPath $val
                    $dedupKey = "REG:$($p.Name):$binPath"
                    if ($processedKeys.Contains($dedupKey)) { continue }
                    $processedKeys.Add($dedupKey) | Out-Null

                    $sigStatus = "NoEncontrado"
                    $signer = "-"
                    $certSubject = "-"
                    if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
                        $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
                        $sigStatus = $sigObj.Status.ToString()
                        if ($sigObj.SignerCertificate) {
                            $certSubject = $sigObj.SignerCertificate.Subject
                            $signer = Get-FriendlySigner $sigObj.SignerCertificate
                        }
                    }

                    $esSospechoso = $false
                    $motivos = [System.Collections.Generic.List[string]]::new()
                    $severidad = "BAJA"

                    if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|programdata\\|\$recycle\.bin)') {
                        $esSospechoso = $true
                        $severidad = "MEDIA"
                        $motivos.Add("Ejecución desde ruta temporal o de usuario")
                    }

                    $baseName = [System.IO.Path]::GetFileName($binPath)
                    if ($baseName -match '(?i)^(svchost|explorer|csrss|taskhost|lsass|rundll32|services)\.exe$' -and $binPath -notmatch '(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)') {
                        $esSospechoso = $true
                        $severidad = "CRITICA"
                        $motivos.Add("Masquerading: Nombre de proceso del sistema fuera de System32")
                    }

                    if ($val -match '(?i)(-enc|-encodedcommand|-w\s+hidden|downloadstring|curl|wget|iex)') {
                        $esSospechoso = $true
                        $severidad = "CRITICA"
                        $motivos.Add("Comando con payload ofuscado o descarga remota")
                    }

                    if ($sigStatus -ne "Valid") {
                        if ($sigStatus -eq "HashMismatch") {
                            $esSospechoso = $true
                            $severidad = "CRITICA"
                            $motivos.Add("Firma Digital Corrupta (HashMismatch)")
                        } elseif ($sigStatus -eq "NotSigned") {
                            if ($esSospechoso) { $severidad = "ALTA" }
                            $motivos.Add("Binario sin firma digital válida (NotSigned)")
                        }
                    }

                    $item = [PSCustomObject]@{
                        Id          = "REG-$($results.Count + 1)"
                        Categoria   = "RegistroRun"
                        Nombre      = $p.Name
                        Comando     = $val
                        Ruta        = $binPath
                        Firma       = $sigStatus
                        Firmante    = $signer
                        Certificado = $certSubject
                        Ubicacion   = $rp.Scope
                        Usuario     = if ($rp.Scope -match 'HKCU') { $env:USERNAME } else { "Todos (Sistema)" }
                        Intervalo   = "Al Iniciar Sesión"
                        Sospechoso  = $esSospechoso
                        Severidad   = $severidad
                        Motivo      = ($motivos -join " | ")
                    }
                    $results.Add($item)
                }
            }
        } catch {}
    }
}

# -----------------------------------------------------------------------------
# 3. Auditoría de Carpetas de Inicio de Windows (Startup Folders / .LNK / Scripts)
# -----------------------------------------------------------------------------
$startupFolders = @(
    @{ Path = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup"); Scope = "User Startup" },
    @{ Path = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\Startup"); Scope = "All Users Startup" }
)

$wshShell = $null
try {
    $wshShell = New-Object -ComObject WScript.Shell -ErrorAction SilentlyContinue
} catch {}

foreach ($sf in $startupFolders) {
    if (Test-Path $sf.Path) {
        try {
            $files = Get-ChildItem -Path $sf.Path -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $targetPath = $f.FullName
                $cmdArgs = ""
                if ($f.Extension -eq ".lnk" -and $wshShell) {
                    try {
                        $shortcut = $wshShell.CreateShortcut($f.FullName)
                        $targetPath = $shortcut.TargetPath
                        $cmdArgs = $shortcut.Arguments
                    } catch {}
                }

                $binPath = Resolve-BinaryPath $targetPath
                $dedupKey = "FOLDER:$($f.Name):$binPath"
                if ($processedKeys.Contains($dedupKey)) { continue }
                $processedKeys.Add($dedupKey) | Out-Null

                $sigStatus = "NoEncontrado"
                $signer = "-"
                $certSubject = "-"
                if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
                    $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
                    $sigStatus = $sigObj.Status.ToString()
                    if ($sigObj.SignerCertificate) {
                        $certSubject = $sigObj.SignerCertificate.Subject
                        $signer = Get-FriendlySigner $sigObj.SignerCertificate
                    }
                }

                $esSospechoso = $false
                $motivos = [System.Collections.Generic.List[string]]::new()
                $severidad = "BAJA"

                if ($f.Extension -match '(?i)\.(vbs|js|bat|cmd|ps1|hta)$') {
                    $esSospechoso = $true
                    $severidad = "ALTA"
                    $motivos.Add("Script ejecutable alojado directamente en carpeta de inicio ($($f.Extension))")
                }

                if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|\$recycle\.bin)') {
                    $esSospechoso = $true
                    if ($severidad -ne "CRITICA") { $severidad = "MEDIA" }
                    $motivos.Add("Acceso directo apuntando a carpeta temporal o de usuario")
                }

                if ($sigStatus -ne "Valid") {
                    if ($sigStatus -eq "HashMismatch") {
                        $esSospechoso = $true
                        $severidad = "CRITICA"
                        $motivos.Add("Firma Digital Corrupta (HashMismatch)")
                    } elseif ($sigStatus -eq "NotSigned") {
                        if ($esSospechoso) { $severidad = "ALTA" }
                        $motivos.Add("Binario sin firma digital válida (NotSigned)")
                    }
                }

                $fullCmd = if ($cmdArgs) { "$targetPath $cmdArgs" } else { $targetPath }
                $item = [PSCustomObject]@{
                    Id          = "DIR-$($results.Count + 1)"
                    Categoria   = "CarpetaInicio"
                    Nombre      = $f.Name
                    Comando     = $fullCmd
                    Ruta        = $binPath
                    Firma       = $sigStatus
                    Firmante    = $signer
                    Certificado = $certSubject
                    Ubicacion   = $sf.Scope
                    Usuario     = if ($sf.Scope -match 'User') { $env:USERNAME } else { "Todos (Sistema)" }
                    Intervalo   = "Al Iniciar Sesión"
                    Sospechoso  = $esSospechoso
                    Severidad   = $severidad
                    Motivo      = ($motivos -join " | ")
                }
                $results.Add($item)
            }
        } catch {}
    }
}

# -----------------------------------------------------------------------------
# 4. Auditoría de Tareas Programadas en Raíz (\) No-Microsoft
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
                # Detectar repeticiones menores o iguales a 30 minutos (ej. PT1M, PT5M, PT10M, PT15M, PT30M)
                if ($interval -match '(?i)PT([1-9]|1[0-9]|2[0-9]|30)M') {
                    $esFrecuente = $true
                }
            }
        } catch {}

        $sigStatus = "NoEncontrado"
        $signer = "-"
        $certSubject = "-"
        if ($binPath -and (Test-Path -Path $binPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $sigObj = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
            $sigStatus = $sigObj.Status.ToString()
            if ($sigObj.SignerCertificate) {
                $certSubject = $sigObj.SignerCertificate.Subject
                $signer = Get-FriendlySigner $sigObj.SignerCertificate
            }
        } elseif (-not $binPath) {
            $sigStatus = "N/A"
        }

        $esSospechoso = $false
        $motivos = [System.Collections.Generic.List[string]]::new()
        $severidad = "BAJA"

        # LOLBins y scripts en tareas
        if ($exec -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32)') {
            $esSospechoso = $true
            $severidad = "MEDIA"
            $motivos.Add("Uso de LOLBin / Intérprete en tarea programada")
        }

        # Rutas temporales
        if ($binPath -match '(?i)(appdata|\\temp\\|users\\public|programdata\\|\$recycle\.bin)') {
            $esSospechoso = $true
            $severidad = "ALTA"
            $motivos.Add("Ejecutable alojado en carpeta temporal o de usuario")
        }

        # Intervalo recurrente frecuente
        if ($esFrecuente) {
            $esSospechoso = $true
            if ($severidad -ne "CRITICA") { $severidad = "ALTA" }
            $motivos.Add("Persistencia de reinicio recurrente de alta frecuencia ($interval)")
        }

        # Argumentos con comandos codificados
        $fullCmd = "$exec $args".Trim()
        if ($fullCmd -match '(?i)(-enc|-encodedcommand|-w\s+hidden|downloadstring|curl|iex)') {
            $esSospechoso = $true
            $severidad = "CRITICA"
            $motivos.Add("Parámetros de tarea con payload ofuscado o llamada remota")
        }

        # Firma no valida
        if ($sigStatus -ne "Valid" -and $sigStatus -ne "N/A") {
            if ($sigStatus -eq "HashMismatch") {
                $esSospechoso = $true
                $severidad = "CRITICA"
                $motivos.Add("Firma Digital Corrupta (HashMismatch)")
            } elseif ($esSospechoso) {
                $severidad = "ALTA"
                $motivos.Add("Binario sin firma digital válida ($sigStatus)")
            }
        }

        $item = [PSCustomObject]@{
            Id          = "TASK-$($results.Count + 1)"
            Categoria   = "TareaProgramada"
            Nombre      = $t.TaskName
            Comando     = $fullCmd
            Ruta        = $binPath
            Firma       = $sigStatus
            Firmante    = $signer
            Certificado = $certSubject
            Ubicacion   = $t.TaskPath
            Usuario     = if ($t.Principal.UserId) { $t.Principal.UserId } else { "Sistema" }
            Intervalo   = $interval
            Sospechoso  = $esSospechoso
            Severidad   = $severidad
            Motivo      = ($motivos -join " | ")
        }
        $results.Add($item)
    }
} catch {}

# Si se pide formato JSON directo para automatización / Python
if ($Json) {
    $results | ConvertTo-Json -Depth 4 -Compress
    return
}

# -----------------------------------------------------------------------------
# Exportación de Archivos (CSV, JSON, HTML)
# -----------------------------------------------------------------------------
if ($ExportarCSV) {
    $results | Export-Csv -Path $ExportarCSV -NoTypeInformation -Encoding UTF8
    Write-Host "[✓] Evidencia exportada a CSV: $ExportarCSV" -ForegroundColor Green
}

if ($ExportarJSON) {
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportarJSON -Encoding UTF8
    Write-Host "[✓] Evidencia exportada a JSON: $ExportarJSON" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Presentación en Terminal para Analista DFIR
# -----------------------------------------------------------------------------
Clear-Host
Write-Host "=========================================================================================" -ForegroundColor Cyan
Write-Host "   STARTUPSENTRY v2.0.0 - FORENSIC AUTOSTART & TASK PERSISTENCE HUNTER" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "   Ecosistema WinAudit-DFIR | Autor: Ezequiel Diaz (Cru9)" -ForegroundColor Gray
Write-Host "   Triage de Win32_StartupCommand, Registry Run Keys, Tareas Raíz y Firmas Authenticode" -ForegroundColor Gray
Write-Host "=========================================================================================" -ForegroundColor Cyan
Write-Host ""

$filtrados = $results
if ($SoloSospechosos) {
    $filtrados = $results | Where-Object { $_.Sospechoso }
}
if ($UmbralSeveridad -ne "TODAS") {
    $filtrados = $filtrados | Where-Object { $_.Severidad -eq $UmbralSeveridad }
}

$sospechosos = @($results | Where-Object { $_.Sospechoso })
$sinFirma = @($results | Where-Object { $_.Firma -ne "Valid" -and $_.Firma -ne "N/A" })
$criticos = @($results | Where-Object { $_.Severidad -eq "CRITICA" })
$altos = @($results | Where-Object { $_.Severidad -eq "ALTA" })

Write-Host "  .---------------------------------------------------------------------------------." -ForegroundColor DarkCyan
Write-Host "  | METRICAS DE AMENAZAS EN ARRANQUE Y PERSISTENCIA                                 |" -ForegroundColor DarkCyan
Write-Host "  +---------------------------------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  | Total Elementos Analizados:  $('{0,-10}' -f $results.Count) | Tareas Raíz No-MS:       $('{0,-12}' -f (@($results | Where-Object { $_.Categoria -eq 'TareaProgramada' }).Count)) |" -ForegroundColor Gray
Write-Host "  | Sin Firma Digital Válida:   $('{0,-10}' -f $sinFirma.Count) | Alertas Sospechosas:     $('{0,-12}' -f $sospechosos.Count) |" -ForegroundColor Gray
Write-Host "  | Severidad Crítica:          $('{0,-10}' -f $criticos.Count) | Severidad Alta:          $('{0,-12}' -f $altos.Count) |" -ForegroundColor Gray
Write-Host "  '---------------------------------------------------------------------------------'" -ForegroundColor DarkCyan
Write-Host ""

if ($sospechosos.Count -gt 0) {
    Write-Host "  [!] ALERTA DFIR: Se detectaron $($sospechosos.Count) vectores de persistencia sospechosos." -ForegroundColor Red
} else {
    Write-Host "  [✓] Sistema limpio: No se encontraron anomalías críticas en el arranque." -ForegroundColor Green
}
Write-Host ""

Write-Host ".-[ DETALLE DE ELEMENTOS EVALUADOS ]-------------------------------------------------------." -ForegroundColor Blue
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

    Write-Host "  $badge $($r.Categoria): $($r.Nombre)" -ForegroundColor $color
    Write-Host "       - Comando:    $($r.Comando)" -ForegroundColor Gray
    Write-Host "       - Ruta:       $($r.Ruta)" -ForegroundColor Gray
    Write-Host "       - Firma:      $($r.Firma)  |  Firmante: $($r.Firmante)" -ForegroundColor Gray
    Write-Host "       - Ubicación:  $($r.Ubicacion)  |  Intervalo: $($r.Intervalo)  |  Usuario: $($r.Usuario)" -ForegroundColor Gray
    if ($r.Motivo) {
        Write-Host "       - ALERTA:     $($r.Motivo)" -ForegroundColor Yellow
    }
    Write-Host ""
}
Write-Host "'------------------------------------------------------------------------------------------'" -ForegroundColor Blue
Write-Host ""
