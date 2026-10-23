<#
.SYNOPSIS
    WiFiSentry v3.0.0: Framework de Auditoria WLAN, Radar Evil Twin en Vivo,
    Calculadora de Entropia / Crackeo y Hardening Defensivo.

.DESCRIPTION
    Herramienta interactiva y didactica disenada para estudiantes, sysadmins y analistas de ciberseguridad / DFIR.
    Permite auditar perfiles Wi-Fi almacenados en Windows, evaluar riesgos de seguridad (redes abiertas, WEP),
    cazar ataques Evil Twin y Rogue APs en vivo, auditar entropia y estimar tiempos de crackeo con GPU (Hashcat / Aircrack-ng),
    inspeccionar contrasenas en texto claro (demostracion de superficie de ataque fisica / DPAPI),
    y exportar reportes ejecutivos interactivos en HTML Cyberpunk.

.AUTHOR
    Ezequiel Diaz (Cru9) | Portafolio DFIR & Networking

.LINK
    https://github.com/Cru9
#>

[CmdletBinding()]
param(
    [switch]$SoloAuditar,
    [switch]$RevelarClaves,
    [switch]$RadarEvilTwin,
    [switch]$MapaCalor,
    [switch]$CalculadoraEntropia,
    [string]$ExportarHTML = ""
)

$ErrorActionPreference = 'SilentlyContinue'

$Host.UI.RawUI.WindowTitle = "WiFiSentry v3.0.0 | Suite WLAN DFIR, Radar Evil Twin & Mapa de Calor (Cru9)"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reportes"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

# ==============================================================================
# CABECERA VISUAL
# ==============================================================================
function Show-Banner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "  __        ___ _____ _ ____             _              " -ForegroundColor Cyan
    Write-Host "  \ \      / (_)  ___(_) ___|  ___ _ __ | |_ _ __ _   _ " -ForegroundColor Cyan
    Write-Host "   \ \ /\ / /| | |_  | \___ \ / _ \ '_ \| __| '__| | | |" -ForegroundColor Cyan
    Write-Host "    \ V  V / | |  _| | |___) |  __/ | | | |_| |  | |_| |" -ForegroundColor Cyan
    Write-Host "     \_/\_/  |_|_|   |_|____/ \___|_| |_|\__|_|   \__, |" -ForegroundColor Cyan
    Write-Host "                                                  |___/ " -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Magenta
    Write-Host "  Suite DFIR de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo" -ForegroundColor White
    Write-Host "  Ecosistema Cru9 | Framework Forense Inalambrico Didactico | v3.0.0" -ForegroundColor DarkGray
    Write-Host "==============================================================================`n" -ForegroundColor Magenta
}

# ==============================================================================
# MOTOR FORENSE: PARSER DE PERFILES WLAN ALMACENADOS (DPAPI)
# ==============================================================================
function Get-WiFiProfilesData {
    $profiles = @()
    $rawProfiles = netsh wlan show profiles 2>&1
    
    $profileNames = @()
    foreach ($line in $rawProfiles) {
        if (($line -match 'Perfil de todos los usuarios' -or $line -match 'All User Profile') -and ($line -match ':\s*(.+)$')) {
            $name = $matches[1].Trim()
            if ($name -and $name -ne "<Ninguno>" -and $name -ne "<None>") {
                $profileNames += $name
            }
        }
    }

    $id = 1
    foreach ($pName in $profileNames) {
        $detail = netsh wlan show profile name="$pName" key=clear 2>&1
        
        $auth = "Desconocida"
        $cipher = "Desconocido"
        $keyPresent = "No"
        $keyContent = ""
        $autoConnect = "Manual"
        
        foreach ($dLine in $detail) {
            if (($dLine -match 'Modo de conexi' -or $dLine -match 'Connection mode') -and ($dLine -match ':\s*(.+)$')) {
                $rawMode = $matches[1].Trim()
                if ($rawMode -match 'autom|auto') {
                    $autoConnect = "Automatica"
                } else {
                    $autoConnect = "Manual"
                }
            }
            if (($dLine -match 'Autenticaci' -or $dLine -match 'Authentication') -and ($dLine -match ':\s*(.+)$')) {
                $rawAuth = $matches[1].Trim()
                if ($auth -eq "Desconocida" -or $rawAuth -match "WPA3") {
                    $auth = $rawAuth
                }
            }
            if (($dLine -match 'Cifrado' -or $dLine -match 'Cipher') -and ($dLine -match ':\s*(.+)$')) {
                $rawCipher = $matches[1].Trim()
                if ($cipher -eq "Desconocido" -or $rawCipher -match "GCMP|CCMP") {
                    $cipher = $rawCipher
                }
            }
            if (($dLine -match 'Contenido de la clave' -or $dLine -match 'Key Content') -and ($dLine -match ':\s*(.+)$')) {
                $keyPresent = "Si"
                $keyContent = $matches[1].Trim()
            }
        }

        # Evaluacion de Riesgo y Diagnostico Forense
        $risk = "Seguro"
        $reasons = @()

        if ($auth -match "Abierta|Open|None|Ninguno") {
            $risk = "Critico"
            $reasons += "Red abierta sin cifrado. Vulnerable a captura pasiva de trafico y suplantacion Evil Twin."
        }
        if ($auth -match "WEP" -or $cipher -match "WEP") {
            $risk = "Critico"
            $reasons += "Cifrado WEP obsoleto y roto. Crackeable en menos de 60 segundos con ataques FMS/PTW."
        }
        if ($autoConnect -eq "Automatica" -and $risk -eq "Critico") {
            $reasons += "Conexion automatica activa en red vulnerable: el equipo emite Probe Requests broadcast."
        }
        if ($keyPresent -eq "Si") {
            if ($keyContent.Length -lt 8) {
                $risk = "Critico"
                $reasons += "Contrasena debil con menos de 8 caracteres (incumple estandares WPA)."
            } elseif ($keyContent -match '^[0-9]+$') {
                if ($risk -ne "Critico") { $risk = "Advertencia" }
                $reasons += "Contrasena exclusivamente numerica: vulnerable a fuerza bruta acelerada por GPU."
            } elseif ($keyContent -match '^[0-9a-fA-F]{8,16}$') {
                if ($risk -ne "Critico") { $risk = "Advertencia" }
                $reasons += "Patron hexadecimal detectado: posible clave de fabrica de router ISP."
            }
        }
        if ($reasons.Count -eq 0) {
            $reasons += "Perfil solido con cifrado moderno ($auth/$cipher)."
        }

        $profiles += [PSCustomObject]@{
            ID          = $id
            SSID        = $pName
            Auth        = $auth
            Cipher      = $cipher
            AutoConnect = $autoConnect
            KeyPresent  = $keyPresent
            KeyContent  = $keyContent
            Risk        = $risk
            Reasons     = ($reasons -join " | ")
        }
        $id++
    }

    return $profiles
}

# ==============================================================================
# MOTOR DE ESCANEO EN VIVO (BSSID / ROGUE AP HUNTER)
# ==============================================================================
function Get-LiveWlanNetworks {
    $liveRaw = netsh wlan show networks mode=bssid 2>&1
    $networks = @()
    $currentSsid = ""
    $currentAuth = "Desconocida"
    $currentCipher = "Desconocido"

    foreach ($line in $liveRaw) {
        $trimLine = $line.Trim()
        if ($trimLine -match '^SSID\s+\d+\s*:\s*(.*)$') {
            $currentSsid = $matches[1].Trim()
            if (-not $currentSsid) { $currentSsid = "<SSID Oculto>" }
        }
        elseif (($trimLine -match 'Autenticaci' -or $trimLine -match 'Authentication') -and ($trimLine -match ':\s*(.+)$')) {
            $currentAuth = $matches[1].Trim()
        }
        elseif (($trimLine -match 'Cifrado' -or $trimLine -match 'Cipher') -and ($trimLine -match ':\s*(.+)$')) {
            $currentCipher = $matches[1].Trim()
        }
        elseif ($trimLine -match '^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})') {
            $bssid = $matches[1].Trim()
            $networks += [PSCustomObject]@{
                SSID    = $currentSsid
                Auth    = $currentAuth
                Cipher  = $currentCipher
                BSSID   = $bssid
                Signal  = "0%"
                Channel = "0"
                Band    = "2.4 GHz"
                Radio   = "Desconocido"
            }
        }
        elseif (($trimLine -match 'al' -or $trimLine -match 'Signal') -and ($trimLine -match ':\s*(\d+%)')) {
            if ($networks.Count -gt 0) { $networks[-1].Signal = $matches[1].Trim() }
        }
        elseif ($trimLine -match '^(?:Canal|Channel)\s*:\s*(\d+)') {
            if ($networks.Count -gt 0) {
                $ch = [int]$matches[1].Trim()
                $networks[-1].Channel = "$ch"
                if ($ch -gt 177) { $networks[-1].Band = "6 GHz" }
                elseif ($ch -gt 14) { $networks[-1].Band = "5 GHz" }
                else { $networks[-1].Band = "2.4 GHz" }
            }
        }
        elseif (($trimLine -match 'Banda' -or $trimLine -match 'Band') -and ($trimLine -match ':\s*(.+)$')) {
            if ($networks.Count -gt 0) { $networks[-1].Band = $matches[1].Trim() }
        }
        elseif (($trimLine -match 'radio' -or $trimLine -match 'Radio') -and ($trimLine -match ':\s*(.+)$')) {
            if ($networks.Count -gt 0) { $networks[-1].Radio = $matches[1].Trim() }
        }
    }
    return $networks
}

# ==============================================================================
# MOTOR DE ANALISIS EVIL TWIN / ROGUE AP
# ==============================================================================
function Get-EvilTwinAnalysis {
    param(
        $LiveNetworks,
        $StoredProfiles
    )

    if (-not $LiveNetworks) { $LiveNetworks = Get-LiveWlanNetworks }
    if (-not $StoredProfiles) { $StoredProfiles = Get-WiFiProfilesData }

    $analysis = @()

    foreach ($ap in $LiveNetworks) {
        $matchedStored = $StoredProfiles | Where-Object { $_.SSID -eq $ap.SSID }
        
        $status = "NEIGHBOR"
        $severity = "Bajo"
        $badge = "Red Vecina"
        $diagnostic = "Red no registrada en el equipo local."

        if ($matchedStored) {
            $stAuth = $matchedStored.Auth
            $isLiveOpen = ($ap.Auth -match "Abierta|Open|None|Ninguno")
            $isStoredProtected = ($stAuth -match "WPA|WPA2|WPA3|802.1x")

            if ($isLiveOpen -and $isStoredProtected) {
                $status = "EVIL_TWIN_CRITICAL"
                $severity = "Critico"
                $badge = "ALERTA EVIL TWIN"
                $diagnostic = "PELIGRO MAXIMO: El perfil guardado '$($ap.SSID)' exige $($stAuth), pero este AP transmite SIN CIFRADO. Rogue AP activo intentando clonar tu red!"
            } elseif ($ap.Auth -ne $stAuth -and $stAuth -ne "Desconocida") {
                $status = "WARNING_DOWNGRADE"
                $severity = "Medio"
                $badge = "Downgrade Cifrado"
                $diagnostic = "ADVERTENCIA: Discrepancia de seguridad. Perfil: $stAuth vs Detectado: $($ap.Auth). Posible intento de degradacion de suite criptografica."
            } else {
                $status = "LEGITIMATE_MATCH"
                $severity = "Informativo"
                $badge = "Legitimo / Coincide"
                $diagnostic = "Coincide con perfil almacenado legitimo ($stAuth). BSSID activo en el entorno."
            }
        } elseif ($ap.Auth -match "Abierta|Open|None|Ninguno") {
            $status = "OPEN_UNENCRYPTED"
            $severity = "Advertencia"
            $badge = "Red Abierta Cercana"
            $diagnostic = "Punto de acceso abierto no cifrado en las inmediaciones. Vulnerable a sniffing y captive portal phishing."
        }

        $analysis += [PSCustomObject]@{
            SSID       = $ap.SSID
            BSSID      = $ap.BSSID
            Auth       = $ap.Auth
            Cipher     = $ap.Cipher
            Signal     = $ap.Signal
            Channel    = $ap.Channel
            Radio      = $ap.Radio
            Status     = $status
            Severity   = $severity
            Badge      = $badge
            Diagnostic = $diagnostic
        }
    }

    return $analysis
}

# ==============================================================================
# CALCULADORA DE ENTROPIA Y ESTIMACION DE CRACKEO GPU (HASHCAT / AIRCRACK)
# ==============================================================================
function Get-PasswordAuditStats {
    param([string]$Password)

    if (-not $Password) {
        return [PSCustomObject]@{
            Length          = 0
            PoolSize        = 0
            EntropyBits     = 0.0
            ComplexityClass = "Sin Clave / Abierta"
            PatternType     = "Red Abierta (0 bits de entropia)"
            SearchSpaceExp  = "0"
            TimeCPU         = "Instantaneo (<1s)"
            TimeRTX3060     = "Instantaneo (<1s)"
            TimeRTX4090     = "Instantaneo (<1s)"
            TimeCluster     = "Instantaneo (<1s)"
            NistCompliance  = "No Cumple (Sin contrasena)"
        }
    }

    $len = $Password.Length
    $hasLower = $Password -cmatch '[a-z]'
    $hasUpper = $Password -cmatch '[A-Z]'
    $hasDigit = $Password -match '[0-9]'
    $hasSpecial = $Password -match '[^a-zA-Z0-9]'

    $pool = 0
    if ($hasLower) { $pool += 26 }
    if ($hasUpper) { $pool += 26 }
    if ($hasDigit) { $pool += 10 }
    if ($hasSpecial) { $pool += 33 }
    if ($pool -eq 0) { $pool = 10 }

    $entropy = [Math]::Round($len * ([Math]::Log($pool) / [Math]::Log(2)), 1)

    # Deteccion de patrones comunes e ISP
    $pattern = "Alfanumerica Personalizada"
    if ($Password -match '^[0-9]+$') {
        $pattern = "Solo Numerica (Vulnerable a PIN/Telefono)"
    } elseif ($Password -match '^[0-9a-fA-F]{8,16}$') {
        $pattern = "Patron Hexadecimal (Clave de fabrica Router ISP)"
    } elseif ($Password -match '^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8}$') {
        $pattern = "8 Caracteres Alfanumericos (Patron tipico ISP modem)"
    } elseif ($len -ge 16 -and (-not $hasSpecial)) {
        $pattern = "Frase de Paso Extensa (Passphrase tipo Diceware)"
    } elseif ($len -ge 14 -and $hasSpecial -and $hasDigit) {
        $pattern = "Frase de Paso Robusta de Alta Seguridad"
    }

    # Clasificacion de Entropia
    $complexity = "Critica"
    $nist = "No Cumple (<64 bits de entropia)"
    if ($entropy -ge 80) {
        $complexity = "Nivel Militar / Extra Robusta"
        $nist = "Excelente (Cumple NIST SP 800-63B / WPA3)"
    } elseif ($entropy -ge 60) {
        $complexity = "Robusta"
        $nist = "Adecuado para WPA2-PSK Domestico"
    } elseif ($entropy -ge 40) {
        $complexity = "Moderada"
        $nist = "Vulnerable a ataques de diccionario dirigidos"
    }

    # Calculo de tiempo de cracking (WPA2 PBKDF2-HMAC-SHA1 a 4096 iteraciones)
    function Format-CrackTime([double]$combinations, [double]$hashRate) {
        if ($combinations -le 0) { return "< 1 segundo" }
        $seconds = ($combinations / 2.0) / $hashRate
        if ($seconds -lt 1) { return "< 1 segundo" }
        if ($seconds -lt 60) { return "$([Math]::Round($seconds, 0)) seg" }
        if ($seconds -lt 3600) { return "$([Math]::Round($seconds / 60, 1)) min" }
        if ($seconds -lt 86400) { return "$([Math]::Round($seconds / 3600, 1)) horas" }
        if ($seconds -lt 31536000) { return "$([Math]::Round($seconds / 86400, 1)) dias" }
        $years = $seconds / 31536000.0
        if ($years -lt 100) { return "$([Math]::Round($years, 1)) anos" }
        if ($years -lt 1000) { return "$([Math]::Round($years, 0)) anos" }
        if ($years -lt 1000000) { return "$([Math]::Round($years / 1000, 1))k anos" }
        return "+1 Millon de anos (Inviable)"
    }

    # Espacio total de busqueda acotado para prevenir overflow aritmetico
    $safeExp = [Math]::Min($len, 16)
    $combinations = [Math]::Pow($pool, $safeExp)
    if ($len -gt 16) {
        $combinations = [Math]::Pow($pool, 16) * [Math]::Pow(10, [Math]::Min($len - 16, 10))
    }

    # Tasas de Hash reales en WPA2-PBKDF2 (Hashcat -m 2500 / -m 22000)
    # CPU Core i7/i9: ~30 kH/s
    # GPU RTX 3060: ~350 kH/s
    # GPU RTX 4090: ~2.4 MH/s (2,400,000 H/s)
    # Cluster 8x RTX 4090: ~19.2 MH/s (19,200,000 H/s)
    return [PSCustomObject]@{
        Length          = $len
        PoolSize        = $pool
        EntropyBits     = $entropy
        ComplexityClass = $complexity
        PatternType     = $pattern
        SearchSpaceExp  = "Pool $pool ^ $len"
        TimeCPU         = (Format-CrackTime $combinations 30000)
        TimeRTX3060     = (Format-CrackTime $combinations 350000)
        TimeRTX4090     = (Format-CrackTime $combinations 2400000)
        TimeCluster     = (Format-CrackTime $combinations 19200000)
        NistCompliance  = $nist
    }
}



# ==============================================================================
# MODULO 1: RADAR EVIL TWIN EN VIVO (HUNTER)
# ==============================================================================
function Show-EvilTwinRadar {
    Show-Banner
    Write-Host "=== RADAR DE CAZA DE ATAQUES EVIL TWIN Y ROGUE AP EN VIVO ===`n" -ForegroundColor Cyan
    Write-Host "[*] Escaneando frecuencias de radio 2.4 GHz, 5 GHz y 6 GHz via interfaz WLAN..." -ForegroundColor Yellow

    $stored = Get-WiFiProfilesData
    $analysis = Get-EvilTwinAnalysis -StoredProfiles $stored

    if ($analysis.Count -eq 0) {
        Write-Host "`n[!] No se detectaron redes inalambricas en vivo." -ForegroundColor Yellow
        Write-Host "    Asegurate de que el adaptador Wi-Fi este encendido y habilitado." -ForegroundColor DarkGray
        Write-Host "`nPresiona cualquier tecla para volver al menu..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    Write-Host "`n[+] Redes y Puntos de Acceso detectados en el entorno: $($analysis.Count)" -ForegroundColor Green

    # Resumen de alertas
    $evilTwinAlerts = $analysis | Where-Object { $_.Status -eq "EVIL_TWIN_CRITICAL" }
    $downgrades = $analysis | Where-Object { $_.Status -eq "WARNING_DOWNGRADE" }
    $openNets = $analysis | Where-Object { $_.Status -eq "OPEN_UNENCRYPTED" }

    if ($evilTwinAlerts.Count -gt 0) {
        Write-Host "`n[!!!] PELIGRO CRITICO: SE HAN DETECTADO $($evilTwinAlerts.Count) PUNTOS DE ACCESO SOSPECHOSOS DE EVIL TWIN!" -ForegroundColor Red -BackgroundColor DarkRed
    } elseif ($downgrades.Count -gt 0) {
        Write-Host "`n[!] ADVERTENCIA: Se detectaron posibles discrepancias de cifrado en redes conocidas." -ForegroundColor Yellow
    } else {
        Write-Host "`n[OK] No se detectan anomalías directas de Evil Twin con los perfiles guardados actuales." -ForegroundColor Green
    }

    Write-Host "`n" + ("-" * 78) -ForegroundColor DarkGray
    Write-Host ("{0,-20} {1,-18} {2,-15} {3,-8} {4,-7} {5,-14}" -f "SSID", "BSSID (MAC AP)", "SEGURIDAD", "SENAL", "CANAL", "ESTADO") -ForegroundColor Cyan
    Write-Host ("-" * 78) -ForegroundColor DarkGray

    foreach ($item in $analysis) {
        $color = "DarkGray"
        $statusLabel = "[Vecina]"

        if ($item.Status -eq "EVIL_TWIN_CRITICAL") {
            $color = "Red"
            $statusLabel = "[EVIL TWIN!]"
        } elseif ($item.Status -eq "WARNING_DOWNGRADE") {
            $color = "Yellow"
            $statusLabel = "[Downgrade]"
        } elseif ($item.Status -eq "LEGITIMATE_MATCH") {
            $color = "Green"
            $statusLabel = "[Legitima]"
        } elseif ($item.Status -eq "OPEN_UNENCRYPTED") {
            $color = "Magenta"
            $statusLabel = "[Abierta]"
        }

        $ssidDisp = if ($item.SSID.Length -gt 19) { $item.SSID.Substring(0, 16) + "..." } else { $item.SSID }
        $authDisp = if ($item.Auth.Length -gt 14) { $item.Auth.Substring(0, 12) + ".." } else { $item.Auth }

        Write-Host ("{0,-20} {1,-18} {2,-15} {3,-8} {4,-7} " -f $ssidDisp, $item.BSSID, $authDisp, $item.Signal, $item.Channel) -NoNewline
        Write-Host ("{0,-14}" -f $statusLabel) -ForegroundColor $color
    }

    Write-Host ("-" * 78) -ForegroundColor DarkGray

    Write-Host "`n--- QUE ES UN ATAQUE EVIL TWIN Y COMO FUNCIONA? ---" -ForegroundColor White
    Write-Host "1. Tu computadora emite constantes ondas (Probe Requests) preguntando: 'Esta aqui mi red guardada?'." -ForegroundColor DarkGray
    Write-Host "2. Un atacante cercano con un dispositivo como Wi-Fi Pineapple o tarjeta Alfa capta esa peticion." -ForegroundColor DarkGray
    Write-Host "3. El atacante clona el nombre de tu red (SSID) con mayor potencia de senal y sin contrasena o con portal falso." -ForegroundColor DarkGray
    Write-Host "4. Tu equipo se conecta automaticamente al atacante, permitiendole interceptar y desviar todo tu trafico." -ForegroundColor DarkGray

    Write-Host "`nPresiona cualquier tecla para volver al menu principal..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ==============================================================================
# MODULO 2: MAPA DE CALOR WI-FI EN TIEMPO REAL (SENSOR DE PROXIMIDAD & RSSI)
# ==============================================================================
function Show-WiFiLiveHeatmap {
    $prevSignals = @{}
    $sweep = 0
    $keepRunning = $true

    while ($keepRunning) {
        $sweep++
        Clear-Host
        $timeStr = (Get-Date).ToString("HH:mm:ss")

        Write-Host "==========================================================================================" -ForegroundColor Cyan
        Write-Host "  MAPA DE CALOR WI-FI EN TIEMPO REAL (SENSOR DE PROXIMIDAD & RSSI TERMICO)" -ForegroundColor Cyan
        Write-Host "==========================================================================================" -ForegroundColor Magenta
        Write-Host "  Barrido #$sweep | Hora: $timeStr | Refresco: 2.5s | [Presiona 'Q' o ESC para salir]" -ForegroundColor White
        Write-Host "==========================================================================================`n" -ForegroundColor DarkGray

        $networks = Get-LiveWlanNetworks

        if ($networks.Count -eq 0) {
            Write-Host "[!] No se detectaron redes en este barrido. Adaptador escaneando el espectro..." -ForegroundColor Yellow
        } else {
            # Ordenar por senal descendente (la mas caliente arriba)
            $sorted = $networks | Sort-Object { [int]($_.Signal -replace '%','') } -Descending

            $hottest = $sorted[0]
            Write-Host "  [+] Puntos de Acceso detectados: $($sorted.Count) | Fuente mas intensa: $($hottest.SSID) ($($hottest.Signal))" -ForegroundColor Green
            Write-Host ("-" * 105) -ForegroundColor DarkGray
            Write-Host ("{0,-18} {1,-18} {2,-5} {3,-8} {4,-6} {5,-9} {6,-11} {7,-8} {8}" -f "SSID", "BSSID (MAC)", "CH", "BANDA", "SENAL", "EST.RSSI", "CALOR", "DELTA", "BARRA TERMICA (HEATMAP)") -ForegroundColor Cyan
            Write-Host ("-" * 105) -ForegroundColor DarkGray

            # Mostrar top 20 redes mas potentes en pantalla
            $displayList = $sorted | Select-Object -First 20

            foreach ($ap in $displayList) {
                $sigVal = [int]($ap.Signal -replace '%', '')
                $rssi = [math]::Round(($sigVal / 2) - 100)
                
                # Clasificacion termica
                $heatLabel = "FRIO"
                $heatColor = "Cyan"
                $icon = "[*]"
                if ($sigVal -ge 80) {
                    $heatLabel = "CRITICO"
                    $heatColor = "Red"
                    $icon = "[!]"
                } elseif ($sigVal -ge 65) {
                    $heatLabel = "ALTO"
                    $heatColor = "DarkYellow"
                    $icon = "[+]"
                } elseif ($sigVal -ge 45) {
                    $heatLabel = "MEDIO"
                    $heatColor = "Yellow"
                    $icon = "[~]"
                } elseif ($sigVal -ge 25) {
                    $heatLabel = "BAJO"
                    $heatColor = "Green"
                    $icon = "[-]"
                }

                # Variacion Delta (Movimiento relativo de la fuente)
                $deltaStr = "  0%"
                $deltaColor = "DarkGray"
                if ($prevSignals.ContainsKey($ap.BSSID)) {
                    $prev = $prevSignals[$ap.BSSID]
                    $diff = $sigVal - $prev
                    if ($diff -gt 0) {
                        $deltaStr = "+$diff%"
                        $deltaColor = "Red"
                    } elseif ($diff -lt 0) {
                        $deltaStr = "$diff%"
                        $deltaColor = "Cyan"
                    }
                }
                $prevSignals[$ap.BSSID] = $sigVal

                # Barra termica visual
                $barsCount = [math]::Round(($sigVal / 100) * 16)
                $bar = ([string]([char]9608) * $barsCount) + ([string]([char]9617) * (16 - $barsCount))

                $ssidShort = if ($ap.SSID.Length -gt 17) { $ap.SSID.Substring(0, 14) + "..." } else { $ap.SSID }
                $rssiStr = "$rssi dBm"
                $bandStr = if ($ap.Band) { $ap.Band } else { "2.4 GHz" }

                Write-Host ("{0,-18} {1,-18} {2,-5} {3,-8} {4,-6} {5,-9} " -f $ssidShort, $ap.BSSID, $ap.Channel, $bandStr, $ap.Signal, $rssiStr) -NoNewline
                Write-Host ("{0,-11} " -f "$icon $heatLabel") -ForegroundColor $heatColor -NoNewline
                Write-Host ("{0,-8} " -f $deltaStr) -ForegroundColor $deltaColor -NoNewline
                Write-Host ("[$bar]") -ForegroundColor $heatColor
            }

            Write-Host ("-" * 105) -ForegroundColor DarkGray

            # Top Canales mas calientes / saturados
            Write-Host "`nTOP CANALES MAS CONGESTIONADOS (CARGA ESPECTRAL DE CALOR):" -ForegroundColor White
            $channels = $sorted | Group-Object Channel | ForEach-Object {
                $chName = $_.Name
                $sigs = $_.Group | ForEach-Object { [int]($_.Signal -replace '%','') }
                $maxSig = ($sigs | Measure-Object -Maximum).Maximum
                $band = if ([int]$chName -gt 14) { "5 GHz" } else { "2.4 GHz" }
                [PSCustomObject]@{
                    Channel = $chName
                    Band    = $band
                    Count   = $_.Count
                    MaxHeat = $maxSig
                }
            } | Sort-Object MaxHeat -Descending | Select-Object -First 5

            foreach ($ch in $channels) {
                $chBar = [math]::Round(($ch.MaxHeat / 100) * 12)
                $chBarStr = ([string]([char]9608) * $chBar) + ([string]([char]9617) * (12 - $chBar))
                $chColor = if ($ch.MaxHeat -ge 75) { "Red" } elseif ($ch.MaxHeat -ge 50) { "Yellow" } else { "Green" }
                Write-Host ("  Canal {0,3} ({1,7}): " -f $ch.Channel, $ch.Band) -NoNewline
                Write-Host ("[{0}] {1,3}% Calor Max " -f $chBarStr, $ch.MaxHeat) -ForegroundColor $chColor -NoNewline
                Write-Host ("({0} APs saturando este canal)" -f $ch.Count) -ForegroundColor DarkGray
            }
        }

        Write-Host "`n[Radar activo - Actualizando cada 2.5s. Presiona 'Q' o ESC para salir]" -ForegroundColor DarkGray

        # Esperar 2.5s en sub-intervalos para detectar tecla inmediatamente
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Milliseconds 250
            try {
                if ($Host.UI.RawUI.KeyAvailable) {
                    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    if ($key.VirtualKeyCode -eq 81 -or $key.VirtualKeyCode -eq 27 -or $key.Character -eq 'q' -or $key.Character -eq 'Q') {
                        $keepRunning = $false
                        break
                    }
                }
            } catch {
                $keepRunning = $false
                break
            }
        }
    }
}

# ==============================================================================
# MODULO 3: CALCULADORA DE ENTROPIA Y ESTIMACION DE CRACKEO
# ==============================================================================
function Show-EntropyCalculator {
    do {
        Show-Banner
        Write-Host "=== CALCULADORA DE ENTROPIA & BENCHMARK DE CRACKEO GPU (HASHCAT) ===`n" -ForegroundColor Cyan
        Write-Host "  [1] Auditar Entropia y Tiempos de Crackeo de Redes Guardadas" -ForegroundColor Yellow
        Write-Host "  [2] Probar una Contrasena o Frase de Paso Personalizada (Simulador en Vivo)" -ForegroundColor Yellow
        Write-Host "  [0] Volver al Menu Principal`n" -ForegroundColor Red

        Write-Host "Selecciona una opcion (0-2): " -NoNewline
        $opt = Read-Host

        switch ($opt) {
            "1" {
                $profiles = Get-WiFiProfilesData | Where-Object { $_.KeyPresent -eq "Si" }
                if ($profiles.Count -eq 0) {
                    Write-Host "`n[!] No se encontraron redes guardadas con clave en claro para auditar." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                    continue
                }

                Write-Host "`n" + ("=" * 82) -ForegroundColor DarkGray
                Write-Host ("{0,-18} {1,-14} {2,-8} {3,-18} {4,-18}" -f "SSID", "LONG / ENTROPIA", "POOL", "ESTIMACION RTX 4090", "PATRON DETECTADO") -ForegroundColor Cyan
                Write-Host ("=" * 82) -ForegroundColor DarkGray

                foreach ($p in $profiles) {
                    $stats = Get-PasswordAuditStats -Password $p.KeyContent
                    $color = "Green"
                    if ($stats.EntropyBits -lt 45) { $color = "Red" }
                    elseif ($stats.EntropyBits -lt 65) { $color = "Yellow" }

                    $ssidShort = if ($p.SSID.Length -gt 17) { $p.SSID.Substring(0, 14) + ".." } else { $p.SSID }
                    $entStr = "$($stats.Length) car | $($stats.EntropyBits) b"
                    $patShort = if ($stats.PatternType.Length -gt 17) { $stats.PatternType.Substring(0, 15) + ".." } else { $stats.PatternType }

                    Write-Host ("{0,-18} {1,-14} {2,-8} " -f $ssidShort, $entStr, $stats.PoolSize) -NoNewline
                    Write-Host ("{0,-18} " -f $stats.TimeRTX4090) -ForegroundColor $color -NoNewline
                    Write-Host ("{0,-18}" -f $patShort) -ForegroundColor DarkGray
                }
                Write-Host ("=" * 82) -ForegroundColor DarkGray
                Write-Host "`nPresiona cualquier tecla para continuar..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "2" {
                Write-Host "`nIntroduce una contrasena o frase de paso a simular: " -NoNewline -ForegroundColor White
                $testPass = Read-Host
                if (-not $testPass) { continue }

                $s = Get-PasswordAuditStats -Password $testPass
                Write-Host "`n--- REPORTE DE ENTROPIA Y RESISTENCIA A FUERZA BRUTA ---" -ForegroundColor Cyan
                Write-Host "  Longitud total:              $($s.Length) caracteres"
                Write-Host "  Espacio de caracteres (Pool):$($s.PoolSize) caracteres posibles"
                Write-Host "  Entropia de Shannon/Keyspace:$($s.EntropyBits) bits" -ForegroundColor Yellow
                Write-Host "  Clasificacion de robustez:   $($s.ComplexityClass)" -ForegroundColor $(if ($s.EntropyBits -ge 65) { "Green" } elseif ($s.EntropyBits -ge 45) { "Yellow" } else { "Red" })
                Write-Host "  Patron identificado:         $($s.PatternType)"
                Write-Host "  Cumplimiento NIST SP 800-63B:$($s.NistCompliance)"

                Write-Host "`n--- TIEMPO ESTIMADO DE CRACKEO WPA2 (PBKDF2 4096 Rondas) ---" -ForegroundColor Magenta
                Write-Host "  [CPU] Multi-Core (30 kH/s):         $($s.TimeCPU)" -ForegroundColor White
                Write-Host "  [GPU] NVIDIA RTX 3060 (350 kH/s):   $($s.TimeRTX3060)" -ForegroundColor White
                Write-Host "  [GPU] NVIDIA RTX 4090 (2.4 MH/s):   $($s.TimeRTX4090)" -ForegroundColor Yellow
                Write-Host "  [CLOUD] Cluster 8x RTX 4090 (19.2M):$($s.TimeCluster)" -ForegroundColor $(if ($s.EntropyBits -ge 70) { "Green" } else { "Red" })

                Write-Host "`nPresiona cualquier tecla para continuar..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "0" { return }
        }
    } while ($true)
}



# ==============================================================================
# MODULO: AUDITORIA COMPLETA DE PERFILES CON SEMAFORO DE RIESGO
# ==============================================================================
function Show-AuditSummary {
    param([switch]$RevealPasswords)

    Show-Banner
    Write-Host "=== AUDITORIA COMPLETA DE PERFILES WI-FI (SEMAFORO DE RIESGO) ===`n" -ForegroundColor Cyan

    $profiles = Get-WiFiProfilesData

    if (@($profiles).Count -eq 0) {
        Write-Host "[!] No se detectaron perfiles Wi-Fi guardados en este equipo." -ForegroundColor Yellow
        if (-not $SoloAuditar) {
            Write-Host "`nPresiona cualquier tecla para continuar..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        return
    }

    $totalCount = @($profiles).Count
    $criticos = @($profiles | Where-Object { $_.Risk -eq "Critico" }).Count
    $advertencias = @($profiles | Where-Object { $_.Risk -eq "Advertencia" }).Count
    $seguros = @($profiles | Where-Object { $_.Risk -eq "Seguro" }).Count

    Write-Host "Resumen Forense:" -ForegroundColor White
    Write-Host "  Total de Redes Analizadas: $totalCount" -ForegroundColor White
    Write-Host "  [!] Criticas: $criticos | [~] Advertencias: $advertencias | [OK] Seguras: $seguros`n" -ForegroundColor Yellow

    Write-Host ("{0,-4} {1,-20} {2,-15} {3,-10} {4,-12} {5,-16}" -f "ID", "SSID", "SEGURIDAD", "AUTO-CONN", "RIESGO", "CLAVE") -ForegroundColor Cyan
    Write-Host ("-" * 80) -ForegroundColor DarkGray

    foreach ($p in $profiles) {
        $color = "Green"
        if ($p.Risk -eq "Critico") { $color = "Red" }
        elseif ($p.Risk -eq "Advertencia") { $color = "Yellow" }

        $keyDisplay = "--------"
        if ($p.KeyPresent -eq "No") {
            $keyDisplay = "<Sin Clave>"
        } elseif ($RevealPasswords) {
            $keyDisplay = $p.KeyContent
        } else {
            $keyDisplay = "********"
        }

        $ssidShort = if ($p.SSID.Length -gt 19) { $p.SSID.Substring(0, 16) + "..." } else { $p.SSID }
        $authShort = if ($p.Auth.Length -gt 14) { $p.Auth.Substring(0, 12) + ".." } else { $p.Auth }

        Write-Host ("{0,-4} {1,-20} {2,-15} {3,-10} " -f $p.ID, $ssidShort, $authShort, $p.AutoConnect) -NoNewline
        Write-Host ("{0,-12} " -f $p.Risk) -ForegroundColor $color -NoNewline
        Write-Host ("{0,-16}" -f $keyDisplay) -ForegroundColor DarkGray
    }

    Write-Host ("-" * 80) -ForegroundColor DarkGray

    if ($SoloAuditar) {
        return
    }

    Write-Host "`nOpciones disponibles:" -ForegroundColor White
    Write-Host "  [R] Revelar contrasenas en consola"
    Write-Host "  [D] Ver diagnostico detallado por ID de red"
    Write-Host "  [V] Volver al Menu Principal`n"

    Write-Host "Selecciona una opcion: " -NoNewline
    $opt = Read-Host

    if ($opt -match '^(r|revelar)$') {
        Show-AuditSummary -RevealPasswords
    } elseif ($opt -match '^(d|detalle)$') {
        Write-Host "Introduce el ID de la red: " -NoNewline
        $targetId = Read-Host
        $target = $profiles | Where-Object { $_.ID -eq [int]$targetId }
        if ($target) {
            Write-Host "`n--- DIAGNOSTICO DETALLADO: $($target.SSID) ---" -ForegroundColor Cyan
            Write-Host "  Autenticacion: $($target.Auth)"
            Write-Host "  Cifrado:       $($target.Cipher)"
            Write-Host "  Conexion:      $($target.AutoConnect)"
            Write-Host "  Tiene Clave:   $($target.KeyPresent)"
            if ($target.KeyPresent -eq "Si") {
                Write-Host "  Contrasena:    $($target.KeyContent)" -ForegroundColor Red
            }
            Write-Host "  Nivel Riesgo:  $($target.Risk)" -ForegroundColor $(if ($target.Risk -eq "Critico") { "Red" } else { "Yellow" })
            Write-Host "  Motivos:       $($target.Reasons)" -ForegroundColor Gray
            Write-Host "`nPresiona cualquier tecla para continuar..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-AuditSummary
        }
    }
}

# ==============================================================================
# MODULO 6: ASISTENTE DE LIMPIEZA & HARDENING
# ==============================================================================
function Invoke-NetworkHardening {
    Show-Banner
    Write-Host "=== ASISTENTE DE LIMPIEZA & HARDENING DE REDES WI-FI ===`n" -ForegroundColor Cyan
    Write-Host "Este asistente te permite eliminar perfiles antiguos y desactivar" -ForegroundColor White
    Write-Host "la conexion automatica a redes que no sean de total confianza.`n" -ForegroundColor White

    $profiles = Get-WiFiProfilesData

    Write-Host "Selecciona la accion de hardening que deseas realizar:" -ForegroundColor Yellow
    Write-Host "  [1] Desactivar conexion automatica en redes abiertas o sospechosas"
    Write-Host "  [2] Eliminar un perfil Wi-Fi especifico (Higiene Digital)"
    Write-Host "  [3] Eliminar todas las redes abiertas (Sin contrasena)"
    Write-Host "  [0] Volver al Menu Principal`n"

    Write-Host "Introduce tu opcion (0-3): " -NoNewline
    $action = Read-Host

    switch ($action) {
        "1" {
            $risky = $profiles | Where-Object { $_.Risk -eq "Critico" -and $_.AutoConnect -eq "Automatica" }
            if ($risky.Count -eq 0) {
                Write-Host "`n[OK] No hay redes criticas con conexion automatica activa." -ForegroundColor Green
            } else {
                foreach ($r in $risky) {
                    Write-Host "[*] Desactivando conexion automatica para: $($r.SSID)..." -ForegroundColor Yellow
                    netsh wlan set profileparameter name="$($r.SSID)" connectionmode=manual 2>&1 | Out-Null
                }
                Write-Host "[+] Accion completada con exito." -ForegroundColor Green
            }
        }
        "2" {
            Write-Host "`nIntroduce el nombre exacto de la red (SSID) que deseas eliminar: " -NoNewline
            $targetSSID = Read-Host
            if ($targetSSID) {
                Write-Host "[*] Eliminando perfil '$targetSSID'..." -ForegroundColor Yellow
                $res = netsh wlan delete profile name="$targetSSID" 2>&1
                Write-Host "[+] Resultado: $res" -ForegroundColor Green
            }
        }
        "3" {
            $openProfiles = $profiles | Where-Object { $_.Auth -match "Abierta|Open|None|Ninguno" }
            if ($openProfiles.Count -eq 0) {
                Write-Host "`n[OK] No tienes redes abiertas almacenadas en este equipo." -ForegroundColor Green
            } else {
                foreach ($op in $openProfiles) {
                    Write-Host "[*] Eliminando red abierta: $($op.SSID)..." -ForegroundColor Yellow
                    netsh wlan delete profile name="$($op.SSID)" 2>&1 | Out-Null
                }
                Write-Host "[+] Todas las redes abiertas han sido eliminadas." -ForegroundColor Green
            }
        }
        "0" { return }
    }

    Write-Host "`nPresiona cualquier tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ==============================================================================
# MODULO 7: GENERADOR DE DASHBOARD INTERACTIVO HTML CYBERPUNK CON TABULADORES
# ==============================================================================
function Export-HtmlAuditReport {
    Write-Host "`n[*] Recopilando telemetria WLAN forense y escaneo en vivo..." -ForegroundColor Yellow

    $profiles = Get-WiFiProfilesData
    $liveNets = Get-LiveWlanNetworks
    $evilTwinAnalysis = Get-EvilTwinAnalysis -LiveNetworks $liveNets -StoredProfiles $profiles

    $totalCount = $profiles.Count
    $criticalCount = ($profiles | Where-Object { $_.Risk -eq "Critico" }).Count
    $warningCount = ($profiles | Where-Object { $_.Risk -eq "Advertencia" }).Count
    $secureCount = ($profiles | Where-Object { $_.Risk -eq "Seguro" }).Count

    # Calculo de Puntuacion de Salud de Seguridad (0 a 100)
    $score = 100
    if ($totalCount -gt 0) {
        $score -= ($criticalCount * 30)
        $score -= ($warningCount * 12)
        if ($score -lt 0) { $score = 0 }
    }
    $scoreColor = "#00ff9d"
    if ($score -lt 50) { $scoreColor = "#ff0055" }
    elseif ($score -lt 75) { $scoreColor = "#ffb703" }

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $reportFile = Join-Path $ReportDir "WiFiSentry_Dashboard_$timestamp.html"
    if ($ExportarHTML -and $ExportarHTML.EndsWith(".html")) {
        $reportFile = $ExportarHTML
    }

    # Filas de tabla de inventario
    $tbodyProfiles = ""
    foreach ($p in $profiles) {
        $badgeClass = "badge-secure"
        if ($p.Risk -eq "Critico") { $badgeClass = "badge-critical" }
        elseif ($p.Risk -eq "Advertencia") { $badgeClass = "badge-warning" }

        $keyCell = "<span class='text-muted'>Sin Clave</span>"
        if ($p.KeyPresent -eq "Si") {
            $encKey = [System.Net.WebUtility]::HtmlEncode($p.KeyContent)
            $maskedKey = ("*" * [Math]::Min($p.KeyContent.Length, 12))
            $keyCell = "<span class='masked-key'>$maskedKey</span><span class='revealed-key' style='display:none;'>$encKey</span> <button class='btn-toggle' onclick='toggleKey(this)'>[Ver]</button> <button class='btn-copy' data-key='$encKey' onclick='copyKey(this)'>Copiar</button>"
        }

        $safeSsid = [System.Net.WebUtility]::HtmlEncode($p.SSID)
        $safeAuth = [System.Net.WebUtility]::HtmlEncode($p.Auth)
        $safeCipher = [System.Net.WebUtility]::HtmlEncode($p.Cipher)
        $safeReasons = [System.Net.WebUtility]::HtmlEncode($p.Reasons)

        $tbodyProfiles += @"
        <tr>
            <td style="color: var(--cyan); font-weight: bold;">$($p.ID)</td>
            <td class="ssid-title">$safeSsid</td>
            <td><span class="auth-pill">$safeAuth</span></td>
            <td>$safeCipher</td>
            <td>$($p.AutoConnect)</td>
            <td class="key-cell">$keyCell</td>
            <td><span class="badge $badgeClass">$($p.Risk)</span></td>
            <td class="reasons-cell">$safeReasons</td>
        </tr>
"@
    }

    # Tarjetas de Mapa de Calor (Heatmap)
    $heatmapCards = ""
    $sortedHeat = $liveNets | Sort-Object { [int]($_.Signal -replace '%','') } -Descending

    foreach ($net in $sortedHeat) {
        $sigVal = [int]($net.Signal -replace '%', '')
        $rssi = [math]::Round(($sigVal / 2) - 100)
        
        $heatClass = "heat-cold"
        $heatStatus = "FRIO / DISTANTE"
        $heatDist = "> 20 metros"
        $heatColor = "var(--heat-cold)"

        if ($sigVal -ge 80) {
            $heatClass = "heat-critical"
            $heatStatus = "CRITICO / INMEDIATO"
            $heatDist = "< 3 metros (Mismo habitaculo)"
            $heatColor = "var(--heat-critical)"
        } elseif ($sigVal -ge 65) {
            $heatClass = "heat-high"
            $heatStatus = "ALTO / MUY CERCANO"
            $heatDist = "~3 a 8 metros"
            $heatColor = "var(--heat-high)"
        } elseif ($sigVal -ge 45) {
            $heatClass = "heat-medium"
            $heatStatus = "MEDIO / TEMPLADO"
            $heatDist = "~8 a 15 metros"
            $heatColor = "var(--heat-medium)"
        } elseif ($sigVal -ge 25) {
            $heatClass = "heat-low"
            $heatStatus = "BAJO / TIBIO"
            $heatDist = "~15 a 25 metros"
            $heatColor = "var(--heat-low)"
        }

        $safeSsid = [System.Net.WebUtility]::HtmlEncode($net.SSID)
        $bandStr = if ($net.Band) { $net.Band } else { "2.4 GHz" }
        $channelStr = $net.Channel

        $heatmapCards += @"
        <div class="heat-card $heatClass" data-bssid="$($net.BSSID)" data-signal="$sigVal" data-channel="$channelStr" data-band="$bandStr">
            <div class="heat-card-header">
                <div>
                    <h3 class="heat-ssid">$safeSsid</h3>
                    <span class="heat-bssid">$($net.BSSID)</span>
                </div>
                <span class="heat-badge" style="background: $($heatColor)22; color: $heatColor; border: 1px solid $($heatColor)88;">$heatStatus</span>
            </div>
            
            <div class="heat-metrics">
                <div class="heat-metric">
                    <span class="heat-val heat-sig-display">$sigVal%</span>
                    <span class="heat-lbl">Potencia RF</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val heat-rssi-display">$rssi dBm</span>
                    <span class="heat-lbl">RSSI Estimado</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val" style="color: var(--cyan);">$channelStr</span>
                    <span class="heat-lbl">Canal ($bandStr)</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val heat-dist-display" style="font-size: 0.9rem; color: #cbd5e1;">$heatDist</span>
                    <span class="heat-lbl">Proximidad</span>
                </div>
            </div>

            <div class="heat-bar-container">
                <div class="heat-bar-fill" style="width: $sigVal%;"></div>
            </div>
        </div>
"@
    }

    $channelGroups = $sortedHeat | Group-Object Channel | ForEach-Object {
        $chName = $_.Name
        $sigs = $_.Group | ForEach-Object { [int]($_.Signal -replace '%','') }
        $maxSig = ($sigs | Measure-Object -Maximum).Maximum
        $band = if ([int]$chName -gt 14) { "5 GHz" } else { "2.4 GHz" }
        [PSCustomObject]@{
            Channel = $chName
            Band    = $band
            Count   = $_.Count
            MaxHeat = $maxSig
        }
    } | Sort-Object MaxHeat -Descending

    $spectrumBars = ""
    foreach ($ch in $channelGroups) {
        $chColor = "var(--heat-cold)"
        if ($ch.MaxHeat -ge 80) { $chColor = "var(--heat-critical)" }
        elseif ($ch.MaxHeat -ge 65) { $chColor = "var(--heat-high)" }
        elseif ($ch.MaxHeat -ge 45) { $chColor = "var(--heat-medium)" }
        elseif ($ch.MaxHeat -ge 25) { $chColor = "var(--heat-low)" }

        $spectrumBars += @"
        <div class="spectrum-bar-item">
            <div class="spectrum-bar-header">
                <span><strong>Canal $($ch.Channel)</strong> ($($ch.Band))</span>
                <span style="color: $chColor; font-family: var(--font-mono); font-weight: bold;">$($ch.MaxHeat)% Calor Max ($($ch.Count) APs)</span>
            </div>
            <div class="spectrum-bar-track">
                <div class="spectrum-bar-fill" style="width: $($ch.MaxHeat)%; background: $chColor;"></div>
            </div>
        </div>
"@
    }

    # Filas de Radar Evil Twin
    $tbodyRadar = ""
    foreach ($r in $evilTwinAnalysis) {
        $radarBadge = "badge-secure"
        if ($r.Status -eq "EVIL_TWIN_CRITICAL") { $radarBadge = "badge-critical" }
        elseif ($r.Status -eq "WARNING_DOWNGRADE" -or $r.Status -eq "OPEN_UNENCRYPTED") { $radarBadge = "badge-warning" }

        $safeSsid = [System.Net.WebUtility]::HtmlEncode($r.SSID)
        $safeDiag = [System.Net.WebUtility]::HtmlEncode($r.Diagnostic)
        $safeAuth = [System.Net.WebUtility]::HtmlEncode($r.Auth)

        $sigNum = 0
        if ($r.Signal -match '(\d+)') { $sigNum = [int]$matches[1] }
        $barWidth = $sigNum

        $tbodyRadar += @"
        <tr>
            <td class="ssid-title">$safeSsid</td>
            <td style="font-family: var(--font-mono); color: var(--cyan);">$($r.BSSID)</td>
            <td><span class="auth-pill">$safeAuth</span></td>
            <td>$($r.Channel)</td>
            <td>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="signal-bar-bg"><div class="signal-bar-fill" style="width: $barWidth%;"></div></div>
                    <span style="font-size: 0.8rem; font-family: var(--font-mono);">$($r.Signal)</span>
                </div>
            </td>
            <td><span class="badge $radarBadge">$($r.Badge)</span></td>
            <td class="reasons-cell">$safeDiag</td>
        </tr>
"@
    }

    # Filas de Calculadora de Entropia de Redes Guardadas
    $tbodyEntropy = ""
    foreach ($p in ($profiles | Where-Object { $_.KeyPresent -eq "Si" })) {
        $st = Get-PasswordAuditStats -Password $p.KeyContent
        $entBadge = "badge-secure"
        if ($st.EntropyBits -lt 45) { $entBadge = "badge-critical" }
        elseif ($st.EntropyBits -lt 65) { $entBadge = "badge-warning" }

        $safeSsid = [System.Net.WebUtility]::HtmlEncode($p.SSID)
        $safePattern = [System.Net.WebUtility]::HtmlEncode($st.PatternType)

        $tbodyEntropy += @"
        <tr>
            <td class="ssid-title">$safeSsid</td>
            <td style="font-family: var(--font-mono);">$($st.Length) caracteres</td>
            <td style="font-family: var(--font-mono);">$($st.PoolSize) vars</td>
            <td><span class="badge $entBadge">$($st.EntropyBits) bits</span></td>
            <td style="font-size: 0.85rem; color: #cbd5e1;">$safePattern</td>
            <td style="font-family: var(--font-mono); font-size: 0.85rem;">$($st.TimeCPU)</td>
            <td style="font-family: var(--font-mono); font-size: 0.85rem; color: #ffb703;">$($st.TimeRTX3060)</td>
            <td style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--cyan); font-weight: bold;">$($st.TimeRTX4090)</td>
            <td style="font-family: var(--font-mono); font-size: 0.85rem; color: #00ff9d;">$($st.TimeCluster)</td>
        </tr>
"@
    }

    $fechaStr = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFiSentry v3.0.0 | Centro de Operaciones Forenses WLAN</title>
    <style>
        :root {
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --border-card: #e2e8f0;
            --text-heading: #0f172a;
            --text-body: #334155;
            --text-muted: #64748b;
            --primary: #2563eb;
            --primary-light: #eff6ff;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.07);
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-page);
            color: var(--text-body);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            min-height: 100vh;
            line-height: 1.6;
        }

        .header {
            background: var(--bg-card);
            border-bottom: 2px solid var(--border-card);
            border-top: 4px solid var(--primary);
            padding: 20px 36px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: var(--shadow-sm);
        }
        .header-title h1 {
            font-size: 1.6rem;
            font-weight: 800;
            color: var(--text-heading);
            letter-spacing: -0.02em;
        }
        .header-title p { color: var(--text-muted); font-size: 0.9rem; margin-top: 2px; }
        .author-tag {
            background: var(--primary-light);
            border: 1px solid #bfdbfe;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--primary);
            font-weight: 600;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 25px 20px 60px 20px; }

        /* NAVEGACION TABULADA */
        .tabs-nav {
            display: flex;
            gap: 8px;
            background: #e2e8f0;
            padding: 4px;
            border-radius: 10px;
            margin-bottom: 25px;
            width: fit-content;
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-body);
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tab-btn:hover { color: var(--text-heading); }
        .tab-btn.active {
            background: #ffffff;
            color: var(--primary);
            box-shadow: var(--shadow-sm);
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* METRIC CARDS */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 18px;
            margin-bottom: 25px;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--shadow-sm);
            transition: transform 0.2s ease;
        }
        .metric-card:hover { transform: translateY(-2px); }
        .metric-title { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; color: var(--text-muted); }
        .metric-value { font-size: 2.2rem; font-weight: 800; margin: 6px 0; font-family: var(--font-mono); color: var(--text-heading); }
        .metric-desc { font-size: 0.75rem; color: var(--text-muted); }

        .section-box {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
            box-shadow: var(--shadow-sm);
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            border-bottom: 1px solid var(--border-card);
            padding-bottom: 12px;
            flex-wrap: wrap;
            gap: 12px;
        }
        .section-header h2 { font-size: 1.25rem; color: var(--text-heading); display: flex; align-items: center; gap: 8px; font-weight: 700; }
        
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.88rem; text-align: left; }
        th { background: #f8fafc; color: #475569; padding: 12px 14px; font-weight: 700; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.05em; border-bottom: 2px solid var(--border-card); }
        td { padding: 12px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
        tr:hover td { background: #f8fafc; }

        .ssid-title { font-weight: 700; color: var(--text-heading); font-size: 0.92rem; }
        .auth-pill { background: #eff6ff; color: #1e40af; border: 1px solid #dbeafe; padding: 3px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600; }
        .badge { padding: 3px 8px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; display: inline-block; }
        .badge-critical { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .badge-warning  { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
        .badge-secure   { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }

        .key-cell { font-family: var(--font-mono); white-space: nowrap; }
        .btn-toggle, .btn-copy { background: #f1f5f9; border: 1px solid #cbd5e1; color: var(--text-body); padding: 3px 8px; border-radius: 4px; cursor: pointer; margin-left: 4px; font-size: 0.75rem; font-weight: 600; }
        .btn-toggle:hover, .btn-copy:hover { background: #e2e8f0; }

        .signal-bar-bg { width: 90px; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }
        .signal-bar-fill { height: 100%; background: #16a34a; border-radius: 4px; }

        .reasons-cell { font-size: 0.8rem; color: #64748b; max-width: 320px; }

        /* HEATMAP STYLES */
        .heat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 15px;
            transition: transform 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .heat-card:hover { transform: translateY(-2px); }
        .heat-card.heat-critical { border-color: rgba(239, 68, 68, 0.4); box-shadow: 0 4px 20px rgba(239, 68, 68, 0.15); }
        .heat-card.heat-high { border-color: rgba(249, 115, 22, 0.4); box-shadow: 0 4px 20px rgba(249, 115, 22, 0.12); }
        .heat-card.heat-medium { border-color: rgba(234, 179, 8, 0.3); }
        .heat-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .heat-ssid { font-size: 1.15rem; font-weight: 700; color: #fff; margin: 0; }
        .heat-bssid { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted); }
        .heat-badge { padding: 5px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
        .heat-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 14px; }
        .heat-metric { background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); }
        .heat-val { display: block; font-size: 1.15rem; font-weight: 700; font-family: var(--font-mono); color: #fff; }
        .heat-lbl { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; }
        .heat-bar-container { height: 10px; background: rgba(255,255,255,0.06); border-radius: 5px; overflow: hidden; }
        .heat-bar-fill { height: 100%; background: linear-gradient(90deg, #06b6d4 0%, #10b981 30%, #eab308 60%, #f97316 85%, #ef4444 100%); border-radius: 5px; transition: width 0.8s ease; }

        .spectrum-bar-item { margin-bottom: 12px; }
        .spectrum-bar-header { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 5px; }
        .spectrum-bar-track { height: 8px; background: rgba(255,255,255,0.06); border-radius: 4px; overflow: hidden; }
        .spectrum-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }


        .search-bar {
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border-glow);
            padding: 8px 16px;
            border-radius: 8px;
            color: #fff;
            width: 260px;
            outline: none;
            font-size: 0.85rem;
        }
        .search-bar:focus { border-color: var(--cyan); }

        /* SIMULADOR DE ENTROPIA WIDGET */
        .simulator-box {
            background: linear-gradient(135deg, rgba(0,242,254,0.06), rgba(139,92,246,0.06));
            border: 1px solid rgba(0,242,254,0.3);
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 25px;
        }
        .sim-input {
            width: 100%;
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--border-glow);
            padding: 12px 18px;
            border-radius: 8px;
            color: #fff;
            font-size: 1.1rem;
            font-family: var(--font-mono);
            outline: none;
            margin: 12px 0 16px 0;
        }
        .sim-input:focus { border-color: var(--cyan); box-shadow: 0 0 15px rgba(0,242,254,0.25); }

        .entropy-meter-wrap {
            height: 12px;
            background: rgba(255,255,255,0.08);
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 18px;
        }
        .entropy-meter-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--red), var(--yellow), var(--green), var(--cyan));
            transition: width 0.3s ease;
        }

        .sim-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        .sim-stat-card {
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border-card);
            padding: 12px;
            border-radius: 8px;
            text-align: center;
        }
        .sim-stat-val { font-size: 1.3rem; font-weight: 700; font-family: var(--font-mono); color: var(--cyan); }
        .sim-stat-lbl { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }

        .crack-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 12px;
        }
        .crack-card {
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border-card);
            border-radius: 8px;
            padding: 12px 14px;
        }
        .crack-hw { font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; }
        .crack-rate { font-size: 0.75rem; color: var(--cyan); font-family: var(--font-mono); }
        .crack-time { font-size: 1.15rem; font-weight: 700; color: #fff; margin-top: 6px; font-family: var(--font-mono); }



        .educational-box {
            background: linear-gradient(135deg, rgba(0,242,254,0.05), rgba(16,185,129,0.03));
            border: 1px solid rgba(0,242,254,0.25);
            border-radius: 12px;
            padding: 22px;
            margin-top: 15px;
        }
        .educational-box h3 { color: var(--cyan); margin-bottom: 10px; font-size: 1.1rem; }
        .educational-box ul { padding-left: 20px; color: #cbd5e1; font-size: 0.88rem; }
        .educational-box li { margin-bottom: 8px; }

        .footer { text-align: center; color: var(--text-muted); font-size: 0.82rem; margin-top: 45px; }
        .footer a { color: var(--cyan); text-decoration: none; }
    </style>
</head>
<body>

    <header class="header">
        <div class="header-title">
            <h1>WiFiSentry v3.0.0</h1>
            <p>Suite DFIR de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo</p>
        </div>
        <div>
            <span class="author-tag">Ezequiel Diaz (Cru9)</span>
        </div>
    </header>

    <div class="container">

        <!-- NAVEGACION POR TABULADORES -->
        <div class="tabs-nav">
            <button class="tab-btn active" onclick="openTab('tab-dashboard')">📊 Resumen Ejecutivo</button>
            <button class="tab-btn" onclick="openTab('tab-heatmap')">🔥 Mapa de Calor Espectral ($($liveNets.Count))</button>
            <button class="tab-btn" onclick="openTab('tab-radar')">📡 Radar Evil Twin (Hunter)</button>
            <button class="tab-btn" onclick="openTab('tab-entropy')">🔐 Calculadora de Entropia & Crackeo</button>
            <button class="tab-btn" onclick="openTab('tab-profiles')">📋 Inventario Forense ($totalCount)</button>
            <button class="tab-btn" onclick="openTab('tab-hardening')">🔒 Manual & Cheatsheet</button>
        </div>

        <!-- TAB 1: DASHBOARD EJECUTIVO -->
        <div id="tab-dashboard" class="tab-content active">
            <div style="text-align: center; margin-bottom: 25px;">
                <img src="../assets/banner.jpg" alt="WiFiSentry Banner" style="width: 100%; max-height: 260px; object-fit: cover; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,242,254,0.25);" onerror="this.style.display='none'" />
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-title">Indice de Salud Inalambrica</div>
                    <div class="metric-value" style="color: $scoreColor;">$score / 100</div>
                    <div class="metric-desc">Puntuacion de postura defensiva y riesgo del endpoint</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Perfiles Guardados</div>
                    <div class="metric-value" style="color: var(--cyan);">$totalCount</div>
                    <div class="metric-desc">Redes registradas en el servicio WLAN AutoConfig</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Redes en Vivo Detectadas</div>
                    <div class="metric-value" style="color: var(--purple);">$($liveNets.Count)</div>
                    <div class="metric-desc">BSSIDs activos transmitiendo en el entorno radial</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Perfiles Criticos / Abiertos</div>
                    <div class="metric-value" style="color: var(--red);">$criticalCount</div>
                    <div class="metric-desc">Expuestas a clonacion Rogue AP y captura de trafico</div>
                </div>
            </div>

            <div class="section-box">
                <div class="section-header">
                    <h2>Estado Global de Seguridad Inalambrica</h2>
                </div>
                <p style="color: #cbd5e1; font-size: 0.95rem;">
                    Este informe fue generado de manera forense inspeccionando la configuracion WLAN del sistema.
                    Se evaluaron perfiles de red persistentes en Windows (protegidos mediante DPAPI), la presencia de puntos de acceso
                    en vivo transmitiendo en las inmediaciones y el grado de exposicion a ataques de clonacion <em>Evil Twin</em> y crackeo offline de contrasenas WPA2 mediante GPU clusters.
                </p>
                <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="tab-btn" onclick="openTab('tab-heatmap')" style="background: rgba(239,68,68,0.15); color: #ef4444; border-color: #ef4444;">Explorar Mapa de Calor en Vivo &rarr;</button>
                    <button class="tab-btn" onclick="openTab('tab-radar')" style="background: rgba(0,242,254,0.15); color: var(--cyan); border-color: var(--cyan);">Examinar Radar Evil Twin &rarr;</button>
                    <button class="tab-btn" onclick="openTab('tab-entropy')" style="background: rgba(139,92,246,0.15); color: var(--purple); border-color: var(--purple);">Auditar Entropia de Claves &rarr;</button>
                </div>
            </div>
        </div>

        <!-- TAB 2: MAPA DE CALOR ESPECTRAL -->
        <div id="tab-heatmap" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>🔥 Mapa de Calor Wi-Fi en Vivo (Sensor de Proximidad & RSSI Espectral)</h2>
                    <input type="text" id="filterHeatmapInput" class="search-bar" placeholder="Filtrar por SSID o BSSID..." onkeyup="filterHeatmapCards()">
                </div>
                <p style="color: var(--text-muted); font-size: 0.88rem; margin-bottom: 20px;">
                    Visualizacion termica de potencia de radiofrecuencia (RF) de todos los puntos de acceso detectados en las bandas 2.4 GHz y 5 GHz.
                    Permite identificar emisores fisicamente cercanos (&lt; 3 metros), posibles atacantes portatiles y saturacion de canales.
                </p>

                <div style="display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center;">
                    <button id="btnPulseSim" class="tab-btn" onclick="toggleHeatmapPulse()" style="background: rgba(239,68,68,0.15); color: #ef4444; border-color: #ef4444;">▶ Iniciar Pulso Termico en Vivo</button>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">Simula la fluctuacion de radiofrecuencia en tiempo real en el navegador</span>
                </div>

                <div class="heatmap-container">
$heatmapCards
                </div>

                <div style="margin-top: 30px;">
                    <h3 style="color: var(--cyan); margin-bottom: 12px; font-size: 1.1rem;">Saturacion Termica por Canal (Carga Espectral RF)</h3>
                    <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-card); border-radius: 10px; padding: 18px;">
$spectrumBars
                    </div>
                </div>

                <div class="educational-box" style="margin-top: 25px;">
                    <h3>Escala Termica y Diagnostico Forense de Proximidad</h3>
                    <ul>
                        <li><strong style="color: var(--heat-critical);">Zona Critica / Fuego (> 80% | > -50 dBm):</strong> Emisor a escasos metros o en el mismo habitaculo (&lt; 3m). Si es una red desconocida o clonada, indica presencia fisica inmediata de un atacante.</li>
                        <li><strong style="color: var(--heat-high);">Zona de Calor Alto (65% - 79% | -51 a -65 dBm):</strong> Cobertura optima y proximidad cercana (3 a 8 metros).</li>
                        <li><strong style="color: var(--heat-medium);">Zona Templada (45% - 64% | -66 a -75 dBm):</strong> Alcance normal de router domestico o empresarial a traves de 1 o 2 paredes (8 a 15 metros).</li>
                        <li><strong style="color: var(--heat-low);">Zona Tibia / Lejana (25% - 44% | -76 a -85 dBm):</strong> Senal atenuada por multiples obstaculos (15 a 25 metros).</li>
                        <li><strong style="color: var(--heat-cold);">Zona Fria (&lt; 25% | &lt; -85 dBm):</strong> Limite de recepcion radial (&gt; 25 metros).</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- TAB 3: RADAR EVIL TWIN -->
        <div id="tab-radar" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>📡 Radar de Caza de Ataques Evil Twin & Rogue AP en Vivo</h2>
                    <input type="text" id="filterRadarInput" class="search-bar" placeholder="Filtrar por SSID o BSSID..." onkeyup="filterRadarTable()">
                </div>
                <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 15px;">
                    Compara en tiempo real las tramas beacon de los puntos de acceso cercanos con los perfiles autorizados y guardados en tu sistema para detectar suplantaciones y degradaciones maliciosas.
                </p>
                <div class="table-responsive">
                    <table id="radarTable">
                        <thead>
                            <tr>
                                <th>Nombre de Red (SSID)</th>
                                <th>BSSID (Direccion MAC AP)</th>
                                <th>Autenticacion</th>
                                <th>Canal</th>
                                <th>Senal</th>
                                <th>Estado Radar</th>
                                <th>Diagnostico Forense</th>
                            </tr>
                        </thead>
                        <tbody>
$tbodyRadar
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="educational-box">
                <h3>Como opera un ataque Evil Twin (Gemelo Malvado)?</h3>
                <ul>
                    <li><strong>Emision de Probe Requests:</strong> Los dispositivos emiten constantemente peticiones broadcast con el nombre de sus redes conocidas.</li>
                    <li><strong>Clonacion Inmediata:</strong> Los atacantes con herramientas como <em>Wi-Fi Pineapple</em> capturan el SSID y levantan un AP falso con potencia superior para que tu equipo se asocie de forma preferente.</li>
                    <li><strong>Degradacion a Red Abierta:</strong> Si tu red original es WPA2, el atacante puede forzar un punto abierto para capturar trafico mediante un portal cautivo falso que simule una actualizacion de router o login corporativo.</li>
                </ul>
            </div>
        </div>

        <!-- TAB 3: CALCULADORA DE ENTROPIA & CRACKEO -->
        <div id="tab-entropy" class="tab-content">
            <!-- WIDGET INTERACTIVO -->
            <div class="simulator-box">
                <h3 style="color: var(--cyan); margin-bottom: 6px;">Simulador Interactivo de Entropia & Estimacion de Crackeo (Hashcat)</h3>
                <p style="color: var(--text-muted); font-size: 0.85rem;">Prueba cualquier contrasena o frase de paso en tiempo real para evaluar su resistencia ante ataques de fuerza bruta asistidos por hardware GPU:</p>
                
                <input type="text" id="liveEntropyInput" class="sim-input" placeholder="Escribe cualquier contrasena o frase de paso de prueba..." oninput="simulateEntropy(this.value)">

                <div class="entropy-meter-wrap">
                    <div id="liveMeterFill" class="entropy-meter-fill"></div>
                </div>

                <div class="sim-stats-grid">
                    <div class="sim-stat-card">
                        <div id="simLen" class="sim-stat-val">0</div>
                        <div class="sim-stat-lbl">Longitud Caracteres</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simPool" class="sim-stat-val">0</div>
                        <div class="sim-stat-lbl">Variedad (Pool)</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simBits" class="sim-stat-val">0.0 b</div>
                        <div class="sim-stat-lbl">Entropia Estimada</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simClass" class="sim-stat-val" style="font-size: 1rem;">Vacio</div>
                        <div class="sim-stat-lbl">Nivel de Fortaleza</div>
                    </div>
                </div>

                <div class="crack-grid">
                    <div class="crack-card">
                        <div class="crack-hw">CPU Multi-Core</div>
                        <div class="crack-rate">30 kH/s</div>
                        <div id="simCpuTime" class="crack-time">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">NVIDIA RTX 3060</div>
                        <div class="crack-rate">350 kH/s</div>
                        <div id="sim3060Time" class="crack-time">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">NVIDIA RTX 4090</div>
                        <div class="crack-rate">2.4 MH/s</div>
                        <div id="sim4090Time" class="crack-time" style="color: var(--cyan);">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">Cluster Cloud (8x 4090)</div>
                        <div class="crack-rate">19.2 MH/s</div>
                        <div id="simClusterTime" class="crack-time" style="color: var(--green);">&lt; 1 seg</div>
                    </div>
                </div>
            </div>

            <!-- TABLA DE CLAVES GUARDADAS -->
            <div class="section-box">
                <div class="section-header">
                    <h2>Auditoria de Entropia de Redes Almacenadas en este Equipo</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>SSID</th>
                                <th>Longitud</th>
                                <th>Pool</th>
                                <th>Entropia</th>
                                <th>Patron Detectado</th>
                                <th>CPU (30k)</th>
                                <th>RTX 3060 (350k)</th>
                                <th>RTX 4090 (2.4M)</th>
                                <th>Cluster 8x GPU</th>
                            </tr>
                        </thead>
                        <tbody>
$tbodyEntropy
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: INVENTARIO FORENSE -->
        <div id="tab-profiles" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>Inventario Forense de Perfiles Guardados (Cache DPAPI)</h2>
                    <input type="text" id="filterProfilesInput" class="search-bar" placeholder="Buscar por SSID, seguridad o riesgo..." onkeyup="filterProfilesTable()">
                </div>
                <div class="table-responsive">
                    <table id="profilesTable">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>SSID</th>
                                <th>Autenticacion</th>
                                <th>Cifrado</th>
                                <th>Conexion</th>
                                <th>Clave en Claro (DPAPI)</th>
                                <th>Riesgo</th>
                                <th>Diagnostico Forense</th>
                            </tr>
                        </thead>
                        <tbody>
$tbodyProfiles
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 6: MANUAL & CHEATSHEET -->
        <div id="tab-hardening" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>Manual Didactico de Hardening & Cheatsheet Multiplataforma</h2>
                </div>

                <div style="text-align: center; margin: 15px 0;">
                    <img src="../assets/wifi_threat_matrix.jpg" alt="Matriz de Riesgo Inalambrico" style="max-width: 100%; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.7);" onerror="this.style.display='none'" />
                </div>

                <div class="educational-box">
                    <h3>Reglas de Oro de Seguridad Inalambrica</h3>
                    <ul>
                        <li><strong>Bloqueo Inmediato de Pantalla (Windows + L):</strong> En 10 segundos, un atacante con acceso fisico a tu ordenador desbloqueado puede ejecutar <code>netsh wlan show profile name="X" key=clear</code> y obtener tus contrasenas Wi-Fi personales y de la empresa.</li>
                        <li><strong>Eliminacion Periodica de Redes Antiguas:</strong> Borra perfiles de hoteles, aeropuertos y cafeterias ejecutando <code>netsh wlan delete profile name="NombreRed"</code> en PowerShell como Administrador.</li>
                        <li><strong>Desactivar Conexion Automatica:</strong> En redes no corporativas, establece el modo de conexion en manual con <code>netsh wlan set profileparameter name="Nombre" connectionmode=manual</code> para evitar que tu PC emita Probe Requests en publico.</li>
                        <li><strong>Uso de Passphrases (>16 caracteres):</strong> La complejidad en WPA2 debe ser de longitud. Una frase de 4 palabras aleatorias (ej: <code>tortuga-cable-saturno-viento</code>) ofrece mas de 75 bits de entropia y resiste ataques de supercomputadoras por siglos.</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generado de forma automatizada por <strong>WiFiSentry v3.0.0</strong> | Ecosistema DFIR Cru9 | <a href="https://github.com/Cru9" target="_blank">github.com/Cru9</a></p>
            <p style="margin-top: 5px; opacity: 0.6;">Fecha de auditoria forense: $fechaStr</p>
        </div>

    </div>

    <script>
        function openTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(tb => tb.classList.remove('active'));
            const target = document.getElementById(tabId);
            if (target) target.classList.add('active');
            event.currentTarget.classList.add('active');
        }

        function toggleKey(btn) {
            const cell = btn.parentElement;
            const masked = cell.querySelector('.masked-key');
            const revealed = cell.querySelector('.revealed-key');
            if (masked.style.display === 'none') {
                masked.style.display = 'inline';
                revealed.style.display = 'none';
                btn.textContent = '[Ver]';
            } else {
                masked.style.display = 'none';
                revealed.style.display = 'inline';
                btn.textContent = '[Ocultar]';
            }
        }

        function copyKey(btn) {
            const text = btn.getAttribute('data-key');
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {
                const orig = btn.textContent;
                btn.textContent = 'Copiado!';
                setTimeout(() => { btn.textContent = orig; }, 1500);
            });
        }

        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Contrasena copiada al portapapeles');
            });
        }

        function filterProfilesTable() {
            const input = document.getElementById('filterProfilesInput').value.toLowerCase();
            const rows = document.querySelectorAll('#profilesTable tbody tr');
            rows.forEach(row => {
                row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none';
            });
        }

        let pulseInterval = null;
        function toggleHeatmapPulse() {
            const btn = document.getElementById('btnPulseSim');
            if (pulseInterval) {
                clearInterval(pulseInterval);
                pulseInterval = null;
                btn.textContent = '▶ Iniciar Pulso Termico en Vivo';
                btn.style.background = 'rgba(239,68,68,0.15)';
                btn.style.color = '#ef4444';
            } else {
                btn.textContent = '⏸ Detener Pulso en Vivo';
                btn.style.background = 'rgba(16,185,129,0.2)';
                btn.style.color = '#10b981';
                
                pulseInterval = setInterval(() => {
                    document.querySelectorAll('.heat-card').forEach(card => {
                        const baseSig = parseInt(card.getAttribute('data-signal')) || 50;
                        const delta = Math.floor(Math.random() * 9) - 4;
                        let curSig = Math.max(5, Math.min(100, baseSig + delta));
                        const rssi = Math.round((curSig / 2) - 100);
                        
                        const sigDisplay = card.querySelector('.heat-sig-display');
                        const rssiDisplay = card.querySelector('.heat-rssi-display');
                        const barFill = card.querySelector('.heat-bar-fill');
                        
                        if (sigDisplay) sigDisplay.textContent = curSig + '%';
                        if (rssiDisplay) rssiDisplay.textContent = rssi + ' dBm';
                        if (barFill) barFill.style.width = curSig + '%';
                    });
                }, 1600);
            }
        }

        function filterHeatmapCards() {
            const q = document.getElementById('filterHeatmapInput').value.toLowerCase();
            document.querySelectorAll('.heat-card').forEach(card => {
                const text = card.innerText.toLowerCase();
                card.style.display = text.includes(q) ? '' : 'none';
            });
        }

        function filterRadarTable() {
            const input = document.getElementById('filterRadarInput').value.toLowerCase();
            const rows = document.querySelectorAll('#radarTable tbody tr');
            rows.forEach(row => {
                row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none';
            });
        }

        function formatCrackTime(seconds) {
            if (seconds < 1) return '< 1 seg';
            if (seconds < 60) return Math.round(seconds) + ' seg';
            if (seconds < 3600) return (seconds / 60).toFixed(1) + ' min';
            if (seconds < 86400) return (seconds / 3600).toFixed(1) + ' horas';
            if (seconds < 31536000) return (seconds / 86400).toFixed(1) + ' dias';
            const years = seconds / 31536000;
            if (years < 100) return years.toFixed(1) + ' anos';
            if (years < 1000) return Math.round(years) + ' anos';
            if (years < 1000000) return (years / 1000).toFixed(1) + 'k anos';
            return '+1 Millon de anos';
        }

        function simulateEntropy(val) {
            if (!val) {
                document.getElementById('simLen').textContent = '0';
                document.getElementById('simPool').textContent = '0';
                document.getElementById('simBits').textContent = '0.0 b';
                document.getElementById('simClass').textContent = 'Vacio';
                document.getElementById('simClass').style.color = '#94a3b8';
                document.getElementById('liveMeterFill').style.width = '0%';
                document.getElementById('simCpuTime').textContent = '< 1 seg';
                document.getElementById('sim3060Time').textContent = '< 1 seg';
                document.getElementById('sim4090Time').textContent = '< 1 seg';
                document.getElementById('simClusterTime').textContent = '< 1 seg';
                return;
            }

            const len = val.length;
            let pool = 0;
            if (/[a-z]/.test(val)) pool += 26;
            if (/[A-Z]/.test(val)) pool += 26;
            if (/[0-9]/.test(val)) pool += 10;
            if (/[^a-zA-Z0-9]/.test(val)) pool += 33;
            if (pool === 0) pool = 10;

            const bits = (len * (Math.log(pool) / Math.log(2))).toFixed(1);
            document.getElementById('simLen').textContent = len;
            document.getElementById('simPool').textContent = pool + ' chars';
            document.getElementById('simBits').textContent = bits + ' bits';

            const fill = document.getElementById('liveMeterFill');
            const classEl = document.getElementById('simClass');
            const pct = Math.min(Math.round((bits / 85) * 100), 100);
            fill.style.width = pct + '%';

            if (bits < 40) {
                classEl.textContent = 'Critica / Muy Debil';
                classEl.style.color = 'var(--red)';
            } else if (bits < 60) {
                classEl.textContent = 'Moderada';
                classEl.style.color = 'var(--yellow)';
            } else if (bits < 80) {
                classEl.textContent = 'Robusta';
                classEl.style.color = 'var(--green)';
            } else {
                classEl.textContent = 'Nivel Militar / Solida';
                classEl.style.color = 'var(--cyan)';
            }

            const safeExp = Math.min(len, 16);
            let combinations = Math.pow(pool, safeExp);
            if (len > 16) {
                combinations = Math.pow(pool, 16) * Math.pow(10, Math.min(len - 16, 10));
            }

            const secCpu = (combinations / 2) / 30000;
            const sec3060 = (combinations / 2) / 350000;
            const sec4090 = (combinations / 2) / 2400000;
            const secCluster = (combinations / 2) / 19200000;

            document.getElementById('simCpuTime').textContent = formatCrackTime(secCpu);
            document.getElementById('sim3060Time').textContent = formatCrackTime(sec3060);
            document.getElementById('sim4090Time').textContent = formatCrackTime(sec4090);
            document.getElementById('simClusterTime').textContent = formatCrackTime(secCluster);
        }
    </script>
</body>
</html>
"@

    Set-Content -Path $reportFile -Value $html -Encoding UTF8
    Write-Host "`n[+] Dashboard HTML interactivo generado con exito en:" -ForegroundColor Green
    Write-Host "  $reportFile" -ForegroundColor Cyan
    
    if (-not $ExportarHTML) {
        Start-Process $reportFile
    }
}

# ==============================================================================
# MODULO 8: CHEATSHEET MULTIPLATAFORMA
# ==============================================================================
function Show-MultiplatformCheatsheet {
    Show-Banner
    Write-Host "=== CHEATSHEET MULTIPLATAFORMA DE AUDITORIA WLAN ===`n" -ForegroundColor Cyan

    Write-Host "WINDOWS (PowerShell / CMD)" -ForegroundColor White
    Write-Host "  1. Ver perfiles guardados:" -ForegroundColor Yellow
    Write-Host "     netsh wlan show profiles"
    Write-Host "  2. Ver contrasena en texto claro:" -ForegroundColor Yellow
    Write-Host "     netsh wlan show profile name=""NOMBRE_RED"" key=clear"
    Write-Host "  3. Escanear redes en vivo con BSSID y senal:" -ForegroundColor Yellow
    Write-Host "     netsh wlan show networks mode=bssid"
    Write-Host "  4. Borrar red guardada (Higiene):" -ForegroundColor Yellow
    Write-Host "     netsh wlan delete profile name=""NOMBRE_RED"""
    Write-Host "  5. Desactivar conexion automatica:" -ForegroundColor Yellow
    Write-Host "     netsh wlan set profileparameter name=""NOMBRE_RED"" connectionmode=manual`n"

    Write-Host "macOS (Terminal)" -ForegroundColor White
    Write-Host "  1. Extraer contrasena del Keychain del sistema:" -ForegroundColor Yellow
    Write-Host "     security find-generic-password -wa ""NOMBRE_RED"""
    Write-Host "  2. Escanear puntos de acceso cercanos:" -ForegroundColor Yellow
    Write-Host "     /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s`n"

    Write-Host "LINUX (Terminal / Bash)" -ForegroundColor White
    Write-Host "  1. Ver contrasena de la red Wi-Fi actual (NetworkManager):" -ForegroundColor Yellow
    Write-Host "     nmcli device wifi show-password"
    Write-Host "  2. Volcar todas las contrasenas guardadas en el sistema:" -ForegroundColor Yellow
    Write-Host "     sudo grep -r '^psk=' /etc/NetworkManager/system-connections/"
    Write-Host "  3. Escanear redes cercanas con intensidad y canal:" -ForegroundColor Yellow
    Write-Host "     nmcli device wifi list`n"

    Write-Host "----------------------------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "Presiona cualquier tecla para volver al Menu Principal..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ==============================================================================
# BUCLE PRINCIPAL / MENU
# ==============================================================================
function Main {
    if ($SoloAuditar) {
        Show-AuditSummary -RevealPasswords:$RevelarClaves
        return
    }
    if ($RadarEvilTwin) {
        Show-EvilTwinRadar
        return
    }
    if ($MapaCalor) {
        Show-WiFiLiveHeatmap
        return
    }
    if ($CalculadoraEntropia) {
        Show-EntropyCalculator
        return
    }
    if ($ExportarHTML) {
        Export-HtmlAuditReport
        return
    }

    do {
        Show-Banner
        Write-Host "   SELECCIONA UNA OPCION:" -ForegroundColor White
        Write-Host "  [1] Auditoria Completa de Perfiles (Tabla con Semaforo de Riesgo)" -ForegroundColor Cyan
        Write-Host "  [2] Radar Evil Twin en Vivo (Deteccion de Rogue AP y Downgrade Attack)" -ForegroundColor Green
        Write-Host "  [3] Mapa de Calor Wi-Fi en Tiempo Real (Heatmap de Senal & Proximidad)" -ForegroundColor Red
        Write-Host "  [4] Calculadora de Entropia & Estimacion de Crackeo (Hashcat / GPU)" -ForegroundColor Yellow
        Write-Host "  [5] Asistente de Limpieza & Hardening (Eliminar redes / Auto-conectar)" -ForegroundColor Cyan
        Write-Host "  [6] Generar Reporte Visual Interactivo (Dashboard HTML Cyberpunk)" -ForegroundColor Cyan
        Write-Host "  [7] Guia de Comandos Multiplataforma (Cheatsheet Windows / Mac / Linux)" -ForegroundColor Cyan
        Write-Host "  [0] Salir`n" -ForegroundColor Red

        Write-Host "Introduce tu opcion (0-7): " -NoNewline
        $choice = Read-Host

        switch ($choice) {
            "1" { Show-AuditSummary }
            "2" { Show-EvilTwinRadar }
            "3" { Show-WiFiLiveHeatmap }
            "4" { Show-EntropyCalculator }
            "5" { Invoke-NetworkHardening }
            "6" { Export-HtmlAuditReport }
            "7" { Show-MultiplatformCheatsheet }
            "0" { 
                Write-Host "`n[+] Gracias por usar WiFiSentry! Cuida tu postura de seguridad inalambrica." -ForegroundColor Green
                exit 0
            }
            Default {
                Write-Host "`n[!] Opcion no reconocida. Intenta de nuevo." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

Main
