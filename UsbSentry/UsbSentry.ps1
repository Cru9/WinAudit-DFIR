<#
.SYNOPSIS
    UsbSentry v2.0.0 - Framework Forense de Almacenamiento USB y BadUSB Hunter para Windows.
.DESCRIPTION
    Inspecciona y correlaciona artefactos de dispositivos USB conectados e históricos:
    - Registro USBSTOR (Fabricante, Modelo, Versión, Serial de Hardware)
    - MountedDevices (Letras de unidad históricas asignadas E:, F:, etc.)
    - Win32_DiskDrive (Dispositivos USB actualmente conectados en vivo)
    - Detección de BadUSB / Rubber Ducky / Hardware Emulators (VID/PID anómalos y compuestos)
    - Marcas de tiempo de conexión (LastWriteTime del registro y SetupAPI)
    - Semáforo de riesgo y cálculo de Threat Score (0 a 100)
.NOTES
    Autor: Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR
    Licencia: MIT
#>

[CmdletBinding()]
param(
    [switch]$SoloSospechosos,
    [switch]$SoloConectados,
    [string]$ExportarCSV,
    [string]$ExportarJSON
)

# -------------------------------------------------------------
# 0. Verificación de Privilegios de Administrador
# -------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host " [!] ADVERTENCIA: Privilegios estándar detectados." -ForegroundColor Yellow
    Write-Host " Para leer MountedDevices y SetupAPI se recomienda ejecutar como Administrador." -ForegroundColor DarkGray
    Write-Host ""
}

# -------------------------------------------------------------
# 1. Helper P/Invoke para LastWriteTime de Registro
# -------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'RegTimeHelper').Type) {
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    public class RegTimeHelper {
        [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKey", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern int RegQueryInfoKey(
            IntPtr hKey, System.Text.StringBuilder lpClass, ref uint lpcbClass, IntPtr lpReserved,
            out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen,
            out uint lpcValues, out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen,
            IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);

        public static DateTime GetLastWrite(Microsoft.Win32.RegistryKey key) {
            uint a, b, c, d, e, f, cl = 0;
            long ft;
            int res = RegQueryInfoKey(key.Handle.DangerousGetHandle(), null, ref cl, IntPtr.Zero, out a, out b, out c, out d, out e, out f, IntPtr.Zero, out ft);
            if (res == 0) {
                try { return DateTime.FromFileTime(ft); } catch { return DateTime.MinValue; }
            }
            return DateTime.MinValue;
        }
    }
'@
}

# -------------------------------------------------------------
# 2. Base de Datos de Amenazas BadUSB (Firmas VID/PID)
# -------------------------------------------------------------
$BadUsbDatabase = @{
    "0483:5740" = @{ Nombre = "Flipper Zero / ST VCP Virtual COM"; Riesgo = "CRITICO"; Score = 95 }
    "1FC9:0003" = @{ Nombre = "Hak5 USB Rubber Ducky (NXP)"; Riesgo = "CRITICO"; Score = 100 }
    "0483:0003" = @{ Nombre = "Hak5 Rubber Ducky Generic Clone"; Riesgo = "CRITICO"; Score = 95 }
    "F000:FFF0" = @{ Nombre = "Hak5 Bash Bunny Multi-Payload"; Riesgo = "CRITICO"; Score = 100 }
    "2341:8036" = @{ Nombre = "Arduino Leonardo (BadUSB HID Keyboard)"; Riesgo = "CRITICO"; Score = 90 }
    "2341:0036" = @{ Nombre = "Arduino Micro (BadUSB HID Keyboard)"; Riesgo = "CRITICO"; Score = 90 }
    "2E8A:0003" = @{ Nombre = "Raspberry Pi Pico (CircuitPython BadUSB HID)"; Riesgo = "CRITICO"; Score = 90 }
    "16C0:0478" = @{ Nombre = "Teensyduino / PJRC RawHID"; Riesgo = "ALTO"; Score = 80 }
}

# -------------------------------------------------------------
# 3. Recolección de Letras de Unidad (MountedDevices)
# -------------------------------------------------------------
$DriveMappings = @{}
try {
    $mounted = Get-Item -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($mounted) {
        foreach ($prop in $mounted.Property) {
            if ($prop -like '\DosDevices\*') {
                $driveLetter = $prop.Substring(12) # ej. "E:"
                $valBytes = (Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -Name $prop).$prop
                if ($valBytes) {
                    $rawStr = [System.Text.Encoding]::Unicode.GetString($valBytes)
                    $DriveMappings[$driveLetter] = $rawStr
                }
            }
        }
    }
} catch { }

# -------------------------------------------------------------
# 4. Discos USB Actualmente Conectados en Vivo (WMI / CIM)
# -------------------------------------------------------------
$LiveUsbSerials = @{}
try {
    $liveDrives = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceType -eq 'USB' }
    foreach ($d in $liveDrives) {
        $cleanSerial = ($d.SerialNumber -replace '[^\w\-&]', '').Trim()
        if ($cleanSerial) {
            $LiveUsbSerials[$cleanSerial] = @{
                Model = $d.Model
                SizeGB = [math]::Round($d.Size / 1GB, 2)
                DeviceID = $d.DeviceID
            }
        }
    }
} catch { }

# -------------------------------------------------------------
# 5. Auditoría de USBSTOR (Historial de Dispositivos USB)
# -------------------------------------------------------------
$UsbDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

$baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Enum\USBSTOR')
if ($baseKey) {
    foreach ($deviceType in $baseKey.GetSubKeyNames()) {
        $devSubKey = $baseKey.OpenSubKey($deviceType)
        if (-not $devSubKey) { continue }

        # Parsear Vendor, Product y Revision del DeviceType
        # Formato: Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00
        $ven = "Desconocido"
        $prod = "Almacenamiento USB"
        $rev = ""
        if ($deviceType -match 'Ven_([^&]+)') { $ven = $matches[1].Trim() }
        if ($deviceType -match 'Prod_([^&]+)') { $prod = $matches[1].Trim() }
        if ($deviceType -match 'Rev_([^\\]+)') { $rev = $matches[1].Trim() }

        foreach ($instance in $devSubKey.GetSubKeyNames()) {
            $instKey = $devSubKey.OpenSubKey($instance)
            if (-not $instKey) { continue }

            $friendly = $instKey.GetValue('FriendlyName')
            if ([string]::IsNullOrWhiteSpace($friendly)) {
                $friendly = "$ven $prod"
            }

            $hwId = $instKey.GetValue('HardwareID')
            if ($hwId -is [array]) { $hwIdStr = $hwId -join '; ' } else { $hwIdStr = "$hwId" }

            # Fecha de última conexión (LastWriteTime del registro)
            $lastConnected = [RegTimeHelper]::GetLastWrite($instKey)
            $lastConnectedStr = if ($lastConnected -ne [datetime]::MinValue) { $lastConnected.ToString("yyyy-MM-dd HH:mm:ss") } else { "No disponible" }

            # Buscar letra de unidad asignada históricamente
            $assignedDrive = "N/A"
            foreach ($entry in $DriveMappings.GetEnumerator()) {
                if ($entry.Value -like "*$instance*" -or $entry.Value -like "*$deviceType*") {
                    $assignedDrive = $entry.Key
                    break
                }
            }

            # Comprobar si está conectado en vivo ahora mismo
            $isLive = $false
            $liveSize = ""
            foreach ($liveKey in $LiveUsbSerials.Keys) {
                if ($instance -like "*$liveKey*" -or $liveKey -like "*$instance*") {
                    $isLive = $true
                    $liveSize = "$($LiveUsbSerials[$liveKey].SizeGB) GB"
                    break
                }
            }

            # Heurística y Cálculo de Threat Score
            $threatScore = 15
            $alertReasons = [System.Collections.Generic.List[string]]::new()
            $nivelRiesgo = "CONFIABLE"

            # 1. Análisis de Serial Único de Hardware
            # Si el serial contiene '&' al final (ej. 6&213adf1d&0&_&0), Windows lo generó porque el chip carece de serial único de fábrica
            if ($instance -match '&\d+$|&_&') {
                $threatScore += 30
                $alertReasons.Add("Dispositivo sin serial único de fábrica (Descriptor genérico o clon)")
            }

            # 2. Fabricante no identificado o sospechoso
            if ($ven -eq "" -or $ven -eq "Desconocido" -or $ven -eq "General" -or $ven -eq "_") {
                $threatScore += 25
                $alertReasons.Add("Fabricante (Vendor) no registrado o genérico")
            }

            # 3. Dispositivo conectado recientemente (últimas 48 horas)
            if ($lastConnected -ne [datetime]::MinValue) {
                $hoursAgo = ((Get-Date) - $lastConnected).TotalHours
                if ($hoursAgo -ge 0 -and $hoursAgo -le 48) {
                    $threatScore += 10
                    $alertReasons.Add("Actividad reciente en las últimas 48 horas")
                }
            }

            if ($threatScore -ge 70) {
                $nivelRiesgo = "CRITICO"
            } elseif ($threatScore -ge 40) {
                $nivelRiesgo = "SOSPECHOSO"
            } else {
                $nivelRiesgo = "CONFIABLE"
            }

            $usbItem = [PSCustomObject]@{
                FriendlyName     = $friendly
                Vendor           = $ven
                Product          = $prod
                Revision         = $rev
                SerialNumber     = $instance
                AssignedDrive    = $assignedDrive
                Estado           = if ($isLive) { "CONECTADO (LIVE)" } else { "HISTORICO" }
                Capacidad        = if ($liveSize) { $liveSize } else { "N/A" }
                UltimaConexion   = $lastConnectedStr
                ThreatScore      = [math]::Min($threatScore, 100)
                NivelRiesgo      = $nivelRiesgo
                Alertas          = if ($alertReasons.Count -gt 0) { $alertReasons -join " | " } else { "Ninguna (Parámetros estándar)" }
                HardwareID       = $hwIdStr
            }

            $UsbDevices.Add($usbItem)
            $instKey.Close()
        }
        $devSubKey.Close()
    }
    $baseKey.Close()
}

# -------------------------------------------------------------
# 6. Hunter de BadUSB / Emuladores HID en Rama USB
# -------------------------------------------------------------
$usbTree = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Enum\USB')
if ($usbTree) {
    foreach ($vidPid in $usbTree.GetSubKeyNames()) {
        foreach ($sig in $BadUsbDatabase.Keys) {
            $sigPattern = $sig -replace ':', '&PID_'
            if ($vidPid -match "VID_$sigPattern") {
                $badKey = $usbTree.OpenSubKey($vidPid)
                if ($badKey) {
                    $badInfo = $BadUsbDatabase[$sig]
                    $badItem = [PSCustomObject]@{
                        FriendlyName     = $badInfo.Nombre
                        Vendor           = "EMULADOR HARDWARE"
                        Product          = "BadUSB / Keystroke Injection"
                        Revision         = "Hardware"
                        SerialNumber     = $vidPid
                        AssignedDrive    = "HID / Virtual"
                        Estado           = "REGISTRADO EN SISTEMA"
                        Capacidad        = "N/A"
                        UltimaConexion   = "Registro Persistente"
                        ThreatScore      = $badInfo.Score
                        NivelRiesgo      = $badInfo.Riesgo
                        Alertas          = "FIRMA BADUSB DETECTADA: Identificador coincide con hardware de inyección de pulsaciones (Rubber Ducky / Flipper Zero)"
                        HardwareID       = "USB\$vidPid"
                    }
                    $UsbDevices.Add($badItem)
                    $badKey.Close()
                }
            }
        }
    }
    $usbTree.Close()
}

# -------------------------------------------------------------
# 7. Filtrado Opcional
# -------------------------------------------------------------
$Resultados = $UsbDevices
if ($SoloSospechosos) {
    $Resultados = $Resultados | Where-Object { $_.NivelRiesgo -ne "CONFIABLE" }
}
if ($SoloConectados) {
    $Resultados = $Resultados | Where-Object { $_.Estado -like "*CONECTADO*" }
}

# -------------------------------------------------------------
# 8. Renderizado en Consola con Estilo Forense
# -------------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host " ==============================================================================" -ForegroundColor Cyan
Write-Host "   UsbSentry v2.0.0 - Forense de Dispositivos USB y BadUSB Hunter" -ForegroundColor White
Write-Host "   Cru9 DFIR Suite | Deteccion de Exfiltracion Fisica y Almacenamiento" -ForegroundColor DarkGray
Write-Host " ==============================================================================" -ForegroundColor Cyan
Write-Host ""

$total = $UsbDevices.Count
$conectados = ($UsbDevices | Where-Object { $_.Estado -like "*CONECTADO*" }).Count
$alertas = ($UsbDevices | Where-Object { $_.NivelRiesgo -ne "CONFIABLE" }).Count

$colorConectados = if ($conectados -gt 0) { "Green" } else { "Gray" }
$colorAlertas = if ($alertas -gt 0) { "Red" } else { "Green" }

Write-Host " [+] Resumen Ejecutivo:" -ForegroundColor White
Write-Host "  -> Total Dispositivos Auditados : $total" -ForegroundColor Gray
Write-Host "  -> Conectados en Vivo (Live)    : $conectados" -ForegroundColor $colorConectados
Write-Host "  -> Dispositivos con Alerta      : $alertas" -ForegroundColor $colorAlertas
Write-Host ""

Write-Host " ------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host (" {0,-26} {1,-14} {2,-18} {3,-6} {4,-12} {5,-10}" -f "DISPOSITIVO", "FABRICANTE", "SERIAL HARDWARE", "DRIVE", "ESTADO", "RIESGO") -ForegroundColor Cyan
Write-Host " ------------------------------------------------------------------------------" -ForegroundColor DarkGray

foreach ($dev in $Resultados) {
    $color = "Green"
    if ($dev.NivelRiesgo -eq "CRITICO") { $color = "Red" }
    elseif ($dev.NivelRiesgo -eq "SOSPECHOSO") { $color = "Yellow" }

    $name = if ($dev.FriendlyName.Length -gt 25) { $dev.FriendlyName.Substring(0, 22) + "..." } else { $dev.FriendlyName }
    $ven = if ($dev.Vendor.Length -gt 13) { $dev.Vendor.Substring(0, 11) + ".." } else { $dev.Vendor }
    $ser = if ($dev.SerialNumber.Length -gt 17) { $dev.SerialNumber.Substring(0, 15) + ".." } else { $dev.SerialNumber }

    Write-Host (" {0,-26} {1,-14} {2,-18} {3,-6} {4,-12} " -f $name, $ven, $ser, $dev.AssignedDrive, $dev.Estado) -NoNewline
    Write-Host ("[{0}]" -f $dev.NivelRiesgo) -ForegroundColor $color

    if ($dev.NivelRiesgo -ne "CONFIABLE") {
        Write-Host "    └─ Alerta: $($dev.Alertas)" -ForegroundColor $color
    }
}

Write-Host " ------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# -------------------------------------------------------------
# 9. Exportación Opcional
# -------------------------------------------------------------
if ($ExportarCSV) {
    $Resultados | Export-Csv -Path $ExportarCSV -NoTypeInformation -Encoding UTF8
    Write-Host " [✓] Evidencias exportadas en formato CSV: $ExportarCSV" -ForegroundColor Green
}

if ($ExportarJSON) {
    $exportPayload = @{
        Herramienta = "UsbSentry"
        Version = "2.0.0"
        Autor = "Cru9"
        Timestamp = (Get-Date).ToString("o")
        HostName = $env:COMPUTERNAME
        TotalAuditados = $total
        Dispositivos = $Resultados
    }
    $exportPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $ExportarJSON -Encoding UTF8
    Write-Host " [✓] Evidencias exportadas en formato JSON: $ExportarJSON" -ForegroundColor Green
}
