<#
.SYNOPSIS
    IntruderDetector v1.2.1 - Suite de Auditoría Forense y Detección de Intrusos en Windows.
.DESCRIPTION
    Inspecciona y correlaciona eventos clave del Visor de Seguridad y Sistema:
    - Borrado de registros de auditoría (Evasión / Evento 1102 / 104)
    - Fuerza bruta y Password Spraying (Evento 4625)
    - Inicios de sesión remotos exitosos (RDP Tipo 10 o Red Tipo 3 / Evento 4624)
    - Creación de usuarios o alteración de grupos (Persistencia / Eventos 4720, 4732, 4728)
    - Detección de comandos LOLBAS y procesos sospechosos (Evento 4688)
    - Instalación de nuevos servicios (Evento 7045)
    - Auditoría agnóstica de administradores locales (SID S-1-5-32-544)
    - Persistencia en inicio y tareas programadas con validación de firmas Authenticode
.NOTES
    Autor: Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR v1.2.1
#>

[CmdletBinding()]
param(
    [int]$DiasAtras = 7,
    [int]$MaxEventos = 500
)

# -------------------------------------------------------------
# 0. Verificación de Privilegios de Administrador
# -------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host " [!] ERROR DE PRIVILEGIOS" -ForegroundColor Red -BackgroundColor Black
    Write-Host " Este script necesita leer el registro de 'Seguridad' (Security Log)." -ForegroundColor Yellow
    Write-Host " Por favor abre PowerShell como Administrador o usa 'Ejecutar-Deteccion.bat'." -ForegroundColor Yellow
    Write-Host ""
}

$FechaInicio = (Get-Date).AddDays(-$DiasAtras)

function Show-Header {
    param([string]$Titulo)
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " $Titulo" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "======================================================================" -ForegroundColor Cyan
}

function Parse-EventData {
    param($Event)
    $data = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) {
                $data[$item.Name] = $item.'#text'
            }
        }
    } catch {}
    return $data
}

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     INTRUDER DETECTOR v1.2.1 - TRIAGE FORENSE DE HOST EN WINDOWS     " -ForegroundColor Yellow -BackgroundColor Black
Write-Host "      Autor: Cru9 | Periodo de análisis: Últimos $DiasAtras días           " -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Integridad de Logs (Evento 1102 / 104)
# -------------------------------------------------------------
Show-Header "1. REVISIÓN DE INTEGRIDAD DE LOGS (Borrado de Registros / T1070)"
try {
    $clearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$FechaInicio} -ErrorAction Stop
    Write-Host " [ALERTA CRÍTICA] Se detectó vaciado del registro de seguridad:" -ForegroundColor Red
    $clearedLogs | ForEach-Object {
        $xmlData = Parse-EventData $_
        [PSCustomObject]@{
            Fecha   = $_.TimeCreated
            Usuario = $xmlData['SubjectUserName']
            Dominio = $xmlData['SubjectDomainName']
            Evento  = "1102 - Registro de Seguridad borrado"
        }
    } | Format-Table -AutoSize
} catch {
    Write-Host " [OK] No se detectó borrado del registro de seguridad (Evento 1102)." -ForegroundColor Green
}

# -------------------------------------------------------------
# 2. Intentos Fallidos de Inicio de Sesión (Evento 4625)
# -------------------------------------------------------------
Show-Header "2. INTENTOS FALLIDOS DE INICIO DE SESIÓN (Fuerza Bruta / Evento 4625)"
try {
    $failedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$FechaInicio} -MaxEvents $MaxEventos -ErrorAction Stop
    $parsedFailed = foreach ($ev in $failedEvents) {
        $data = Parse-EventData $ev
        [PSCustomObject]@{
            Fecha        = $ev.TimeCreated
            Usuario      = $data['TargetUserName']
            IPOrigen     = if ($data['IpAddress']) { $data['IpAddress'] } else { "Local" }
            Puerto       = $data['IpPort']
            TipoAcceso   = $data['LogonType']
        }
    }

    Write-Host " [!] Se encontraron $($parsedFailed.Count) intento(s) fallido(s)." -ForegroundColor Yellow
    Write-Host "`n>>> Resumen por IP de origen:" -ForegroundColor Cyan
    $parsedFailed | Group-Object IPOrigen | Sort-Object Count -Descending | Select-Object Count, @{Name="Dirección IP"; Expression={$_.Name}} | Format-Table -AutoSize

    Write-Host ">>> Usuarios más atacados:" -ForegroundColor Cyan
    $parsedFailed | Group-Object Usuario | Sort-Object Count -Descending | Select-Object Count, @{Name="Usuario Objetivo"; Expression={$_.Name}} | Format-Table -AutoSize
} catch {
    Write-Host " [OK] No se registraron intentos fallidos en los últimos $DiasAtras días." -ForegroundColor Green
}

# -------------------------------------------------------------
# 3. Inicios de Sesión Exitosos Remotos o por Red (Evento 4624)
# -------------------------------------------------------------
Show-Header "3. INICIOS DE SESIÓN EXITOSOS REMOTOS / RED (Evento 4624)"
try {
    $successEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$FechaInicio} -MaxEvents $MaxEventos -ErrorAction Stop
    $parsedSuccess = foreach ($ev in $successEvents) {
        $data = Parse-EventData $ev
        $logonType = [string]$data['LogonType']
        $user = $data['TargetUserName']

        if (($logonType -eq '10' -or $logonType -eq '3') -and $user -notmatch '^(ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$$)') {
            $tipoTexto = switch ($logonType) {
                '10' { "RDP (Escritorio Remoto)" }
                '3'  { "Red (SMB/Carpetas compartidas)" }
                default { "Tipo $logonType" }
            }

            [PSCustomObject]@{
                Fecha       = $ev.TimeCreated
                Usuario     = $user
                TipoAcceso  = $tipoTexto
                IPOrigen    = if ($data['IpAddress']) { $data['IpAddress'] } else { "-" }
                Equipo      = $data['WorkstationName']
            }
        }
    }

    if ($parsedSuccess -and $parsedSuccess.Count -gt 0) {
        Write-Host " [AVISO] Conexiones remotas / de red detectadas:" -ForegroundColor Yellow
        $parsedSuccess | Select-Object -First 25 | Format-Table -AutoSize
    } else {
        Write-Host " [OK] No hay sesiones remotas de usuarios externos en este periodo." -ForegroundColor Green
    }
} catch {
    Write-Host " [OK] No se encontraron eventos de inicio de sesión remotos aplicables." -ForegroundColor Green
}

# -------------------------------------------------------------
# 4. Creación de Cuentas y Modificación de Grupos (4720, 4732, 4728)
# -------------------------------------------------------------
Show-Header "4. CREACIÓN Y MODIFICACIÓN DE CUENTAS (Persistencia / Eventos 4720, 4732)"
try {
    $accountEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4732,4728; StartTime=$FechaInicio} -ErrorAction Stop
    Write-Host " [ALERTA] Se detectaron alteraciones de cuentas o grupos:" -ForegroundColor Red
    $accountEvents | ForEach-Object {
        $data = Parse-EventData $_
        $accion = switch ($_.Id) {
            4720 { "Usuario Creado: $($data['TargetUserName'])" }
            4732 { "Usuario añadido a grupo local: $($data['MemberName']) -> $($data['TargetUserName'])" }
            4728 { "Usuario añadido a grupo global: $($data['MemberName'])" }
            default { "Evento $($_.Id)" }
        }
        [PSCustomObject]@{
            Fecha        = $_.TimeCreated
            IdEvento     = $_.Id
            Acción       = $accion
            EjecutadoPor = $data['SubjectUserName']
        }
    } | Format-Table -AutoSize
} catch {
    Write-Host " [OK] No se han creado usuarios ni modificado grupos en los últimos $DiasAtras días." -ForegroundColor Green
}

# -------------------------------------------------------------
# 5. Comandos LOLBAS y Procesos Sospechosos (Evento 4688)
# -------------------------------------------------------------
Show-Header "5. DETECCIÓN DE COMANDOS SOSPECHOSOS Y LOLBAS (Evento 4688 / T1490)"
try {
    $procEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$FechaInicio} -MaxEvents $MaxEventos -ErrorAction Stop
    $suspicious = foreach ($p in $procEvents) {
        $d = Parse-EventData $p
        $cmdLine = $d['CommandLine']
        if ($cmdLine -match '(vssadmin.*delete|wmic.*shadowcopy|certutil.*-urlcache|powershell.*-enc|bitsadmin.*transfer)') {
            [PSCustomObject]@{
                Fecha   = $p.TimeCreated
                Usuario = $d['SubjectUserName']
                Comando = $cmdLine
            }
        }
    }
    if ($suspicious) {
        Write-Host " [ALERTA CRÍTICA] Comandos de evasión o ransomware detectados:" -ForegroundColor Red
        $suspicious | Format-Table -AutoSize
    } else {
        Write-Host " [OK] No se detectaron comandos LOLBAS o de destrucción de copias de seguridad." -ForegroundColor Green
    }
} catch {
    Write-Host " [INFO] Auditoría de creación de procesos (4688) sin registros en este periodo." -ForegroundColor Gray
}

# -------------------------------------------------------------
# 6. Nuevos Servicios Instalados (Evento 7045 en System Log)
# -------------------------------------------------------------
Show-Header "6. NUEVOS SERVICIOS DE WINDOWS INSTALADOS (Evento 7045 / T1543.003)"
try {
    $svcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$FechaInicio} -MaxEvents 50 -ErrorAction Stop
    Write-Host " [AVISO] Se detectó la instalación reciente de servicios:" -ForegroundColor Yellow
    $svcEvents | ForEach-Object {
        $data = Parse-EventData $_
        [PSCustomObject]@{
            Fecha    = $_.TimeCreated
            Servicio = $data['ServiceName']
            Ruta     = $data['ImagePath']
            Cuenta   = $data['AccountName']
        }
    } | Format-Table -AutoSize
} catch {
    Write-Host " [OK] No se registraron nuevos servicios instalados en los últimos $DiasAtras días." -ForegroundColor Green
}

# -------------------------------------------------------------
# 7. Auditoría del Grupo Administradores Local
# -------------------------------------------------------------
Show-Header "7. MIEMBROS ACTUALES DEL GRUPO ADMINISTRADORES (SID S-1-5-32-544)"
try {
    $sidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroupName = $sidAdmin.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        $admins = Get-LocalGroupMember -Group $adminGroupName
        $admins | Select-Object @{Name="Cuenta"; Expression={$_.Name}}, @{Name="Clase"; Expression={$_.ObjectClass}}, @{Name="Origen"; Expression={$_.PrincipalSource}} | Format-Table -AutoSize
    } else {
        net localgroup $adminGroupName
    }
} catch {
    net localgroup Administradores
}

# -------------------------------------------------------------
# 8. Persistencia en Inicio y Tareas Programadas (Authenticode / T1547 / T1053)
# -------------------------------------------------------------
Show-Header "8. PERSISTENCIA EN ARRANQUE Y TAREAS PROGRAMADAS (Authenticode / T1547 / T1053)"
$scriptPersistencia = Join-Path $PSScriptRoot "Auditar-Persistencia-Arranque.ps1"
if (Test-Path $scriptPersistencia) {
    & $scriptPersistencia
} else {
    Write-Host " [INFO] Script de persistencia no encontrado en: $scriptPersistencia" -ForegroundColor Gray
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                     AUDITORÍA COMPLETADA                             " -ForegroundColor Green -BackgroundColor Black
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
