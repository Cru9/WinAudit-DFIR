<#
.SYNOPSIS
    Script de Auditoría Forense y Detección de Intrusos en Windows.
.DESCRIPTION
    Inspecciona el Visor de Eventos de Seguridad (Security Log) para detectar:
    - Borrado de registros de auditoría (Evasión / Evento 1102)
    - Intentos fallidos de autenticación (Fuerza bruta / Evento 4625)
    - Inicios de sesión remotos exitosos (RDP Tipo 10 o Red Tipo 3 / Evento 4624)
    - Creación de usuarios o alteración de grupos (Persistencia / Eventos 4720, 4732, 4728)
    - Auditoría del grupo Administradores local
.NOTES
    Requiere ejecutarse con privilegios de Administrador.
#>

[CmdletBinding()]
param(
    [int]$DiasAtras = 7,
    [int]$MaxEventos = 50
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
    Write-Host " Por favor abre PowerShell haciendo clic derecho -> 'Ejecutar como administrador'." -ForegroundColor Yellow
    Write-Host ""
    return
}

# -------------------------------------------------------------
# Configuración y Helper Functions
# -------------------------------------------------------------
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
    }
    catch {
        # Fallback si el XML no es parseable
    }
    return $data
}

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "       AUDITORÍA DE SEGURIDAD Y ANÁLISIS DE ACTIVIDAD EN WINDOWS      " -ForegroundColor Yellow -BackgroundColor Black
Write-Host "       Periodo de análisis: Últimos $DiasAtras días                        " -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. ¿Alguien intentó borrar las evidencias? (Evento 1102 / 104)
# -------------------------------------------------------------
Show-Header "1. REVISIÓN DE INTEGRIDAD DE LOGS (Borrado de Registros)"

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
}
catch [System.Exception] {
    Write-Host " [OK] No se detectó borrado del registro de seguridad (Evento 1102)." -ForegroundColor Green
}

# -------------------------------------------------------------
# 2. Intentos Fallidos de Inicio de Sesión (Evento 4625)
# -------------------------------------------------------------
Show-Header "2. INTENTOS FALLIDOS DE INICIO DE SESIÓN (Evento 4625)"

try {
    $failedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$FechaInicio} -MaxEvents 500 -ErrorAction Stop
    
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
}
catch [System.Exception] {
    Write-Host " [OK] No se registraron intentos fallidos en los últimos $DiasAtras días." -ForegroundColor Green
}

# -------------------------------------------------------------
# 3. Inicios de Sesión Exitosos Remotos o por Red (Evento 4624)
# -------------------------------------------------------------
Show-Header "3. INICIOS DE SESIÓN EXITOSOS REMOTOS / RED (Evento 4624)"

try {
    $successEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$FechaInicio} -MaxEvents 500 -ErrorAction Stop
    
    $parsedSuccess = foreach ($ev in $successEvents) {
        $data = Parse-EventData $ev
        $logonType = [string]$data['LogonType']

        # Filtrar Tipo 10 (RemoteInteractive/RDP) y Tipo 3 (Network)
        # Omitir cuentas internas del sistema como DWM-*, UMFD-* o vacías
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
        $parsedSuccess | Select-Object -First $MaxEventos | Format-Table -AutoSize
    } else {
        Write-Host " [OK] No hay sesiones remotas (RDP / Red) de usuarios externos en este periodo." -ForegroundColor Green
    }
}
catch [System.Exception] {
    Write-Host " [OK] No se encontraron eventos de inicio de sesión aplicables." -ForegroundColor Green
}

# -------------------------------------------------------------
# 4. Creación de Cuentas y Modificación de Grupos (Eventos 4720, 4732, 4728)
# -------------------------------------------------------------
Show-Header "4. CREACIÓN Y MODIFICACIÓN DE CUENTAS (Eventos 4720, 4732)"

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
}
catch [System.Exception] {
    Write-Host " [OK] No se han creado usuarios ni modificado grupos en los últimos $DiasAtras días." -ForegroundColor Green
}

# -------------------------------------------------------------
# 5. Auditoría del Grupo Administradores Local
# -------------------------------------------------------------
Show-Header "5. MIEMBROS ACTUALES DEL GRUPO ADMINISTRADORES"

try {
    # Resuelve el nombre del grupo Administradores sin importar el idioma (S-1-5-32-544)
    $sidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroupName = $sidAdmin.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    
    Write-Host " Identificando grupo: '$adminGroupName'..." -ForegroundColor Gray

    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        $admins = Get-LocalGroupMember -Group $adminGroupName
        $admins | Select-Object @{Name="Cuenta"; Expression={$_.Name}}, @{Name="Clase"; Expression={$_.ObjectClass}}, @{Name="Origen"; Expression={$_.PrincipalSource}} | Format-Table -AutoSize
    } else {
        net localgroup $adminGroupName
    }
    
    Write-Host " [?] Verifica que todas las cuentas listadas arriba sean legítimas." -ForegroundColor Yellow
}
catch [System.Exception] {
    Write-Host " [!] No se pudo obtener la lista con Get-LocalGroupMember. Intentando 'net localgroup'..." -ForegroundColor Yellow
    net localgroup Administradores
}

# -------------------------------------------------------------
# Fin del Informe
# -------------------------------------------------------------
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                     AUDITORÍA COMPLETADA                             " -ForegroundColor Green -BackgroundColor Black
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
