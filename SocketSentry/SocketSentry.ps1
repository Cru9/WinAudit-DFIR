<#
.SYNOPSIS
    SocketSentry v2.0.0 - Framework de Detección y Análisis Forense de Conexiones de Red en Windows.
.DESCRIPTION
    Herramienta avanzada de Threat Hunting y DFIR (Digital Forensics & Incident Response) para Windows.
    Wrapper principal y conmutador para Auditar-Conexiones.ps1.
    Inspecciona conexiones TCP/UDP activas, procesos propietarios, CommandLine, LOLBins, Feodo Tracker C2
    y balizas periódicas (Beaconing).
.NOTES
    Autor: Ezequiel Diaz (Cru9) | Ecosistema WinAudit-DFIR
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
    [string]$ExportarHTML = "",
    [string]$ExportarCSV = "",
    [switch]$Monitor,
    [int]$IntervaloSegundos = 10
)

$scriptPath = Join-Path $PSScriptRoot "Auditar-Conexiones.ps1"
if (Test-Path $scriptPath) {
    & $scriptPath @PSBoundParameters
} else {
    Write-Host "[!] Error: No se encontró Auditar-Conexiones.ps1 en $PSScriptRoot" -ForegroundColor Red
}
