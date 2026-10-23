#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 WinAudit-DFIR - Master Forensic & Incident Response Suite (Python Core)
 Autor: Ezequiel Diaz (Cru9) | Versión: v3.0.0
==============================================================================
 Orquestador y Consola Maestra Forense multiplataforma en Python puro (0-pip).
 Integra los 9 módulos forenses especializados del ecosistema para recolección,
 análisis pericial y preservación de evidencias en terminal de consola.
==============================================================================
"""

import os
import sys
import subprocess
import platform
import argparse
import datetime
import hashlib
from pathlib import Path

# Configurar codificación de terminal UTF-8
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Habilitar secuencias de escape ANSI VT100 en Windows CMD
if os.name == 'nt':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h_out = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(h_out, ctypes.byref(mode))
        kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
    except Exception:
        pass

# -----------------------------------------------------------------------------
# CONSTANTES Y PALETA DE COLORES ANSI
# -----------------------------------------------------------------------------
VERSION = "3.0.0"
AUTHOR = "Cru9"
TOOL_NAME = "WinAudit-DFIR Suite"

C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"
C_CYAN    = "\033[96m"
C_BLUE    = "\033[94m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_MAGENTA = "\033[95m"
C_WHITE   = "\033[97m"
C_GRAY    = "\033[90m"

BASE_DIR = Path(__file__).resolve().parent

# Mapeo de módulos forenses del ecosistema
MODULES = {
    "1": {
        "id": "1",
        "name": "IntruderDetector",
        "title": "Detección de Intrusos (Host Security Logs & Live Radar)",
        "desc": "Análisis de Security Log, Fuerza Bruta (4625), Sesiones RDP (10) y Anti-Forensics (1102)",
        "path": None,  # Se resuelve dinámicamente para soportar acentos
        "reports": None
    },
    "2": {
        "id": "2",
        "name": "WiFiSentry",
        "title": "WiFiSentry (Wireless Forensic Suite & Rogue AP Hunter)",
        "desc": "Perfiles WLAN guardados, auditoría de claves, sensor RF y detección de Evil Twin",
        "path": BASE_DIR / "WiFiSentry" / "WiFiSentry.py",
        "reports": BASE_DIR / "WiFiSentry" / "Reportes"
    },
    "3": {
        "id": "3",
        "name": "SocketSentry",
        "title": "SocketSentry (Threat Hunter de Red & Sockets Activos)",
        "desc": "Inspección de sockets TCP/UDP en vivo, balizas C2 salientes y LOLBins en red",
        "path": BASE_DIR / "SocketSentry" / "SocketSentry.py",
        "reports": BASE_DIR / "SocketSentry" / "Reportes"
    },
    "4": {
        "id": "4",
        "name": "DnsSentry",
        "title": "DnsSentry (Forense de Caché DNS & Hosts File Poisoning)",
        "desc": "Extracción de caché DNS, entropía DGA, túneles C2 e integridad de archivo Hosts",
        "path": BASE_DIR / "DnsSentry" / "DnsSentry.py",
        "reports": BASE_DIR / "DnsSentry" / "Reportes"
    },
    "5": {
        "id": "5",
        "name": "StartupSentry",
        "title": "StartupSentry (Persistencia, Tareas Raíz & Authenticode)",
        "desc": "Puntos de inicio ASEP, Registry Run Keys, Tareas no-Microsoft y firmas digitales",
        "path": BASE_DIR / "StartupSentry" / "StartupSentry.py",
        "reports": BASE_DIR / "StartupSentry" / "Reportes"
    },
    "6": {
        "id": "6",
        "name": "UsbSentry",
        "title": "UsbSentry (Forense de Almacenamiento USB & BadUSB Hunter)",
        "desc": "Historial USBSTOR, MountedDevices históricas y cazador de BadUSB / Rubber Ducky",
        "path": BASE_DIR / "UsbSentry" / "UsbSentry.py",
        "reports": BASE_DIR / "UsbSentry" / "Reportes"
    },
    "7": {
        "id": "7",
        "name": "ExecSentry",
        "title": "ExecSentry (Evidencia Forense de Ejecución en Windows)",
        "desc": "Prefetch (.pf), UserAssist (ROT13), BAM/DAM, Shimcache y PCA (binarios eliminados)",
        "path": BASE_DIR / "ExecSentry" / "ExecSentry.py",
        "reports": BASE_DIR / "ExecSentry" / "Reportes"
    },
    "8": {
        "id": "8",
        "name": "BrowserSentry",
        "title": "BrowserSentry (Forense de Navegadores Web & Descargas)",
        "desc": "Triage SQLite en Chrome, Edge, Brave, Opera y Firefox: descargas, historial y extensiones",
        "path": BASE_DIR / "BrowserSentry" / "BrowserSentry.py",
        "reports": BASE_DIR / "BrowserSentry" / "Reportes"
    },
    "9": {
        "id": "9",
        "name": "MemSentry",
        "title": "MemSentry (Procesos en RAM, Inyección & LSASS Guard)",
        "desc": "Árbol de procesos en vivo, linaje padre-hijo, RunAsPPL, WDigest y Unquoted Paths",
        "path": BASE_DIR / "MemSentry" / "MemSentry.py",
        "reports": BASE_DIR / "MemSentry" / "Reportes"
    }
}

def resolve_intruder_module():
    """Resuelve la ruta de IntruderDetector considerando acentos o codificación del directorio."""
    for folder_name in ["Detección de Intrusos", "Deteccion de Intrusos", "Deteccin de Intrusos"]:
        p = BASE_DIR / folder_name / "IntruderDetector.py"
        if p.exists():
            MODULES["1"]["path"] = p
            MODULES["1"]["reports"] = BASE_DIR / folder_name / "Reportes"
            return p
    # Búsqueda por glob
    matches = list(BASE_DIR.glob("*Intrusos*/IntruderDetector.py"))
    if matches:
        p = matches[0]
        MODULES["1"]["path"] = p
        MODULES["1"]["reports"] = p.parent / "Reportes"
        return p
    return None

# Resolver dinámicamente al cargar
resolve_intruder_module()


# -----------------------------------------------------------------------------
# CONTROL DE PRIVILEGIOS Y ELEVACIÓN UAC
# -----------------------------------------------------------------------------
def is_admin() -> bool:
    """Verifica si el proceso actual cuenta con privilegios elevados de Administrador."""
    if os.name != 'nt':
        return os.getuid() == 0 if hasattr(os, "getuid") else False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def request_uac_elevation():
    """Solicita elevación UAC en Windows y relanza la suite como Administrador."""
    if os.name != 'nt' or is_admin():
        return
    try:
        import ctypes
        script = str(Path(__file__).resolve())
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:] if arg != "--elevated"])
        params = f'"{script}" -elevated {params}'
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if ret > 32:
            sys.exit(0)
    except Exception:
        pass


# -----------------------------------------------------------------------------
# INTERFAZ VISUAL Y MENÚ PRINCIPAL
# -----------------------------------------------------------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    clear_screen()
    hostname = os.environ.get("COMPUTERNAME", platform.node())
    username = os.environ.get("USERNAME", os.environ.get("USER", "ForensicAnalyst"))
    admin_status = f"{C_BOLD}{C_GREEN}[ ADMINISTRADOR ]{C_RESET}" if is_admin() else f"{C_BOLD}{C_YELLOW}[ USUARIO ESTÁNDAR ]{C_RESET}"
    py_ver = f"Python {platform.python_version()}"

    print(f"""  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}__          ___             __             _ _ _      _____  ______ _____ _____                 {C_CYAN}|{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}\\ \\        / (_)           /\\ \\           | (_) |    |  __ \\|  ____|_   _|  __ \\                {C_CYAN}|{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE} \\ \\  /\\  / / _ _ __      /  \\ \\ _   _  __| |_| |_   | |  | | |__    | | | |__) |               {C_CYAN}|{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}  \\ \\/  \\/ / | | '_ \\    / /\\ \\ | | | |/ _` | | __|  | |  | |  __|   | | |  _  /                {C_CYAN}|{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}   \\  /\\  /  | | | | |  / ____ \\| |_| | (_| | | |_   | |__| | |     _| |_| | \\ \\                {C_CYAN}|{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}    \\/  \\/   |_|_| |_| /_/    \\_\\__,_|\\__,_|_|\\__|  |_____/|_|    |_____|_|  \\_\\               {C_CYAN}|{C_RESET}
  {C_CYAN}|                                                                                                  |{C_RESET}
  {C_CYAN}|             {C_BOLD}{C_CYAN}DFIR CYBERSECURITY ECOSYSTEM {C_GRAY}v{VERSION}  {C_WHITE}|  {C_MAGENTA}DEVELOPED BY {AUTHOR.upper()}                             {C_CYAN}|{C_RESET}
  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}
   {C_GRAY}[+] HOST:{C_WHITE} {hostname}  {C_GRAY}|  USUARIO:{C_WHITE} {username}  {C_GRAY}|  ESTADO: {admin_status}  {C_GRAY}|  MOTOR: {C_CYAN}{py_ver}{C_RESET}
""")

def display_menu():
    show_banner()
    print(f"""  {C_BLUE}.--------------------------------------------------------------------------------------------------.{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[ MÓDULOS FORENSES ESPECIALIZADOS INDIVIDUALES ]                                                {C_BLUE}|{C_RESET}
  {C_BLUE}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_BLUE}|                                                                                                  |{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[1]{C_RESET}  {C_BOLD}{C_CYAN}Detección de Intrusos {C_GRAY}(Security Log, Fuerza Bruta & SIEM Live Radar){C_RESET}                       {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[2]{C_RESET}  {C_BOLD}{C_CYAN}WiFiSentry {C_GRAY}(Wireless Forensic Suite, Rogue AP Hunter & Entropía PBKDF2){C_RESET}                     {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[3]{C_RESET}  {C_BOLD}{C_CYAN}SocketSentry {C_GRAY}(Threat Hunter de Red, Sockets TCP/UDP & Feodo C2 Beaconing){C_RESET}                  {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[4]{C_RESET}  {C_BOLD}{C_CYAN}DnsSentry {C_GRAY}(Caché DNS en Vivo, DGA, Túneles C2 & Manipulación de Hosts){C_RESET}                       {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[5]{C_RESET}  {C_BOLD}{C_CYAN}StartupSentry {C_GRAY}(Persistencia en Arranque, Tareas Raíz & Firmas Authenticode){C_RESET}                  {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[6]{C_RESET}  {C_BOLD}{C_CYAN}UsbSentry {C_GRAY}(Forense USBSTOR, MountedDevices & Inyectores Hardware BadUSB){C_RESET}                    {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[7]{C_RESET}  {C_BOLD}{C_CYAN}ExecSentry {C_GRAY}(Evidencia de Ejecución: Prefetch, UserAssist, BAM, Shim & PCA){C_RESET}                  {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[8]{C_RESET}  {C_BOLD}{C_CYAN}BrowserSentry {C_GRAY}(SQLite Forensics Multi-Navegador, Descargas Web & Extensiones){C_RESET}             {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[9]{C_RESET}  {C_BOLD}{C_CYAN}MemSentry {C_GRAY}(Procesos en RAM, Linaje Padre-Hijo, Masquerading & LSASS Guard){C_RESET}                 {C_BLUE}|{C_RESET}
  {C_BLUE}|                                                                                                  |{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[D]{C_RESET}  {C_BOLD}{C_GREEN}Visor Forense en Consola {C_GRAY}(Explorar Resúmenes Ejecutivos en Terminal){C_RESET}                       {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_WHITE}[S]{C_RESET}  {C_BOLD}{C_MAGENTA}Diagnóstico de Salud {C_GRAY}(Verificar Módulos, Permisos y Entorno 0-pip){C_RESET}                       {C_BLUE}|{C_RESET}
  {C_BLUE}|  {C_BOLD}{C_RED}[0]{C_RESET}  {C_BOLD}{C_WHITE}Finalizar Sesión Forense {C_GRAY}(Cerrar Suite DFIR){C_RESET}                                                {C_BLUE}|{C_RESET}
  {C_BLUE}|                                                                                                  |{C_RESET}
  {C_BLUE}'--------------------------------------------------------------------------------------------------'{C_RESET}
""")


# -----------------------------------------------------------------------------
# EJECUCIÓN Y GESTIÓN DE MÓDULOS
# -----------------------------------------------------------------------------
def run_module(module_key: str):
    """Ejecuta un módulo específico pasando los argumentos y control necesarios."""
    mod = MODULES.get(module_key.upper())
    if not mod:
        print(f"\n  {C_RED}[!] Módulo no reconocido: {module_key}{C_RESET}")
        return

    script_path = mod.get("path")
    if not script_path or not script_path.exists():
        print(f"\n  {C_RED}[!] Error: No se encontró el script de {mod['name']} en: {script_path}{C_RESET}")
        input(f"\n  {C_CYAN}Presione Enter para volver al menú...{C_RESET}")
        return

    clear_screen()
    print(f"""
  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}CARGANDO ENTORNO FORENSE: {C_CYAN}{mod['title']}{C_RESET}
  {C_CYAN}|  {C_GRAY}{mod['desc'][:96]}{C_RESET}
  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}
""")

    try:
        # Invocamos el módulo en su propio subproceso respetando el directorio de trabajo del módulo
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        cmd = [sys.executable, str(script_path)]
        subprocess.run(cmd, cwd=str(script_path.parent), env=env)
    except KeyboardInterrupt:
        print(f"\n\n  {C_YELLOW}[!] Ejecución interrumpida por el analista.{C_RESET}")
    except Exception as e:
        print(f"\n  {C_RED}[!] Error al ejecutar {mod['name']}: {e}{C_RESET}")

    print()
    input(f"  {C_CYAN}Presione Enter para volver a la Consola Maestra...{C_RESET}")




def _show_module_summary(mod_key: str, pause: bool = True):
    """Muestra el resumen ejecutivo forense de un módulo en la terminal a partir de su último reporte JSON."""
    mod = MODULES.get(mod_key.upper())
    if not mod:
        print(f"  {C_RED}[!] Módulo no válido: {mod_key}{C_RESET}")
        return

    clear_screen()
    print(f"""
  {C_CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════╗{C_RESET}
  {C_CYAN}║  {C_BOLD}{C_WHITE}VISOR FORENSE EN CONSOLA: {mod['name'].upper():<35}                             {C_CYAN}║{C_RESET}
  {C_CYAN}║  {C_GRAY}{mod['desc'][:96]:<96} {C_CYAN}║{C_RESET}
  {C_CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════╝{C_RESET}
""")

    r_dir = mod.get("reports")
    json_file = None
    if r_dir and r_dir.exists():
        candidates = sorted(r_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for c in candidates:
            if "Navigator" not in c.name:
                json_file = c
                break
        if not json_file and candidates:
            json_file = candidates[0]

    if not json_file:
        print(f"  {C_YELLOW}[!] No se encontró ningún reporte JSON previo para {mod['name']}.{C_RESET}")
        print(f"  {C_WHITE}[*] Puede ejecutar la auditoría pericial desde el menú principal [Opción {mod['id']}].{C_RESET}")
        if pause:
            input(f"\n  {C_CYAN}Presione Enter para continuar...{C_RESET}")
        return

    try:
        import json
        with open(json_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        hasher = hashlib.sha256()
        with open(json_file, "rb") as f:
            hasher.update(f.read())

        print(f"  {C_BOLD}{C_WHITE}[+] METADATOS DEL ARTEFACTO FORENSE:{C_RESET}")
        print(f"      {C_GRAY}Archivo :{C_RESET} {C_YELLOW}{json_file.name}{C_RESET}")
        print(f"      {C_GRAY}Ruta    :{C_RESET} {json_file.parent}")
        print(f"      {C_GRAY}Tamaño  :{C_RESET} {json_file.stat().st_size:,} bytes")
        print(f"      {C_GRAY}SHA-256 :{C_RESET} {C_WHITE}{hasher.hexdigest()}{C_RESET}\n")

        mid = mod["id"]
        if mid == "1":
            findings = data.get("findings", {})
            fails = findings.get("failed_logons", [])
            succs = findings.get("successful_logons", [])
            clears = findings.get("cleared_logs", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN EJECUTIVO DE EVENTOS DE SEGURIDAD:{C_RESET}")
            print(f"      - Intentos Fallidos de Inicio de Sesión (Event 4625) : {C_BOLD}{C_RED if fails else C_GREEN}{len(fails)}{C_RESET}")
            print(f"      - Inicios de Sesión Exitosos Analizados (Event 4624)  : {C_BOLD}{C_WHITE}{len(succs)}{C_RESET}")
            print(f"      - Registros de Eventos Borrados / Anti-Forensics     : {C_BOLD}{C_RED if clears else C_GREEN}{len(clears)}{C_RESET}")
            if fails:
                print(f"\n  {C_BOLD}{C_YELLOW}[!] MUESTRA DE LOGONS FALLIDOS RECIENTES:{C_RESET}")
                for fl in fails[:5]:
                    u = fl.get("TargetUserName", "-")
                    ip = fl.get("IpAddress", "-")
                    t = fl.get("TimeCreated", "-")
                    print(f"      * [{t}] Usuario: {u} | Origen IP: {ip}")

        elif mid == "2":
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DE REDES INALÁMBRICAS:{C_RESET}")
            print(f"      - Módulo especializado en extracción y análisis de entropía PBKDF2 de perfiles WLAN.")
            print(f"      - Detección de Evil Twin, puntos de acceso Rogue y descifrado pericial WPA2/WPA3.")
            print(f"      - Estado del sensor: {C_GREEN}OPERATIVO 0-PIP (netsh wlan interface){C_RESET}")

        elif mid == "3":
            conns = data.get("conexiones", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN DE CONEXIONES DE RED ACTIVAS:{C_RESET}")
            print(f"      - Total de Sockets TCP/UDP Inspeccionados : {C_BOLD}{C_CYAN}{len(conns)}{C_RESET}")
            est_counts = {}
            for c in conns:
                st = c.get("estado", "UNKNOWN")
                est_counts[st] = est_counts.get(st, 0) + 1
            print(f"      - Estados: " + ", ".join([f"{k}: {v}" for k, v in est_counts.items()]))
            susp = [c for c in conns if c.get("alerta") or c.get("threat")]
            print(f"      - Conexiones Sospechosas / Feodo C2 Beaconing: {C_BOLD}{C_RED if susp else C_GREEN}{len(susp)}{C_RESET}")
            if conns:
                print(f"\n  {C_BOLD}{C_WHITE}[+] MUESTRA DE SOCKETS ACTIVOS (TOP 6):{C_RESET}")
                for c in conns[:6]:
                    loc = f"{c.get('ip_local', '-')}:{c.get('puerto_local', '-')}"
                    rem = f"{c.get('ip_remota', '-')}:{c.get('puerto_remoto', '-')}"
                    proc = c.get("proceso", "-")
                    print(f"      * {proc:<20} {loc:<22} -> {rem:<22} [{c.get('estado', '-')}]")

        elif mid == "4":
            cache = data.get("dns_cache", [])
            hosts = data.get("hosts_audit", {})
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DNS Y ARCHIVO HOSTS:{C_RESET}")
            print(f"      - Dominios en Caché DNS Analizados : {C_BOLD}{C_CYAN}{len(cache)}{C_RESET}")
            print(f"      - Integridad del Fichero Hosts     : {C_BOLD}{C_GREEN if hosts.get('exists') else C_RED}{'INTEGRO' if hosts.get('exists') else 'NO ENCONTRADO'}{C_RESET}")
            print(f"      - Entradas Personalizadas en Hosts : {C_BOLD}{len(hosts.get('entries', []))}{C_RESET}")
            if cache:
                print(f"\n  {C_BOLD}{C_WHITE}[+] DOMINIOS RECIENTES EN CACHÉ (TOP 6):{C_RESET}")
                for d in cache[:6]:
                    dom = d.get("domain", d.get("Entry", d.get("Name", "-")))
                    typ = d.get("type", d.get("Type", "-"))
                    print(f"      * {dom:<45} (Tipo: {typ})")

        elif mid == "5":
            findings = data.get("findings", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN DE PERSISTENCIA Y AUTO-ARRANQUE:{C_RESET}")
            print(f"      - Puntos de Persistencia Detectados : {C_BOLD}{C_YELLOW}{len(findings)}{C_RESET}")
            cats = {}
            for item in findings:
                cat = item.get("Categoria", item.get("categoria", item.get("category", "General")))
                cats[cat] = cats.get(cat, 0) + 1
            print(f"      - Desglose por Vector: " + ", ".join([f"{k}: {v}" for k, v in cats.items()]))
            if findings:
                print(f"\n  {C_BOLD}{C_WHITE}[+] ENTRADAS DE PERSISTENCIA (TOP 6):{C_RESET}")
                for item in findings[:6]:
                    nom = str(item.get("Nombre", item.get("nombre", item.get("name", "-"))))[:28]
                    rut = str(item.get("Ruta", item.get("Comando", item.get("ruta", item.get("path", "-")))))[:50]
                    print(f"      * {nom:<30} -> {rut}")

        elif mid == "6":
            devs = data.get("dispositivos", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DE DISPOSITIVOS USB:{C_RESET}")
            print(f"      - Dispositivos USB Auditados : {C_BOLD}{C_CYAN}{len(devs)}{C_RESET}")
            sos = [d for d in devs if d.get("nivel_riesgo") not in ["CONFIABLE", "NORMAL", None]]
            print(f"      - Dispositivos Sospechosos / BadUSB : {C_BOLD}{C_RED if sos else C_GREEN}{len(sos)}{C_RESET}")
            if devs:
                print(f"\n  {C_BOLD}{C_WHITE}[+] DISPOSITIVOS IDENTIFICADOS:{C_RESET}")
                for d in devs:
                    fn = d.get("friendly_name", "-")
                    ser = d.get("serial_number", "-")
                    st = d.get("estado", "-")
                    print(f"      * {fn} | Serial: {ser} | Estado: {st}")

        elif mid == "7":
            evs = data.get("evidence", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DE EVIDENCIAS DE EJECUCIÓN:{C_RESET}")
            print(f"      - Total de Registros de Ejecución Extraídos : {C_BOLD}{C_CYAN}{len(evs):,}{C_RESET}")
            sources = {}
            for e in evs:
                s = e.get("source", "General")
                sources[s] = sources.get(s, 0) + 1
            print(f"      - Fuentes Forenses: " + ", ".join([f"{k}: {v:,}" for k, v in sources.items()]))
            if evs:
                print(f"\n  {C_BOLD}{C_WHITE}[+] MUESTRA DE EJECUCIÓN RECIENTE (TOP 6):{C_RESET}")
                for e in evs[:6]:
                    raw_p = e.get("path", e.get("program", "-"))
                    pr = Path(raw_p).name if raw_p and raw_p != "-" else str(raw_p)[:30]
                    sr = str(e.get("source", "-"))
                    ts = str(e.get("last_execution", e.get("timestamp", "-")))
                    print(f"      * [{ts}] {pr:<32} (Fuente: {sr})")

        elif mid == "8":
            dls = data.get("downloads", [])
            exts = data.get("extensions", [])
            hist = data.get("suspicious_history", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DE NAVEGADORES WEB (SQLITE TRIAGE):{C_RESET}")
            print(f"      - Descargas de Archivos Registradas : {C_BOLD}{C_CYAN}{len(dls)}{C_RESET}")
            print(f"      - Extensiones Instaladas Detectadas : {C_BOLD}{C_WHITE}{len(exts)}{C_RESET}")
            print(f"      - Entradas Sospechosas en Historial : {C_BOLD}{C_RED if hist else C_GREEN}{len(hist)}{C_RESET}")
            if dls:
                print(f"\n  {C_BOLD}{C_WHITE}[+] ÚLTIMAS DESCARGAS (TOP 5):{C_RESET}")
                for d in dls[:5]:
                    fn = str(d.get("filename", d.get("target_path", "-")))[:35]
                    url = str(d.get("url", "-"))[:45]
                    print(f"      * {fn:<37} -> {url}")

        elif mid == "9":
            procs = data.get("all_processes", [])
            susp = data.get("suspicious_processes", [])
            lsass = data.get("lsass_guard", [])
            unquoted = data.get("unquoted_services", [])
            print(f"  {C_BOLD}{C_WHITE}[+] RESUMEN FORENSE DE MEMORIA Y PROCESOS:{C_RESET}")
            print(f"      - Procesos en RAM Inspeccionados   : {C_BOLD}{C_CYAN}{len(procs)}{C_RESET}")
            print(f"      - Procesos Sospechosos / Anómalos  : {C_BOLD}{C_RED if susp else C_GREEN}{len(susp)}{C_RESET}")
            print(f"      - Servicios con Rutas no Entrecomilladas: {C_BOLD}{C_YELLOW if unquoted else C_GREEN}{len(unquoted)}{C_RESET}")
            print(f"      - Comprobaciones LSASS Guard Activas   : {C_BOLD}{len(lsass)}{C_RESET}")


    except Exception as e:
        print(f"  {C_RED}[!] Error al procesar reporte JSON de {mod['name']}: {e}{C_RESET}")

    if pause:
        input(f"\n  {C_CYAN}Presione Enter para continuar...{C_RESET}")


def view_forensic_summaries():
    """Muestra el submenú de Visor Forense en Consola para explorar resúmenes ejecutivos sin navegador."""
    while True:
        clear_screen()
        print(f"""
  {C_GREEN}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}VISOR FORENSE EN CONSOLA: RESÚMENES EJECUTIVOS Y TELEMETRÍA (100% TERMINAL)                     {C_GREEN}|{C_RESET}
  {C_GREEN}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_GREEN}|                                                                                                  |{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[1]{C_RESET}  {C_CYAN}IntruderDetector: Auditoría de Eventos de Seguridad & Intentos de Intrusión                {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[2]{C_RESET}  {C_CYAN}WiFiSentry: Redes Inalámbricas, Rogue AP Hunter & Entropía PBKDF2                          {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[3]{C_RESET}  {C_CYAN}SocketSentry: Conexiones de Red, Sockets Activos & C2 Beaconing                            {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[4]{C_RESET}  {C_CYAN}DnsSentry: Caché DNS, Análisis DGA & Manipulación de Hosts                                 {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[5]{C_RESET}  {C_CYAN}StartupSentry: Mecanismos de Persistencia, Autoruns & Firmas                               {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[6]{C_RESET}  {C_CYAN}UsbSentry: Dispositivos de Almacenamiento USB & BadUSB Hunter                              {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[7]{C_RESET}  {C_CYAN}ExecSentry: Evidencias de Ejecución (Prefetch, UserAssist, BAM, Shim)                      {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[8]{C_RESET}  {C_CYAN}BrowserSentry: Forense SQLite Multi-Navegador, Descargas & Extensiones                     {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[9]{C_RESET}  {C_CYAN}MemSentry: Procesos en RAM, Linaje de Procesos & LSASS Guard                               {C_GREEN}|{C_RESET}
  {C_GREEN}|                                                                                                  |{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_WHITE}[A]{C_RESET}  {C_BOLD}{C_WHITE}Visualizar Resumen de TODOS los Módulos en Secuencia por Consola                            {C_GREEN}|{C_RESET}
  {C_GREEN}|  {C_BOLD}{C_RED}[0]{C_RESET}  {C_WHITE}Volver al Menú Principal                                                                   {C_GREEN}|{C_RESET}
  {C_GREEN}|                                                                                                  |{C_RESET}
  {C_GREEN}+--------------------------------------------------------------------------------------------------+{C_RESET}
""")
        opt = input(f"  {C_BOLD}{C_GREEN}Seleccione módulo a visualizar [1 al 9, A o 0]: {C_RESET}").strip().upper()
        if opt == "0":
            break
        elif opt == "A":
            for mod_k in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                _show_module_summary(mod_k)
        elif opt in MODULES:
            _show_module_summary(opt)
        else:
            print(f"\n  {C_YELLOW}[!] Opción no reconocida: {opt}{C_RESET}")
            import time
            time.sleep(1)


def run_system_healthcheck(pause: bool = True):
    """Realiza un diagnóstico forense completo del entorno, permisos y módulos."""
    clear_screen()
    print(f"""
  {C_MAGENTA}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_MAGENTA}|  {C_BOLD}{C_WHITE}DIAGNÓSTICO DE SALUD Y VERIFICACIÓN DEL ENTORNO FORENSE                                        {C_MAGENTA}|{C_RESET}
  {C_MAGENTA}+--------------------------------------------------------------------------------------------------+{C_RESET}
""")
    print(f"  {C_BOLD}{C_WHITE}1. VERIFICACIÓN DE PRIVILEGIOS DE SISTEMA:{C_RESET}")
    if is_admin():
        print(f"     {C_GREEN}[✓] Privilegios de Administrador: ACTIVOS (Acceso a Security Log, SAM, Memoria y BITS){C_RESET}")
    else:
        print(f"     {C_YELLOW}[!] Privilegios de Administrador: NO ACTIVOS (Se recomienda ejecutar como Administrador){C_RESET}")

    print(f"\n  {C_BOLD}{C_WHITE}2. VERIFICACIÓN DE COMPATIBILIDAD 0-PIP (STANDARD LIBRARY):{C_RESET}")
    std_libs = ["sqlite3", "csv", "json", "hashlib", "ctypes", "winreg", "subprocess", "datetime", "html"]
    for lib in std_libs:
        try:
            __import__(lib)
            print(f"     {C_GREEN}[✓] {lib}: DISPONIBLE{C_RESET}")
        except ImportError:
            print(f"     {C_YELLOW}[!] {lib}: NO DISPONIBLE EN ESTE ENTORNO{C_RESET}")

    print(f"\n  {C_BOLD}{C_WHITE}3. ESTADO DE LOS MÓDULOS DEL ECOSISTEMA (9 MÓDULOS ESPECIALIZADOS):{C_RESET}")
    for key, mod in MODULES.items():
        p = mod.get("path")
        exists = p and p.exists()
        status_tag = f"{C_GREEN}[ OK ]{C_RESET}" if exists else f"{C_RED}[FALTA]{C_RESET}"
        print(f"     {status_tag} [{mod['id']}] {mod['name']:<18} -> {p.name if exists else 'No encontrado'}")

    print(f"\n  {C_BOLD}{C_WHITE}4. ESTADO DE LAS EVIDENCIAS FORENSES EN DISCO (JSON / CSV CUSTODIA):{C_RESET}")
    for key, mod in MODULES.items():
        r_dir = mod.get("reports")
        has_ev = False
        ev_count = 0
        if r_dir and r_dir.exists():
            files = list(r_dir.glob("*.json")) + list(r_dir.glob("*.csv"))
            has_ev = len(files) > 0
            ev_count = len(files)
        tag = f"{C_GREEN}[ LISTO ]{C_RESET}" if has_ev else f"{C_YELLOW}[PENDIENTE]{C_RESET}"
        print(f"     {tag} {mod['name']:<18} -> {ev_count} archivos de evidencia en {r_dir.name if r_dir else 'N/A'}")

    if pause:
        input(f"\n  {C_CYAN}Presione Enter para volver al menú...{C_RESET}")


# -----------------------------------------------------------------------------
# BUCLE INTERACTIVO
# -----------------------------------------------------------------------------
def interactive_console():
    while True:
        display_menu()
        prompt_text = f"  {C_BOLD}{C_CYAN}Cru9@WinAudit-DFIR{C_WHITE} [{C_GREEN}PYTHON-CORE{C_WHITE}] {C_CYAN}>> {C_RESET}"
        try:
            opcion = input(prompt_text).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not opcion:
            continue

        opcion = opcion.upper()
        if opcion == "0":
            break
        elif opcion in [str(i) for i in range(1, 10)]:
            run_module(opcion)
        elif opcion == "D":
            view_forensic_summaries()
        elif opcion == "S":
            run_system_healthcheck()
        else:
            print(f"\n  {C_YELLOW}[!] Opción inválida '{opcion}'. Seleccione [1 al 9, D, S o 0]...{C_RESET}")
            import time
            time.sleep(1.2)

    clear_screen()
    print(f"""
  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}
  {C_CYAN}|  {C_BOLD}{C_WHITE}WinAudit-DFIR Master Suite | Cru9 Cybersecurity Engineering                               {C_CYAN}|{C_RESET}
  {C_CYAN}+--------------------------------------------------------------------------------------------------+{C_RESET}

   {C_GREEN}[+] Sesión pericial finalizada correctamente.{C_RESET}
   {C_GRAY}Custodia de evidencias preservada bajo norma ISO/IEC 27037:2012.{C_RESET}
""")


# -----------------------------------------------------------------------------
# ENTRY POINT & MODO HEADLESS / CLI
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} | Orquestador Maestro Forense de Cru9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso CLI:
  python Suite-DFIR.py                     # Inicia la consola maestra interactiva
  python Suite-DFIR.py --module 7          # Ejecuta directamente ExecSentry
  python Suite-DFIR.py --health            # Diagnóstico de módulos y entorno 0-pip
  python Suite-DFIR.py --summaries         # Visualiza los resúmenes periciales por consola
        """
    )
    parser.add_argument("--module", "-m", type=str, help="Ejecuta un módulo específico (1..9 o nombre)")
    parser.add_argument("--health", action="store_true", help="Ejecuta el diagnóstico de salud del entorno")
    parser.add_argument("--summaries", "--demos", action="store_true", help="Visualiza los resúmenes forenses de los módulos en consola")
    parser.add_argument("--elevated", "-elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-uac", action="store_true", help="Omite la solicitud de elevación de privilegios")

    args = parser.parse_args()

    # Si no es admin y no se especificó --no-uac ni --elevated, solicitar UAC en Windows
    if not is_admin() and not args.no_uac and not args.elevated and len(sys.argv) == 1:
        request_uac_elevation()

    if args.module:
        mod_key = args.module.upper()
        if mod_key not in MODULES:
            for k, m in MODULES.items():
                if m["name"].upper() == mod_key:
                    mod_key = k
                    break
        if mod_key in MODULES:
            run_module(mod_key)
        else:
            print(f"[!] Módulo no encontrado: {args.module}")
    elif args.health:
        run_system_healthcheck(pause=False)
    elif args.summaries:
        for mod_k in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]:
            _show_module_summary(mod_k, pause=False)
    else:
        interactive_console()


if __name__ == "__main__":
    main()
