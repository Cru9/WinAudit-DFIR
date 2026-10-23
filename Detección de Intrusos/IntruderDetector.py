#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IntruderDetector v3.0.0 | Suite Forense de Host, Detección de Intrusos y Triage de Seguridad en Windows
Desarrollado por: Ezequiel Diaz (Cru9) | https://github.com/Cru9
Parte del Ecosistema WinAudit-DFIR
"""

import os
import sys
import re
import json
import csv
import time
import socket
import datetime
import platform
import subprocess
import html
import ctypes
from pathlib import Path
from typing import Dict, List, Any, Optional

# Habilitar soporte VT100 para colores ANSI en Windows
os.system('')

# Paleta de colores ANSI
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Rutas del proyecto
SCRIPT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SCRIPT_DIR / "Reportes"
ASSETS_DIR = SCRIPT_DIR / "assets"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def is_admin() -> bool:
    """Verifica si el proceso actual cuenta con privilegios de Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_elevation():
    """Solicita elevación UAC en una nueva ventana si no es administrador."""
    try:
        script = str(Path(__file__).resolve())
        params = f'"{script}"'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] No se pudo solicitar elevación UAC: {e}{RESET}")


def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""==============================================================================
   ___       _                 _             ____       _            _             
  |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __  |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
   | || '_ \| __| '__| | | |/ _` |/ _ \ '__| | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
   | || | | | |_| |  | |_| | (_| |  __/ |    | |_| |  __/ ||  __/ (__| || (_) | |   
  |___|_| |_|\__|_|   \__,_|\__,_|\___|_|    |____/ \___|\__\___|\___|\__\___/|_|   
=============================================================================="""
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print("  Suite DFIR de Detección de Intrusos, Triage de Host & Forense de Eventos")
    print("  Ecosistema Cru9 | Windows Host Security Intelligence | v3.0.0")
    print(f"=============================================================================={RESET}\n")


def parse_xml_event_data(xml_str: str) -> Dict[str, str]:
    """Parsea el bloque EventData de un XML de evento de Windows de forma robusta."""
    data = {}
    # Extracción de campos Data con atributo Name
    matches = re.findall(r'<Data\s+Name=[\'"]([^\'"]+)[\'"]>([^<]*)</Data>', xml_str, re.IGNORECASE)
    for k, v in matches:
        data[k] = v.strip()
    
    # Si no tiene Name, extraer los Data secuenciales
    if not matches:
        raw_datas = re.findall(r'<Data>([^<]*)</Data>', xml_str, re.IGNORECASE)
        for idx, val in enumerate(raw_datas):
            data[f"Data_{idx}"] = val.strip()

    # Extracción de campos del System block
    time_match = re.search(r'<TimeCreated\s+SystemTime=[\'"]([^\'"]+)[\'"]', xml_str, re.IGNORECASE)
    if time_match:
        data["SystemTime"] = time_match.group(1)

    event_id_match = re.search(r'<EventID(?:\s+[^>]*)?>(\d+)</EventID>', xml_str, re.IGNORECASE)
    if event_id_match:
        data["EventID"] = event_id_match.group(1)

    computer_match = re.search(r'<Computer>([^<]+)</Computer>', xml_str, re.IGNORECASE)
    if computer_match:
        data["Computer"] = computer_match.group(1)

    return data


def run_wevtutil_query(log_name: str, xpath_query: str, max_events: int = 500) -> List[Dict[str, str]]:
    """Ejecuta una consulta XPath nativa en Windows Event Log usando wevtutil."""
    events = []
    cmd = f'wevtutil qe {log_name} "/q:{xpath_query}" /f:RenderedXml /c:{max_events}'
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="replace")
        if proc.returncode != 0:
            return events
        raw_xml = proc.stdout
        # Dividir cada bloque <Event>...</Event>
        blocks = re.findall(r'(<Event\b[\s\S]*?</Event>)', raw_xml)
        for b in blocks:
            parsed = parse_xml_event_data(b)
            if parsed:
                events.append(parsed)
    except Exception:
        pass
    return events


def run_powershell_query(log_name: str, event_ids: List[int], days_back: int = 7, max_events: int = 500) -> List[Dict[str, Any]]:
    """Consulta de respaldo mediante PowerShell Get-WinEvent."""
    ids_str = ",".join(str(i) for i in event_ids)
    ps_cmd = f"""
    $startDate = (Get-Date).AddDays(-{days_back});
    try {{
        $events = Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Id={ids_str}; StartTime=$startDate}} -MaxEvents {max_events} -ErrorAction Stop;
        $out = foreach ($e in $events) {{
            $d = @{{ TimeCreated = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $e.Id }};
            [xml]$xml = $e.ToXml();
            foreach ($item in $xml.Event.EventData.Data) {{
                if ($item.Name) {{ $d[$item.Name] = $item.'#text' }}
            }}
            $d
        }};
        $out | ConvertTo-Json -Compress
    }} catch {{
        Write-Output "[]"
    }}
    """
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, errors="replace")
        out = proc.stdout.strip()
        if out and out != "[]":
            data = json.loads(out)
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def is_private_ip(ip: str) -> str:
    """Clasifica la dirección IP de origen en Local, Privada (RFC 1918) o WAN Pública."""
    ip = ip.strip()
    if not ip or ip in ["-", "::1", "127.0.0.1", "Local"]:
        return "Local (Loopback)"
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
        return "Red Privada Local"
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return "Red Privada Local"
        except Exception:
            pass
    return "Pública / Internet (EXTERNA)"


def get_current_administrators() -> List[Dict[str, str]]:
    """Obtiene los miembros actuales del grupo Administradores de forma agnóstica al idioma (SID S-1-5-32-544)."""
    members = []
    # 1. Intentar con PowerShell por SID
    ps_cmd = """
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544');
        $groupName = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1];
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            Get-LocalGroupMember -Group $groupName | Select-Object @{N='Name';E={$_.Name}}, @{N='Class';E={$_.ObjectClass}}, @{N='Source';E={$_.PrincipalSource}} | ConvertTo-Json -Compress
        } else {
            net localgroup $groupName
        }
    } catch {
        net localgroup Administradores
    }
    """
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, errors="replace")
        out = res.stdout.strip()
        if out.startswith("[") or out.startswith("{"):
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                members.append({
                    "Cuenta": item.get("Name", "Desconocido"),
                    "Tipo": item.get("Class", "User"),
                    "Origen": item.get("Source", "Local")
                })
            return members
    except Exception:
        pass

    # 2. Fallback a comando net localgroup
    try:
        net_res = subprocess.run("net localgroup Administradores", shell=True, capture_output=True, text=True, errors="replace")
        lines = net_res.stdout.splitlines()
        start = False
        for l in lines:
            l = l.strip()
            if l.startswith("---"):
                start = True
                continue
            if start:
                if "El comando se completó" in l or "The command completed" in l or not l:
                    break
                members.append({"Cuenta": l, "Tipo": "User/Group", "Origen": "Local"})
    except Exception:
        pass

    return members


# ==============================================================================
# CLASE PRINCIPAL: INTRUDER DETECTOR ENGINE
# ==============================================================================
class IntruderDetector:
    def __init__(self, days_back: int = 7, max_events: int = 500):
        self.days_back = days_back
        self.max_events = max_events
        self.hostname = platform.node()
        self.os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        self.cleared_logs: List[Dict[str, Any]] = []
        self.failed_logons: List[Dict[str, Any]] = []
        self.successful_logons: List[Dict[str, Any]] = []
        self.account_changes: List[Dict[str, Any]] = []
        self.suspicious_processes: List[Dict[str, Any]] = []
        self.service_persistence: List[Dict[str, Any]] = []
        self.admin_members: List[Dict[str, str]] = []
        self.threat_score = 0
        self.threat_level = "BAJO"

    def audit_cleared_logs(self) -> List[Dict[str, Any]]:
        """Módulo 1: Revisa si se vaciaron registros de auditoría (1102 / 104 - Anti-Forensics)."""
        results = []
        # Evento 1102: Security log cleared
        ms = self.days_back * 86400000
        sec_xpath = f"*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("Security", sec_xpath, 50)
        
        # Fallback a powershell si wevtutil devolvio vacio pero somos admin
        if not events and is_admin():
            events = run_powershell_query("Security", [1102], self.days_back, 50)

        for ev in events:
            results.append({
                "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "Reciente"),
                "Usuario": ev.get("SubjectUserName", "Desconocido"),
                "Dominio": ev.get("SubjectDomainName", "-"),
                "Log": "Security",
                "Id": 1102,
                "Descripcion": "Vaciado intencional del Registro de Seguridad (Anti-Forensics)",
                "Severidad": "CRÍTICA"
            })

        # Evento 104: System log cleared
        sys_xpath = f"*[System[(EventID=104) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        sys_events = run_wevtutil_query("System", sys_xpath, 50)
        for ev in sys_events:
            results.append({
                "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "Reciente"),
                "Usuario": ev.get("SubjectUserName", "Sistema/Admin"),
                "Dominio": ev.get("SubjectDomainName", "-"),
                "Log": "System",
                "Id": 104,
                "Descripcion": "Registro del Sistema (System Log) vaciado",
                "Severidad": "ALTA"
            })

        self.cleared_logs = results
        return results

    def audit_failed_logons(self) -> List[Dict[str, Any]]:
        """Módulo 2: Revisa intentos fallidos de inicio de sesión (4625 - Fuerza Bruta / Spraying)."""
        results = []
        ms = self.days_back * 86400000
        xpath = f"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("Security", xpath, self.max_events)
        
        if not events and is_admin():
            events = run_powershell_query("Security", [4625], self.days_back, self.max_events)

        for ev in events:
            ip = ev.get("IpAddress", "-").strip()
            user = ev.get("TargetUserName", "Desconocido")
            logon_type = ev.get("LogonType", "-")
            status = ev.get("Status", "")
            substatus = ev.get("SubStatus", "")
            
            # Mapeo de motivo de fallo
            motivo = "Credenciales incorrectas"
            if substatus == "0xc0000064" or substatus == "0xC0000064":
                motivo = "Usuario inexistente (Enumeración)"
            elif substatus == "0xc000006a" or substatus == "0xC000006A":
                motivo = "Contraseña errónea (Fuerza Bruta)"
            elif substatus == "0xc0000234" or substatus == "0xC0000234":
                motivo = "Cuenta Bloqueada por intentos excesivos"

            # Traduccion de LogonType
            tipo_txt = {
                "2": "Interactivo Local (Consola)",
                "3": "Red (SMB / Carpetas)",
                "7": "Desbloqueo de pantalla",
                "10": "RDP (Escritorio Remoto)"
            }.get(logon_type, f"Tipo {logon_type}")

            results.append({
                "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "-"),
                "Usuario": user,
                "IPOrigen": ip,
                "ClasificacionIP": is_private_ip(ip),
                "Puerto": ev.get("IpPort", "-"),
                "TipoAcceso": tipo_txt,
                "LogonType": logon_type,
                "Motivo": motivo,
                "Workstation": ev.get("WorkstationName", "-")
            })

        self.failed_logons = results
        return results

    def audit_successful_logons(self) -> List[Dict[str, Any]]:
        """Módulo 3: Revisa accesos exitosos por RDP (10) o Red (3) (4624 - Movimiento Lateral)."""
        results = []
        ms = self.days_back * 86400000
        # Filtrar específicamente LogonType 10 o 3
        xpath = f"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("Security", xpath, self.max_events)

        if not events and is_admin():
            events = run_powershell_query("Security", [4624], self.days_back, self.max_events)

        ignored_users = {"ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"}
        
        for ev in events:
            user = ev.get("TargetUserName", "")
            logon_type = str(ev.get("LogonType", ""))
            
            # Filtrar cuentas de servicio ruidosas y máquinas terminadas en $
            if not user or user in ignored_users or user.endswith("$") or user.startswith("DWM-") or user.startswith("UMFD-"):
                continue

            if logon_type in ["10", "3"]:
                tipo_txt = "RDP (Escritorio Remoto)" if logon_type == "10" else "Red (SMB / Recursos compartidos)"
                ip = ev.get("IpAddress", "-").strip()
                results.append({
                    "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "-"),
                    "Usuario": user,
                    "Dominio": ev.get("TargetDomainName", "-"),
                    "TipoAcceso": tipo_txt,
                    "LogonType": logon_type,
                    "IPOrigen": ip if ip else "-",
                    "ClasificacionIP": is_private_ip(ip),
                    "EquipoRemoto": ev.get("WorkstationName", "-"),
                    "Proceso": ev.get("ProcessName", "-")
                })

        self.successful_logons = results
        return results

    def audit_account_manipulation(self) -> List[Dict[str, Any]]:
        """Módulo 4: Detecta creación o alteración de usuarios y grupos (4720, 4732, 4728 - Persistencia)."""
        results = []
        ms = self.days_back * 86400000
        xpath = f"*[System[(EventID=4720 or EventID=4726 or EventID=4738 or EventID=4732 or EventID=4728) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("Security", xpath, 100)

        if not events and is_admin():
            events = run_powershell_query("Security", [4720, 4726, 4738, 4732, 4728], self.days_back, 100)

        for ev in events:
            eid = str(ev.get("EventID", ev.get("Id", "")))
            subject = ev.get("SubjectUserName", "Sistema")
            target = ev.get("TargetUserName", ev.get("Data_0", "Cuenta"))
            member = ev.get("MemberName", "-")
            
            acciones = {
                "4720": f"Usuario Creado: '{target}'",
                "4726": f"Usuario Eliminado: '{target}'",
                "4738": f"Usuario Modificado: '{target}'",
                "4732": f"Añadido a Grupo Local: '{member}' -> '{target}'",
                "4728": f"Añadido a Grupo Global: '{member}'"
            }

            results.append({
                "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "-"),
                "IdEvento": eid,
                "Accion": acciones.get(eid, f"Evento {eid}"),
                "EjecutadoPor": subject,
                "Objetivo": target,
                "Severidad": "ALTA" if eid in ["4720", "4732"] else "MEDIA"
            })

        self.account_changes = results
        self.admin_members = get_current_administrators()
        return results

    def audit_suspicious_processes_and_lolbas(self) -> List[Dict[str, Any]]:
        """Módulo 5: Detecta comandos sospechosos, evasión y LOLBAS (4688 / PowerShell 4104)."""
        results = []
        ms = self.days_back * 86400000
        # Evento 4688: Process Creation (si la auditoria de linea de comandos esta activa)
        xpath = f"*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("Security", xpath, 300)

        patterns = [
            (r'vssadmin.*delete\s+shadows', "Destrucción de Backups / Ransomware (vssadmin)", "CRÍTICA", "T1490"),
            (r'wmic.*shadowcopy.*delete', "Destrucción de Copias de Sombra (WMIC)", "CRÍTICA", "T1490"),
            (r'powershell.*(-enc|-encodedcommand)\b', "PowerShell con Payload Ofuscado en Base64", "ALTA", "T1059.001"),
            (r'certutil.*(-urlcache|-split|-decode)\b', "Descarga Insegura / LOLBAS (certutil)", "ALTA", "T1105"),
            (r'bitsadmin.*\/transfer\b', "Descarga Oculta con BITSAdmin", "ALTA", "T1197"),
            (r'(whoami\s+\/all|nltest\s+\/dclist|net\s+group\s+"domain admins")', "Reconocimiento Activo de Privilegios/Dominio", "MEDIA", "T1087"),
            (r'(mimikatz|sekurlsa|procdump.*lsass)', "Intento de Extracción de Credenciales (LSASS)", "CRÍTICA", "T1003.001")
        ]

        for ev in events:
            cmd_line = ev.get("CommandLine", "") or ev.get("ProcessCommandLine", "")
            proc_name = ev.get("NewProcessName", "-")
            parent = ev.get("ParentProcessName", "-")
            user = ev.get("SubjectUserName", "-")

            if not cmd_line and proc_name:
                cmd_line = proc_name

            for pat, desc, sev, mitre in patterns:
                if re.search(pat, cmd_line, re.IGNORECASE):
                    results.append({
                        "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "-"),
                        "Proceso": proc_name.split("\\")[-1],
                        "LineaComando": cmd_line,
                        "Usuario": user,
                        "Amenaza": desc,
                        "Severidad": sev,
                        "Mitre": mitre
                    })
                    break

        self.suspicious_processes = results
        return results

    def audit_services_and_persistence(self) -> List[Dict[str, Any]]:
        """Módulo 6: Detecta nuevos servicios de Windows instalados en el registro de Sistema (Evento 7045)."""
        results = []
        ms = self.days_back * 86400000
        # Evento 7045: A service was installed in the system
        sys_xpath = f"*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
        events = run_wevtutil_query("System", sys_xpath, 100)

        for ev in events:
            name = ev.get("ServiceName", "Servicio")
            path = ev.get("ImagePath", "-")
            user = ev.get("AccountName", "LocalSystem")
            
            # Evaluar si la ruta esta en Temp, AppData o usa cmd/powershell
            sev = "MEDIA"
            if re.search(r'(temp|appdata|users\\public|powershell|cmd\.exe|mshta)', path, re.IGNORECASE):
                sev = "ALTA"

            results.append({
                "Fecha": ev.get("SystemTime") or ev.get("TimeCreated", "-"),
                "Servicio": name,
                "RutaEjecutable": path,
                "Cuenta": user,
                "Severidad": sev,
                "Tipo": "Servicio de Windows (Event 7045)"
            })

        self.service_persistence = results
        return results

    def calculate_threat_score(self):
        """Calcula el índice de riesgo global del sistema host (0 a 100)."""
        score = 0
        
        # Vaciado de registros = sospecha crítica inmediata
        if self.cleared_logs:
            score += len(self.cleared_logs) * 35

        # Fuerza bruta
        failed_count = len(self.failed_logons)
        if failed_count > 50:
            score += 30
        elif failed_count > 10:
            score += 15
        elif failed_count > 0:
            score += 5

        # Inicios remotos RDP
        rdp_logons = [x for x in self.successful_logons if x.get("LogonType") == "10"]
        if rdp_logons:
            score += len(rdp_logons) * 10

        # Cuentas creadas
        if self.account_changes:
            score += len(self.account_changes) * 12

        # Procesos sospechosos
        if self.suspicious_processes:
            score += len(self.suspicious_processes) * 20

        # Servicios sospechosos
        high_services = [s for s in self.service_persistence if s.get("Severidad") == "ALTA"]
        if high_services:
            score += len(high_services) * 15

        self.threat_score = min(score, 100)
        if self.threat_score >= 60:
            self.threat_level = "CRÍTICO (Alta probabilidad de intrusión)"
        elif self.threat_score >= 25:
            self.threat_level = "MEDIO (Actividad sospechosa detectada)"
        else:
            self.threat_level = "BAJO (Sistema íntegro / Sin incidentes graves)"

    def run_full_audit(self):
        """Ejecuta todos los módulos de auditoría en batería."""
        print(f"\n{CYAN}{BOLD}[*] INICIANDO AUDITORÍA FORENSE INTEGRAL DE HOST (Últimos {self.days_back} días)...{RESET}")
        time.sleep(0.5)

        print(f"  {YELLOW}├─ [1/6] Inspeccionando Integridad de Registros (Anti-Forensics)...{RESET}")
        self.audit_cleared_logs()

        print(f"  {YELLOW}├─ [2/6] Analizando Intentos de Autenticación Fallidos (Fuerza Bruta)...{RESET}")
        self.audit_failed_logons()

        print(f"  {YELLOW}├─ [3/6] Rastreo de Movimiento Lateral y Accesos RDP/Red...{RESET}")
        self.audit_successful_logons()

        print(f"  {YELLOW}├─ [4/6] Verificando Alteración de Cuentas y Administradores Locales...{RESET}")
        self.audit_account_manipulation()

        print(f"  {YELLOW}├─ [5/6] Escaneando Ejecución de Comandos LOLBAS y Procesos Sospechosos...{RESET}")
        self.audit_suspicious_processes_and_lolbas()

        print(f"  {YELLOW}└─ [6/6] Auditando Nuevos Servicios de Windows (Evento 7045)...{RESET}")
        self.audit_services_and_persistence()

        self.calculate_threat_score()
        print(f"\n{GREEN}{BOLD}[+] Auditoría completada con éxito. Nivel de Riesgo Global: {self.threat_level}{RESET}\n")

    def print_cli_summary(self):
        """Muestra un resumen estructurado en la consola con colores ANSI."""
        print(f"{CYAN}{BOLD}==============================================================================")
        print(f"                 RESUMEN EJECUTIVO DE TRIAGE FORENSE - CRU9                   ")
        print(f"=============================================================================={RESET}")
        print(f"  {BOLD}Equipo Evaluado:{RESET} {self.hostname} | {BOLD}SO:{RESET} {self.os_info}")
        print(f"  {BOLD}Fecha y Hora:{RESET} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Color del score
        lvl_color = GREEN if "BAJO" in self.threat_level else (YELLOW if "MEDIO" in self.threat_level else RED)
        print(f"  {BOLD}Índice de Amenaza:{RESET} {lvl_color}{BOLD}{self.threat_score}/100 [{self.threat_level}]{RESET}")
        print(f"{CYAN}------------------------------------------------------------------------------{RESET}")

        # 1. Integridad
        print(f"\n{BOLD}[1] INTEGRIDAD DE LOGS (Anti-Forensics / T1070):{RESET}")
        if self.cleared_logs:
            print(f"  {RED}{BOLD}[!] ALERTA CRÍTICA: Se detectaron {len(self.cleared_logs)} evento(s) de vaciado de log!{RESET}")
            for c in self.cleared_logs:
                print(f"      • {c['Fecha']} | Log: {c['Log']} (ID {c['Id']}) | Usuario: {c['Usuario']}")
        else:
            print(f"  {GREEN}[✓] Registros íntegros. No se detectó borrado de auditoría.{RESET}")

        # 2. Fuerza Bruta
        print(f"\n{BOLD}[2] FUERZA BRUTA & AUTENTICACIÓN FALLIDA (Evento 4625 / T1110):{RESET}")
        if self.failed_logons:
            print(f"  {YELLOW}[!] Detectados {len(self.failed_logons)} intento(s) fallido(s).{RESET}")
            # Top atacantes por IP
            ip_counts: Dict[str, int] = {}
            user_counts: Dict[str, int] = {}
            for f in self.failed_logons:
                ip_counts[f["IPOrigen"]] = ip_counts.get(f["IPOrigen"], 0) + 1
                user_counts[f["Usuario"]] = user_counts.get(f["Usuario"], 0) + 1
            
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            
            print(f"      {DIM}Principales fuentes IP:{RESET}")
            for ip, cnt in top_ips:
                print(f"      • {ip} ({is_private_ip(ip)}) -> {cnt} intento(s)")
            print(f"      {DIM}Usuarios más atacados:{RESET}")
            for u, cnt in top_users:
                print(f"      • {u} -> {cnt} intento(s)")
        else:
            print(f"  {GREEN}[✓] Sin intentos fallidos registrados en el periodo.{RESET}")

        # 3. Sesiones RDP / Red
        print(f"\n{BOLD}[3] INICIOS DE SESIÓN REMOTOS EXITOSOS (Evento 4624 / T1021):{RESET}")
        if self.successful_logons:
            print(f"  {YELLOW}[!] Conexiones remotas activas de usuarios:{RESET}")
            for s in self.successful_logons[:5]:
                print(f"      • {s['Fecha']} | {s['Usuario']} | {s['TipoAcceso']} | IP: {s['IPOrigen']} ({s['EquipoRemoto']})")
        else:
            print(f"  {GREEN}[✓] Sin inicios de sesión remotos externos detectados.{RESET}")

        # 4. Cuentas y Administradores
        print(f"\n{BOLD}[4] GESTIÓN DE CUENTAS & ADMINISTRADORES LOCALES (T1136 / S-1-5-32-544):{RESET}")
        if self.account_changes:
            print(f"  {RED}[!] Alteraciones recientes en usuarios/grupos:{RESET}")
            for a in self.account_changes:
                print(f"      • {a['Fecha']} | {a['Accion']} (Por: {a['EjecutadoPor']})")
        else:
            print(f"  {GREEN}[✓] Sin creación anómala de cuentas.{RESET}")
        
        print(f"  {DIM}Miembros del Grupo Administradores:{RESET}")
        for m in self.admin_members:
            print(f"      • {m['Cuenta']} [{m.get('Tipo', 'User')}] ({m.get('Origen', 'Local')})")

        # 5. LOLBAS y Comandos
        print(f"\n{BOLD}[5] DETECCIÓN DE PROCESOS SOSPECHOSOS & LOLBAS (T1059 / T1490):{RESET}")
        if self.suspicious_processes:
            print(f"  {RED}{BOLD}[!] ALERTA: Comandos altamente sospechosos detectados:{RESET}")
            for p in self.suspicious_processes:
                print(f"      • {p['Fecha']} | {p['Amenaza']} (MITRE {p['Mitre']})")
                print(f"        Comando: {p['LineaComando'][:90]}...")
        else:
            print(f"  {GREEN}[✓] No se detectaron comandos destructivos o de evasión de defensas.{RESET}")

        # 6. Servicios Nuevos
        print(f"\n{BOLD}[6] SERVICIOS NUEVOS INSTALADOS (Evento 7045 / T1543.003):{RESET}")
        if self.service_persistence:
            for s in self.service_persistence[:3]:
                print(f"      • {s['Fecha']} | Servicio: '{s['Servicio']}' | Ruta: {s['RutaEjecutable']}")
        else:
            print(f"  {GREEN}[✓] Sin instalación reciente de servicios sospechosos.{RESET}")

        print(f"\n{CYAN}=============================================================================={RESET}\n")

    def export_json(self, filepath: Optional[Path] = None) -> Path:
        """Exporta la evidencia forense completa en formato JSON estructurado."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"IntruderDetector_Audit_{ts}.json"
        
        payload = {
            "metadata": {
                "suite": "WinAudit-DFIR",
                "modulo": "IntruderDetector (Detección de Intrusos)",
                "autor": "Cru9",
                "timestamp": datetime.datetime.now().isoformat(),
                "hostname": self.hostname,
                "os": self.os_info,
                "dias_analizados": self.days_back,
                "threat_score": self.threat_score,
                "threat_level": self.threat_level
            },
            "findings": {
                "cleared_logs": self.cleared_logs,
                "failed_logons": self.failed_logons,
                "successful_logons": self.successful_logons,
                "account_changes": self.account_changes,
                "administrators": self.admin_members,
                "suspicious_processes": self.suspicious_processes,
                "services": self.service_persistence
            }
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return filepath

    def export_csv(self, filepath: Optional[Path] = None) -> Path:
        """Exporta los intentos fallidos y conexiones remotas a CSV para análisis SIEM."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"IntruderDetector_Logons_{ts}.csv"

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Tipo_Evento", "Fecha", "Usuario", "IP_Origen", "Clasificacion_IP", "Puerto", "Tipo_Acceso", "Detalle"])
            for fl in self.failed_logons:
                writer.writerow(["Intento_Fallido", fl.get("Fecha"), fl.get("Usuario"), fl.get("IPOrigen"), fl.get("ClasificacionIP"), fl.get("Puerto"), fl.get("TipoAcceso"), fl.get("Motivo")])
            for sl in self.successful_logons:
                writer.writerow(["Acceso_Exitoso", sl.get("Fecha"), sl.get("Usuario"), sl.get("IPOrigen"), sl.get("ClasificacionIP"), "-", sl.get("TipoAcceso"), sl.get("EquipoRemoto")])
        return filepath

    def generate_html_dashboard(self, filepath: Optional[Path] = None) -> Path:
        """Genera un dashboard interactivo de nivel ejecutivo con colores claros y diseño profesional."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"IntruderDetector_Dashboard_{ts}.html"

        total_failed = len(self.failed_logons)
        total_rdp = len([x for x in self.successful_logons if x.get("LogonType") == "10"])
        total_cleared = len(self.cleared_logs)
        total_accounts = len(self.account_changes)
        total_threats = len(self.suspicious_processes)

        if self.threat_score >= 60:
            score_color = "#b91c1c"
            score_bg = "#fef2f2"
            score_border = "#fecaca"
        elif self.threat_score >= 25:
            score_color = "#b45309"
            score_bg = "#fffbeb"
            score_border = "#fde68a"
        else:
            score_color = "#15803d"
            score_bg = "#f0fdf4"
            score_border = "#bbf7d0"

        # Filas de eventos forenses
        events_rows = []
        for fl in self.failed_logons[:200]:
            events_rows.append(f"""
            <tr class="ev-row">
                <td><span class="badge badge-crit">FALLIDO (4625)</span></td>
                <td><span class="ts-badge">{fl.get('TimeGenerated', '')}</span></td>
                <td><strong style="color:#0f172a;">{html.escape(fl.get('TargetUserName', ''))}</strong></td>
                <td><code class="mono-code">{html.escape(fl.get('IpAddress', ''))}</code></td>
                <td><span class="ioc-alert">Fallo de autenticación (Tipo: {fl.get('LogonType')})</span></td>
            </tr>
            """)

        for sl in self.successful_logons[:100]:
            is_rdp = sl.get("LogonType") == "10"
            b_cls = "badge-high" if is_rdp else "badge-clean"
            lbl = "RDP (TIPO 10)" if is_rdp else "LOGON EXITOSO"
            events_rows.append(f"""
            <tr class="ev-row">
                <td><span class="badge {b_cls}">{lbl}</span></td>
                <td><span class="ts-badge">{sl.get('TimeGenerated', '')}</span></td>
                <td><strong style="color:#0f172a;">{html.escape(sl.get('TargetUserName', ''))}</strong></td>
                <td><code class="mono-code">{html.escape(sl.get('IpAddress', ''))}</code></td>
                <td><span class="{'ioc-alert' if is_rdp else 'ioc-ok'}">Sesión interactiva remota</span></td>
            </tr>
            """)

        for cl in self.cleared_logs:
            events_rows.append(f"""
            <tr class="ev-row">
                <td><span class="badge badge-crit">LOG BORRADO (1102)</span></td>
                <td><span class="ts-badge">{cl.get('TimeGenerated', '')}</span></td>
                <td><strong style="color:#b91c1c;">{html.escape(cl.get('SubjectUserName', ''))}</strong></td>
                <td><code class="mono-code">LOCAL</code></td>
                <td><span class="ioc-alert">⚠️ Anti-Forense: Se limpió el log de seguridad</span></td>
            </tr>
            """)

        metrics = [


            {"label": "Eventos de Seguridad", "value": total_evs, "icon": "🌐"},


            {"label": "Fuerza Bruta (4625)", "value": total_fuerza_bruta, "icon": "🚫"},


            {"label": "Sesiones RDP (10)", "value": len(self.successful_logons), "icon": "🖥️"},


            {"label": "Anti-Forensics (1102)", "value": len(self.cleared_logs), "icon": "🧹"}


        ]


        headers = [


            "Severidad", "Timestamp UTC", "Usuario / Cuenta", "Dirección IP Origen",


            "Diagnóstico Forense"


        ]


        try:


            import forensic_theme


        except ImportError:


            base_dir = Path(__file__).resolve().parent.parent


            if str(base_dir) not in sys.path:


                sys.path.insert(0, str(base_dir))


            import forensic_theme



        html_content = forensic_theme.render_homologated_dashboard(


            title="Detección de Intrusos & Live Host Radar",


            sentry_id="1",


            sentry_name="IntruderDetector",


            sentry_icon="🌐",


            subtitle="Auditoría de Security Log, Fuerza Bruta (4625), Sesiones RDP (10) y Anti-Forensics (1102)",


            metrics=metrics,


            table_headers=headers,


            table_rows_html="".join(events_rows),


            risk_score=self.threat_score if hasattr(self, 'threat_score') else 0,


            back_url="../../index.html"


        )
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath

    def live_radar_monitor(self, interval: int = 3):
        """Módulo 7: Radar en Tiempo Real (Live SIEM) que vigila el Security Log continuamente."""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{CYAN}{BOLD}==============================================================================")
        print("     RADAR DE INTRUSIONES EN TIEMPO REAL (LIVE HOST SIEM & EVENT TAIL)        ")
        print(f"==============================================================================")
        print(f"  Vigilando: Eventos 1102 (Vaciado), 4625 (Fuerza Bruta), 4624-10 (RDP), 4720")
        print(f"  Refresco: Cada {interval}s | [Presiona 'Ctrl+C' para detener el radar]")
        print(f"=============================================================================={RESET}\n")

        seen_timestamps = set()
        scan_count = 0

        try:
            while True:
                scan_count += 1
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                # Consultar ultimos 10 segundos
                xpath = "*[System[(EventID=1102 or EventID=4625 or EventID=4624 or EventID=4720) and TimeCreated[timediff(@SystemTime) <= 15000]]]"
                events = run_wevtutil_query("Security", xpath, 20)

                sys.stdout.write(f"\r  {CYAN}[Radar Pulso #{scan_count}]{RESET} {now_str} | Escaneando canales de auditoría... ")
                sys.stdout.flush()

                for ev in events:
                    eid = ev.get("EventID", "")
                    st = ev.get("SystemTime", "")
                    key = f"{eid}_{st}_{ev.get('TargetUserName', '')}"
                    if key not in seen_timestamps:
                        seen_timestamps.add(key)
                        print("\n")
                        # Emite alerta sonora si esta en Windows
                        print('\a', end='')
                        
                        if eid == "1102":
                            print(f"  {RED}{BOLD}[ALERTA CRÍTICA 1102]{RESET} {st} - Registro de Seguridad Vaciado por '{ev.get('SubjectUserName')}'!")
                        elif eid == "4625":
                            ip = ev.get("IpAddress", "-")
                            print(f"  {YELLOW}{BOLD}[ALERTA FUERZA BRUTA 4625]{RESET} {st} - Fallo de logon usuario '{ev.get('TargetUserName')}' desde IP: {ip} ({is_private_ip(ip)})")
                        elif eid == "4624" and ev.get("LogonType") == "10":
                            print(f"  {MAGENTA}{BOLD}[AVISO ACCESO RDP 4624-10]{RESET} {st} - Inicio de sesión RDP por '{ev.get('TargetUserName')}' desde IP: {ev.get('IpAddress')}")
                        elif eid == "4720":
                            print(f"  {RED}{BOLD}[ALERTA PERSISTENCIA 4720]{RESET} {st} - Nuevo usuario creado: '{ev.get('TargetUserName')}'")

                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[*] Radar en tiempo real detenido por el usuario.{RESET}")


# ==============================================================================
# MENU INTERACTIVO Y CLI
# ==============================================================================
def interactive_menu():
    detector = IntruderDetector(days_back=7)

    # Comprobacion de permisos
    if not is_admin():
        print(f"{YELLOW}[!] AVISO: No estás ejecutando como Administrador.{RESET}")
        print(f"    El Registro de Seguridad de Windows requiere permisos elevados.")
        print(f"    ¿Deseas solicitar elevación de permisos ahora? (s/n)")
        resp = input("    > ").strip().lower()
        if resp == 's':
            request_elevation()
            return

    while True:
        show_banner()
        print("  Selecciona una opción de análisis forense:")
        print("  ────────────────────────────────────────────────────────────────────────")
        print("  [1] 🚀 Auditoría Forense Integral Completa (Todos los Módulos)")
        print("  [2] 🛡️  Revisión de Integridad de Logs & Anti-Forensics (Eventos 1102 / 104)")
        print("  [3] 🔨 Hunter de Fuerza Bruta & Password Spraying (Evento 4625)")
        print("  [4] 🌐 Rastreo de Accesos Remotos & Movimiento Lateral (RDP 10 / Red 3)")
        print("  [5] 👥 Auditoría de Persistencia y Cuentas de Administrador (4720 / S-1-5-32-544)")
        print("  [6] 🥷 Hunter de Comandos Sospechosos & LOLBAS (Evento 4688 / T1490)")
        print("  [7] ⚙️  Nuevos Servicios Instalados en el Sistema (Evento 7045 en System Log)")
        print("  [8] 📡 Radar de Intrusiones en Vivo (Monitor en Tiempo Real / Live Tail)")
        print("  [9] 📊 Generar y Abrir Dashboard HTML Cyberpunk (Reporte Ejecutivo)")
        print("  [10] 💾 Exportar Evidencias Multi-formato (JSON + CSV)")
        print("  [0] 🚪 Salir")
        print("  ────────────────────────────────────────────────────────────────────────")

        choice = input("\n  Ingrese una opción [0-10]: ").strip()

        if choice == "1":
            detector.run_full_audit()
            detector.print_cli_summary()
            html_p = detector.generate_html_dashboard()
            json_p = detector.export_json()
            csv_p = detector.export_csv()
            print(f"  {GREEN}[+] Reportes generados en 'Reportes/':{RESET}")
            print(f"      • HTML: {html_p.name}")
            print(f"      • JSON: {json_p.name}")
            print(f"      • CSV:  {csv_p.name}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "2":
            res = detector.audit_cleared_logs()
            print(f"\n{CYAN}{BOLD}=== REVISIÓN DE INTEGRIDAD DE LOGS ==={RESET}")
            if res:
                for r in res:
                    print(f"  {RED}[!] {r['Fecha']} | {r['Descripcion']} | Usuario: {r['Usuario']}{RESET}")
            else:
                print(f"  {GREEN}[✓] No se detectó vaciado de registros en los últimos {detector.days_back} días.{RESET}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "3":
            res = detector.audit_failed_logons()
            print(f"\n{CYAN}{BOLD}=== INTENTOS FALLIDOS DE INICIO DE SESIÓN (4625) ==={RESET}")
            print(f"  Total detectados: {len(res)}")
            for r in res[:15]:
                print(f"  • {r['Fecha']} | Usuario: {r['Usuario']} | IP: {r['IPOrigen']} ({r['ClasificacionIP']}) | Motivo: {r['Motivo']}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "4":
            res = detector.audit_successful_logons()
            print(f"\n{CYAN}{BOLD}=== INICIOS DE SESIÓN REMOTOS (RDP / RED) ==={RESET}")
            print(f"  Total detectados: {len(res)}")
            for r in res[:15]:
                print(f"  • {r['Fecha']} | Usuario: {r['Usuario']} | {r['TipoAcceso']} | IP: {r['IPOrigen']}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "5":
            detector.audit_account_manipulation()
            print(f"\n{CYAN}{BOLD}=== MIEMBROS ACTUALES DEL GRUPO ADMINISTRADORES ==={RESET}")
            for m in detector.admin_members:
                print(f"  • {m['Cuenta']} [{m.get('Tipo', 'User')}] ({m.get('Origen', 'Local')})")
            if detector.account_changes:
                print(f"\n{YELLOW}{BOLD}Alteraciones recientes:{RESET}")
                for a in detector.account_changes:
                    print(f"  • {a['Fecha']} | {a['Accion']} por {a['EjecutadoPor']}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "6":
            res = detector.audit_suspicious_processes_and_lolbas()
            print(f"\n{CYAN}{BOLD}=== COMANDOS SOSPECHOSOS Y LOLBAS ==={RESET}")
            if res:
                for p in res:
                    print(f"  {RED}[!] {p['Fecha']} | {p['Amenaza']} (MITRE {p['Mitre']})")
                    print(f"      Cmd: {p['LineaComando']}")
            else:
                print(f"  {GREEN}[✓] No se detectaron comandos sospechosos en el periodo analizado.{RESET}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "7":
            res = detector.audit_services_and_persistence()
            print(f"\n{CYAN}{BOLD}=== SERVICIOS INSTALADOS RECIENTEMENTE (7045) ==={RESET}")
            for s in res[:10]:
                print(f"  • {s['Fecha']} | Servicio: {s['Servicio']} | Ruta: {s['RutaEjecutable']}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "8":
            detector.live_radar_monitor(interval=3)
            input("\n  Presiona Enter para continuar...")

        elif choice == "9":
            if not detector.failed_logons and not detector.cleared_logs:
                detector.run_full_audit()
            html_path = detector.generate_html_dashboard()
            print(f"\n{GREEN}[+] Dashboard HTML generado en: {html_path}{RESET}")
            try:
                os.startfile(html_path)
            except Exception:
                pass
            input("\n  Presiona Enter para continuar...")

        elif choice == "10":
            if not detector.failed_logons and not detector.cleared_logs:
                detector.run_full_audit()
            j = detector.export_json()
            c = detector.export_csv()
            print(f"\n{GREEN}[+] Evidencias exportadas:{RESET}")
            print(f"    • JSON: {j}")
            print(f"    • CSV:  {c}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "0":
            print(f"\n{CYAN}Gracias por utilizar IntruderDetector de Cru9.{RESET}\n")
            break


def main():
    if len(sys.argv) > 1:
        # Modo CLI / Headless para ejecución grupal automatizada
        import argparse
        parser = argparse.ArgumentParser(description="IntruderDetector | Windows DFIR Host Intrusion Triage")
        parser.add_argument("--scan", action="store_true", help="Ejecuta la auditoría forense completa")
        parser.add_argument("--days", type=int, default=7, help="Días hacia atrás a inspeccionar (default: 7)")
        parser.add_argument("--json", action="store_true", help="Exporta los resultados a JSON")
        parser.add_argument("--csv", action="store_true", help="Exporta los resultados a CSV")
        parser.add_argument("--html", action="store_true", help="Genera el Dashboard HTML ejecutivo")
        parser.add_argument("--live", action="store_true", help="Inicia el monitor radar en tiempo real")
        args = parser.parse_args()

        detector = IntruderDetector(days_back=args.days)
        if args.live:
            detector.live_radar_monitor()
            return

        if args.scan or args.json or args.csv or args.html:
            detector.run_full_audit()
            detector.print_cli_summary()
            if args.json:
                jp = detector.export_json()
                print(f"[+] JSON: {jp}")
            if args.csv:
                cp = detector.export_csv()
                print(f"[+] CSV: {cp}")
            if args.html:
                hp = detector.generate_html_dashboard()
                print(f"[+] HTML: {hp}")
            return

    interactive_menu()


if __name__ == "__main__":
    main()
