#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExecSentry v3.0.0 - Framework Forense de Evidencia de Ejecución en Windows
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
WinAudit-DFIR Suite | Licencia MIT
Zero Dependencias Externas (0-pip: 100% Python Standard Library)
"""

import os
import sys
import re
import json
import csv
import struct
import codecs
import datetime
import html
from pathlib import Path

# Activar colores ANSI en Windows
os.system('')

VERSION = "3.0.0"
AUTHOR = "Cru9"
ECOSYSTEM = "WinAudit-DFIR"

# Paleta ANSI Cyberpunk
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
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# Firmas de Amenazas, LOLBins y Carpetas Sospechosas
SUSPICIOUS_TOOLS = [
    "mimikatz", "rubeus", "procdump", "sharp", "seatbelt", "bloodhound",
    "chisel", "ngrok", "fscan", "adfind", "kekeo", "psexec", "paexec",
    "lazagne", "nanodump", "safetykatz", "pwdump", "gsecdump", "meterpreter",
    "cobaltstrike", "beacon", "havoc", "sliver", "covenant", "brute", "hydra"
]

LOLBINS = [
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "wmic.exe", "powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe",
    "msbuild.exe", "installutil.exe", "vssadmin.exe", "schtasks.exe", "at.exe",
    "nltest.exe", "whoami.exe", "net.exe", "net1.exe", "curl.exe", "wget.exe",
    "csc.exe", "hh.exe", "control.exe", "reg.exe", "bash.exe", "wsl.exe"
]

SUSPICIOUS_PATHS = [
    r"appdata\local\temp", r"appdata\roaming", r"\downloads",
    r"\public", r"\perflogs", r"\programdata", r"windows\temp"
]

def filetime_to_datetime(ft):
    if not ft or ft <= 0:
        return None
    try:
        # Windows FILETIME: 100-ns intervals since 1601-01-01 UTC
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt
    except Exception:
        return None

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""==============================================================================
   ______               _____             _              
  |  ____|             / ____|           | |             
  | |__  __  _____  __| (___   ___ _ __ | |_ _ __ _   _ 
  |  __| \ \/ / _ \/ __\___ \ / _ \ '_ \| __| '__| | | |
  | |____ >  <  __/ (__ ____) |  __/ | | | |_| |  | |_| |
  |______/_/\_\___|\___|_____/ \___|_| |_|\__|_|   \__, |
                                                   |___/ 
=============================================================================="""
    admin_tag = f"{GREEN}[ADMINISTRADOR]{RESET}" if is_admin() else f"{YELLOW}[USUARIO ESTANDAR]{RESET}"
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print(f"  Framework Forense de Evidencia de Ejecución en Windows | v{VERSION}")
    print(f"  Ecosistema Cru9 | Prefetch, UserAssist (ROT13) & BAM | Estado: {admin_tag}")
    print(f"=============================================================================={RESET}\n")

# ==============================================================================
# MOTOR FORENSE 1: USERASSIST (ROT13 & GUI RUNS)
# ==============================================================================
def parse_userassist():
    entries = []
    if os.name != 'nt':
        return entries
    
    import winreg
    targets = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", "Current User")]
    
    # Si somos admin, podemos auditar todos los perfiles montados en HKEY_USERS
    if is_admin():
        try:
            hku = winreg.OpenKey(winreg.HKEY_USERS, "")
            num_keys = winreg.QueryInfoKey(hku)[0]
            for i in range(num_keys):
                sid = winreg.EnumKey(hku, i)
                if not sid.endswith("_Classes") and sid.startswith("S-1-5-21-"):
                    subpath = f"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
                    targets.append((winreg.HKEY_USERS, subpath, f"SID: {sid}"))
        except Exception:
            pass

    for root_hkey, ua_path, user_label in targets:
        try:
            base_key = winreg.OpenKey(root_hkey, ua_path)
        except Exception:
            continue
            
        try:
            num_subkeys = winreg.QueryInfoKey(base_key)[0]
        except Exception:
            num_subkeys = 0

        for i in range(num_subkeys):
            try:
                guid = winreg.EnumKey(base_key, i)
                count_key = winreg.OpenKey(base_key, f"{guid}\\Count")
                num_vals = winreg.QueryInfoKey(count_key)[1]
                for j in range(num_vals):
                    raw_name, data, val_type = winreg.EnumValue(count_key, j)
                    decoded_name = codecs.decode(raw_name, 'rot_13')
                    
                    # Ignorar entradas de sistema no ejecutables
                    if decoded_name in ["UEME_CTLSESSION", "UEME_RUNPATH", "UEME_UIHOTPATH"]:
                        continue
                        
                    run_count = 0
                    last_run = None
                    if isinstance(data, (bytes, bytearray)) and len(data) >= 68:
                        run_count = struct.unpack('<I', data[4:8])[0]
                        ft = struct.unpack('<Q', data[60:68])[0]
                        last_run = filetime_to_datetime(ft)

                    if run_count > 0 or last_run:
                        entries.append({
                            "source": "UserAssist",
                            "user": user_label,
                            "path": decoded_name,
                            "run_count": run_count,
                            "last_execution": last_run.strftime('%Y-%m-%d %H:%M:%S') if last_run else "Desconocido",
                            "raw_timestamp": last_run.timestamp() if last_run else 0,
                            "guid": guid
                        })
            except Exception:
                continue

    return entries

# ==============================================================================
# MOTOR FORENSE 2: BAM / DAM (BACKGROUND ACTIVITY MODERATOR)
# ==============================================================================
def parse_bam():
    entries = []
    if os.name != 'nt':
        return entries
        
    import winreg
    paths = [
        r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    ]
    
    for base_sub in paths:
        try:
            base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_sub)
            num_subkeys = winreg.QueryInfoKey(base_key)[0]
            for i in range(num_subkeys):
                sid = winreg.EnumKey(base_key, i)
                try:
                    sid_key = winreg.OpenKey(base_key, sid)
                    num_vals = winreg.QueryInfoKey(sid_key)[1]
                    for j in range(num_vals):
                        val_name, data, val_type = winreg.EnumValue(sid_key, j)
                        if val_name in ["SequenceNumber", "Version"]:
                            continue
                            
                        last_run = None
                        if isinstance(data, (bytes, bytearray)) and len(data) >= 8:
                            ft = struct.unpack('<Q', data[0:8])[0]
                            last_run = filetime_to_datetime(ft)
                            
                        # Limpiar rutas \Device\HarddiskVolumeX
                        clean_path = val_name
                        m = re.match(r"^\\Device\\HarddiskVolume\d+(.*)$", val_name, re.IGNORECASE)
                        if m:
                            clean_path = f"C:{m.group(1)}"  # normalizacion para inspeccion

                        entries.append({
                            "source": "BAM/DAM",
                            "user": sid,
                            "path": clean_path,
                            "run_count": 1,
                            "last_execution": last_run.strftime('%Y-%m-%d %H:%M:%S') if last_run else "Desconocido",
                            "raw_timestamp": last_run.timestamp() if last_run else 0,
                            "guid": base_sub.split("\\")[4]
                        })
                except Exception:
                    continue
        except Exception:
            continue

    return entries

# ==============================================================================
# MOTOR FORENSE 3: WINDOWS PREFETCH (*.PF)
# ==============================================================================
def parse_prefetch():
    entries = []
    pf_dir = Path("C:/Windows/Prefetch")
    if not pf_dir.exists():
        return entries
        
    try:
        for pf in pf_dir.glob("*.pf"):
            try:
                name = pf.name
                mtime = datetime.datetime.fromtimestamp(pf.stat().st_mtime)
                size_kb = round(pf.stat().st_size / 1024, 2)
                
                # Formato típico: BINARIO.EXE-HASH.pf
                parts = name.split("-")
                exe_name = parts[0]
                pf_hash = parts[1].replace(".pf", "") if len(parts) > 1 else ""
                
                entries.append({
                    "source": "Prefetch",
                    "user": "SYSTEM (Host)",
                    "path": f"C:\\Windows\\Prefetch\\{name} [{exe_name}]",
                    "executable": exe_name,
                    "pf_hash": pf_hash,
                    "size_kb": size_kb,
                    "run_count": 1,
                    "last_execution": mtime.strftime('%Y-%m-%d %H:%M:%S'),
                    "raw_timestamp": mtime.timestamp(),
                    "guid": "PF"
                })
            except Exception:
                continue
    except Exception:
        pass

    return entries

# ==============================================================================
# MOTOR FORENSE 4: SHIMCACHE (APPLICATION COMPATIBILITY CACHE - APPCOMPATCACHE)
# ==============================================================================
def parse_shimcache():
    entries = []
    if os.name != 'nt':
        return entries
        
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache")
        data, _ = winreg.QueryValueEx(key, "AppCompatCache")
    except Exception:
        return entries
        
    pos = 0
    while True:
        pos = data.find(b'10ts', pos)
        if pos == -1:
            break
        try:
            magic, unk, data_size = struct.unpack_from('<4sII', data, pos)
            path_len = struct.unpack_from('<H', data, pos + 12)[0]
            if 0 < path_len < 2000 and (pos + 14 + path_len) <= len(data):
                path_bytes = data[pos + 14 : pos + 14 + path_len]
                path = path_bytes.decode('utf-16le', errors='replace').rstrip('\x00')
                after_path = pos + 14 + path_len
                last_mod = None
                if after_path + 8 <= len(data):
                    last_mod_ft = struct.unpack_from('<Q', data, after_path)[0]
                    last_mod = filetime_to_datetime(last_mod_ft)
                
                clean_path = path
                if clean_path.startswith(r'\??\\'):
                    clean_path = clean_path[4:]
                    
                # Ignorar nombres vacíos o basura binaria
                if clean_path and ("\\" in clean_path or clean_path.endswith(".exe")):
                    exists_on_disk = os.path.exists(clean_path)
                    raw_ts = last_mod.timestamp() if last_mod else 0
                    entries.append({
                        "source": "Shimcache",
                        "user": "SYSTEM (AppCompat)",
                        "path": clean_path,
                        "executable": Path(clean_path).name,
                        "exists_on_disk": exists_on_disk,
                        "run_count": 1,
                        "last_execution": last_mod.strftime('%Y-%m-%d %H:%M:%S') if last_mod else "Desconocido",
                        "raw_timestamp": raw_ts,
                        "guid": "AppCompatCache"
                    })
        except Exception:
            pass
        pos += 4
    return entries

# ==============================================================================
# MOTOR FORENSE 5: AMCACHE & PROGRAM COMPATIBILITY ASSISTANT (PCA)
# ==============================================================================
def parse_pca_amcache():
    entries = []
    if os.name != 'nt':
        return entries
        
    import glob
    import winreg
    
    # 1. Base de datos de ejecución PCA (Windows 10/11)
    for fpath in glob.glob(r"C:\Windows\appcompat\pca\PcaGeneralDb*.txt"):
        try:
            with open(fpath, "r", encoding="utf-16le", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split("|")
                    if len(parts) >= 3:
                        ts_str = parts[0]
                        raw_exe = parts[2]
                        # Expandir variables de entorno
                        clean_exe = os.path.expandvars(raw_exe)
                        app_name = parts[3] if len(parts) > 3 else ""
                        
                        raw_ts = 0
                        try:
                            dt = datetime.datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d %H:%M:%S")
                            raw_ts = dt.timestamp()
                        except Exception:
                            pass
                            
                        exists_on_disk = os.path.exists(clean_exe)
                        entries.append({
                            "source": "Amcache/PCA",
                            "user": "SYSTEM (PCA Store)",
                            "path": clean_exe,
                            "executable": Path(clean_exe).name,
                            "app_name": app_name,
                            "exists_on_disk": exists_on_disk,
                            "run_count": 1,
                            "last_execution": ts_str,
                            "raw_timestamp": raw_ts,
                            "guid": "PCA"
                        })
        except Exception:
            pass

    # 2. Clave de Registro Compatibility Assistant Store
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store")
        num_vals = winreg.QueryInfoKey(key)[1]
        for i in range(num_vals):
            exe_path, _, _ = winreg.EnumValue(key, i)
            if exe_path and ("\\" in exe_path):
                entries.append({
                    "source": "Amcache/PCA",
                    "user": os.environ.get("USERNAME", "Current User"),
                    "path": exe_path,
                    "executable": Path(exe_path).name,
                    "exists_on_disk": os.path.exists(exe_path),
                    "run_count": 1,
                    "last_execution": "Registrado en PCA Store",
                    "raw_timestamp": 0,
                    "guid": "PCA-Store"
                })
    except Exception:
        pass

    return entries

def evaluate_risk(item):
    path_lower = item["path"].lower()
    score = 0
    reasons = []
    
    # 1. Herramientas Ofensivas / Credential Dumping
    for tool in SUSPICIOUS_TOOLS:
        if tool in path_lower:
            score += 85
            reasons.append(f"Herramienta ofensiva conocida / C2: '{tool}'")
            break
            
    # 2. LOLBins (Living Off The Land Binaries)
    for lb in LOLBINS:
        if lb in path_lower:
            score += 40
            reasons.append(f"Binario legítimo potencialmente abusado (LOLBin): '{lb}'")
            break
            
    # 3. Ejecución desde rutas temporales o descargadas
    for sp in SUSPICIOUS_PATHS:
        if sp in path_lower:
            score += 35
            reasons.append(f"Ejecutado desde ruta sospechosa: '{sp}'")
            break
            
    # 4. Doble extensión (e.g., pdf.exe, doc.scr)
    if re.search(r"\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|scr|bat|cmd|vbs|ps1)$", path_lower):
        score += 90
        reasons.append("Técnica de evasión Masquerading: Doble extensión de archivo")

    # 5. Detección Anti-Forensics: Binario ejecutado pero eliminado del disco
    if item.get("exists_on_disk") is False:
        if score > 0 or any(sp in path_lower for sp in SUSPICIOUS_PATHS):
            score += 35
            reasons.append("Anti-Forensics: Binario ejecutado pero eliminado del disco (T1070.004)")
        
    if score >= 75:
        risk = "CRITICAL"
    elif score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    elif reasons:
        risk = "LOW"
    else:
        risk = "CLEAN"
        
    item["risk_level"] = risk
    item["risk_score"] = score
    item["reasons"] = reasons
    return item

def get_all_execution_evidence():
    # Recolectar de las 5 fuentes forenses de ejecución
    ua = parse_userassist()
    bam = parse_bam()
    pf = parse_prefetch()
    shim = parse_shimcache()
    pca = parse_pca_amcache()
    
    combined = ua + bam + pf + shim + pca
    for item in combined:
        evaluate_risk(item)
        
    # Ordenar por fecha más reciente
    combined.sort(key=lambda x: x["raw_timestamp"], reverse=True)
    return combined

# ==============================================================================
# EXPORTACIONES: JSON & CSV
# ==============================================================================
def export_json(data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"ExecSentry_Report_{ts}.json"
    else:
        output_path = Path(output_path)
        
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "tool": "ExecSentry",
                "version": VERSION,
                "author": AUTHOR,
                "timestamp": datetime.datetime.now().isoformat(),
                "total_records": len(data),
                "is_admin": is_admin()
            },
            "evidence": data
        }, f, indent=2, ensure_ascii=False)
    return output_path

def export_csv(data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"ExecSentry_Report_{ts}.csv"
    else:
        output_path = Path(output_path)
        
    keys = ["source", "risk_level", "risk_score", "last_execution", "run_count", "user", "path", "reasons"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in data:
            row = {k: item.get(k, "") for k in keys}
            if isinstance(row["reasons"], list):
                row["reasons"] = " | ".join(row["reasons"])
            writer.writerow(row)
    return output_path

# ==============================================================================
# GENERADOR DASHBOARD HTML CYBERPUNK
# ==============================================================================
def generate_html_dashboard(data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"ExecSentry_Dashboard_{ts}.html"
    else:
        output_path = Path(output_path)

    total = len(data)
    critical_cnt = sum(1 for x in data if x.get("risk_level") == "CRITICAL")
    high_cnt = sum(1 for x in data if x.get("risk_level") == "HIGH")
    medium_cnt = sum(1 for x in data if x.get("risk_level") == "MEDIUM")
    clean_cnt = total - critical_cnt - high_cnt - medium_cnt
    
    # Conteo por fuente
    ua_cnt = sum(1 for x in data if x.get("source") == "UserAssist")
    bam_cnt = sum(1 for x in data if x.get("source") == "BAM/DAM")
    pf_cnt = sum(1 for x in data if x.get("source") == "Prefetch")
    shim_cnt = sum(1 for x in data if x.get("source") == "Shimcache")
    pca_cnt = sum(1 for x in data if x.get("source") in ("PCA", "Amcache/PCA"))

    rows_html = []
    for item in data:
        risk = item.get("risk_level", "CLEAN")
        badge_cls = {
            "CRITICAL": "badge-crit",
            "HIGH": "badge-high",
            "MEDIUM": "badge-med",
            "LOW": "badge-low",
            "CLEAN": "badge-clean"
        }.get(risk, "badge-clean")
        
        src_cls = {
            "UserAssist": "src-ua",
            "BAM/DAM": "src-bam",
            "Prefetch": "src-pf",
            "Shimcache": "src-shim",
            "PCA": "src-pca",
            "Amcache/PCA": "src-pca"
        }.get(item.get("source"), "src-ua")

        reasons = item.get("reasons", [])
        if reasons:
            reasons_html = " • ".join(html.escape(r) for r in reasons)
            reasons_cell = f'<span class="ioc-alert">⚠️ {reasons_html}</span>'
        else:
            reasons_cell = '<span class="ioc-ok">✓ Comportamiento estándar</span>'

        rows_html.append(f"""
        <tr class="evidence-row" data-risk="{risk}" data-source="{item.get('source')}">
            <td><span class="src-badge {src_cls}">{html.escape(item.get('source', ''))}</span></td>
            <td><span class="badge {badge_cls}">{risk}</span></td>
            <td><span class="ts-badge">{item.get('last_execution', '')}</span></td>
            <td><span class="mono-user">{html.escape(str(item.get('user', '')))}</span></td>
            <td><span class="run-count">{item.get('run_count', 0)}</span></td>
            <td class="mono-path">{html.escape(item.get('path', ''))}</td>
            <td>{reasons_cell}</td>
        </tr>
        """)

    metrics = [


        {"label": "Evidencias de Ejecución", "value": total_evidences, "icon": "⚡"},


        {"label": "Severidad Crítica", "value": crit_count, "icon": "🚨"},


        {"label": "Severidad Alta", "value": high_count, "icon": "⚠️"},


        {"label": "Evidencias Íntegras", "value": clean_count, "icon": "✓"}


    ]


    headers = [


        "Fuente Forense", "Riesgo", "Última Ejecución (UTC)", "Usuario",


        "Ejecuciones", "Ruta de Archivo / Binario", "Diagnóstico Forense"


    ]


    try:


        import forensic_theme


    except ImportError:


        base_dir = Path(__file__).resolve().parent.parent


        if str(base_dir) not in sys.path:


            sys.path.insert(0, str(base_dir))


        import forensic_theme



    html_content = forensic_theme.render_homologated_dashboard(


        title="Evidencia Forense de Ejecución en Windows",


        sentry_id="7",


        sentry_name="ExecSentry",


        sentry_icon="⚡",


        subtitle="Análisis de Prefetch (.pf), UserAssist (ROT13), telemetría BAM/DAM y binarios eliminados",


        metrics=metrics,


        table_headers=headers,


        table_rows_html="".join(rows_html),


        risk_score=0 if crit_count == 0 else 65,


        back_url="../../index.html"


    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

# ==============================================================================
# MENU INTERACTIVO CLI
# ==============================================================================
def interactive_menu():
    while True:
        show_banner()
        print(f"  {BOLD}{WHITE}MENU FORENSE DE EVIDENCIA DE EJECUCIÓN:{RESET}")
        print(f"  {CYAN}[1]{RESET} Triage Completo de Ejecución (UserAssist + BAM + Prefetch)")
        print(f"  {CYAN}[2]{RESET} Inspección de UserAssist (Ejecuciones GUI decodificadas ROT13)")
        print(f"  {CYAN}[3]{RESET} Auditoría BAM/DAM (Background Activity Moderator por SID)")
        print(f"  {CYAN}[4]{RESET} Análisis de Archivos Prefetch (C:\\Windows\\Prefetch\\*.pf)")
        print(f"  {CYAN}[5]{RESET} Caza de LOLBins y Binarios Sospechosos Ejecutados")
        print(f"  {CYAN}[6]{RESET} Generar Reportes Forenses (JSON, CSV y Dashboard HTML)")
        print(f"  {RED}[0]{RESET} Volver al Menú Principal de la Suite")
        print()
        
        opt = input(f"  {YELLOW}Selecciona una opción [0-6]: {RESET}").strip()
        
        if opt == "0":
            break
        elif opt in ["1", "5", "6"]:
            print(f"\n  {CYAN}[*] Recolectando evidencias de ejecución en el host...{RESET}")
            evidence = get_all_execution_evidence()
            print(f"  {GREEN}[+] Se encontraron {len(evidence)} evidencias de ejecución.{RESET}")
            
            if opt == "5":
                suspicious = [x for x in evidence if x.get("risk_level") in ["CRITICAL", "HIGH", "MEDIUM"]]
                print(f"\n  {RED}{BOLD}[!] BINARIOS Y LOLBINS SOSPECHOSOS DETECTADOS ({len(suspicious)}):{RESET}")
                for s in suspicious[:15]:
                    print(f"   • [{s['risk_level']}] {s['last_execution']} | {s['path']}")
                    for r in s.get("reasons", []):
                        print(f"      -> {YELLOW}{r}{RESET}")
                if len(suspicious) > 15:
                    print(f"   ... y {len(suspicious) - 15} eventos más en el reporte.")
            else:
                for item in evidence[:10]:
                    print(f"   • [{item['source']}] {item['last_execution']} | {item['path'][:65]}")
                if len(evidence) > 10:
                    print(f"   ... y {len(evidence) - 10} registros adicionales.")
                    
            if opt == "6" or input(f"\n  {YELLOW}¿Deseas generar los reportes y abrir el Dashboard HTML ahora? (s/n): {RESET}").strip().lower() == "s":
                j_out = export_json(evidence)
                c_out = export_csv(evidence)
                h_out = generate_html_dashboard(evidence)
                print(f"\n  {GREEN}[+] Reporte JSON:{RESET} {j_out}")
                print(f"  {GREEN}[+] Reporte CSV:{RESET}  {c_out}")
                print(f"  {GREEN}[+] Dashboard:{RESET}    {h_out}")
                if os.name == 'nt':
                    os.system(f'start "" "{h_out}"')
                    
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")
            
        elif opt == "2":
            print(f"\n  {CYAN}[*] Extrayendo y decodificando claves UserAssist (ROT13)...{RESET}")
            ua = parse_userassist()
            print(f"  {GREEN}[+] Entradas de UserAssist procesadas: {len(ua)}{RESET}\n")
            for item in ua[:12]:
                print(f"   • {item['last_execution']} | Runs: {item['run_count']} | {item['path']}")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")
            
        elif opt == "3":
            print(f"\n  {CYAN}[*] Auditando claves BAM/DAM en HKLM...{RESET}")
            bam = parse_bam()
            if not bam:
                print(f"  {YELLOW}[!] No se pudieron leer claves BAM. Asegúrate de ejecutar como Administrador.{RESET}")
            else:
                print(f"  {GREEN}[+] Entradas BAM procesadas: {len(bam)}{RESET}\n")
                for item in bam[:12]:
                    print(f"   • {item['last_execution']} | SID: {item['user']} | {item['path']}")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

        elif opt == "4":
            print(f"\n  {CYAN}[*] Auditando artefactos Prefetch (*.pf)...{RESET}")
            pf = parse_prefetch()
            if not pf:
                print(f"  {YELLOW}[!] No se pudieron leer archivos Prefetch. Requiere permisos de Administrador.{RESET}")
            else:
                print(f"  {GREEN}[+] Archivos Prefetch analizados: {len(pf)}{RESET}\n")
                for item in pf[:12]:
                    print(f"   • {item['last_execution']} | {item['executable']} ({item['size_kb']} KB)")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description=f"ExecSentry v{VERSION} | Evidencia Forense de Ejecución")
    parser.add_argument("--all", action="store_true", help="Ejecutar triage completo en modo headless y exportar reportes")
    parser.add_argument("--html", type=str, help="Ruta de salida personalizada para el dashboard HTML")
    parser.add_argument("--json", type=str, help="Ruta de salida personalizada para el reporte JSON")
    args = parser.parse_args()
    
    if args.all or args.html or args.json:
        evidence = get_all_execution_evidence()
        j_out = export_json(evidence, args.json)
        h_out = generate_html_dashboard(evidence, args.html)
        c_out = export_csv(evidence)
        print(f"[+] ExecSentry finalizado:")
        print(f"    Total evidencias: {len(evidence)}")
        print(f"    JSON: {j_out}")
        print(f"    CSV:  {c_out}")
        print(f"    HTML: {h_out}")
        return
        
    interactive_menu()

if __name__ == "__main__":
    main()
