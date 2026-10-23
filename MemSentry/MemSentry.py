#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MemSentry v3.0.0 - Framework Forense de Procesos en Vivo, Inyección & LSASS Guard
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
WinAudit-DFIR Suite | Licencia MIT
Zero Dependencias Externas (0-pip: 100% Python Standard Library)
"""

import os
import sys
import re
import json
import csv
import subprocess
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

SYSTEM_BINARIES = [
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "svchost.exe", "spoolsv.exe", "taskhostw.exe", "explorer.exe"
]

SUSPICIOUS_PARENTS = {
    "svchost.exe": ["services.exe"],
    "services.exe": ["wininit.exe"],
    "lsass.exe": ["wininit.exe"]
}

OFFICE_PARENT_BLACKLIST = [
    "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe",
    "acrobat.exe", "w3wp.exe", "sqlservr.exe"
]

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""==============================================================================
  __  __                 _____             _              
 |  \/  |               / ____|           | |             
 | \  / | ___ _ __ ___ | (___   ___ _ __ | |_ _ __ _   _ 
 | |\/| |/ _ \ '_ ` _ \ \___ \ / _ \ '_ \| __| '__| | | |
 | |  | |  __/ | | | | |____) |  __/ | | | |_| |  | |_| |
 |_|  |_|\___|_| |_| |_|_____/ \___|_| |_|\__|_|   \__, |
                                                   |___/ 
=============================================================================="""
    admin_tag = f"{GREEN}[ADMINISTRADOR]{RESET}" if is_admin() else f"{YELLOW}[USUARIO ESTANDAR]{RESET}"
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print(f"  Framework Forense de Procesos en RAM, Inyección & LSASS Guard | v{VERSION}")
    print(f"  Ecosistema Cru9 | Process Tree, Masquerading & Credential Protection | Estado: {admin_tag}")
    print(f"=============================================================================={RESET}\n")

# ==============================================================================
# AUDITORÍA 1: PROTECCIÓN DE LSASS Y SEGURIDAD DE CREDENCIALES
# ==============================================================================
def audit_lsass_protection():
    findings = []
    if os.name != 'nt':
        return findings

    import winreg

    # 1. RunAsPPL (Protected Process Light)
    ppl_val = None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa")
        ppl_val, _ = winreg.QueryValueEx(key, "RunAsPPL")
    except Exception:
        pass

    if ppl_val == 1:
        findings.append({
            "check": "LSASS RunAsPPL (Protected Process)",
            "status": "SECURE",
            "risk_level": "CLEAN",
            "value": "1 (Habilitado con bloqueo UEFI)",
            "description": "LSASS se ejecuta como Proceso Protegido con firma de Microsoft (Inmune a volcados directos)."
        })
    elif ppl_val == 2:
        findings.append({
            "check": "LSASS RunAsPPL (Protected Process)",
            "status": "SECURE",
            "risk_level": "CLEAN",
            "value": "2 (Habilitado sin bloqueo UEFI)",
            "description": "LSASS se ejecuta como Proceso Protegido sin candado UEFI."
        })
    else:
        findings.append({
            "check": "LSASS RunAsPPL (Protected Process)",
            "status": "VULNERABLE",
            "risk_level": "CRITICAL",
            "value": "Deshabilitado (0 o ausente)",
            "description": "LSASS está desprotegido. Herramientas como Mimikatz o ProcDump pueden volcar credenciales de memoria."
        })

    # 2. WDigest (Almacenamiento de contraseñas en texto claro)
    wdigest_val = 0
    try:
        wd_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")
        wdigest_val, _ = winreg.QueryValueEx(wd_key, "UseLogonCredential")
    except Exception:
        pass

    if wdigest_val == 1:
        findings.append({
            "check": "WDigest Plaintext Credentials",
            "status": "VULNERABLE",
            "risk_level": "CRITICAL",
            "value": "UseLogonCredential = 1",
            "description": "Windows está forzado a guardar contraseñas en texto claro en memoria RAM."
        })
    else:
        findings.append({
            "check": "WDigest Plaintext Credentials",
            "status": "SECURE",
            "risk_level": "CLEAN",
            "value": "Deshabilitado (0)",
            "description": "Caché de contraseñas en texto claro de WDigest desactivada."
        })

    # 3. Credential Guard (VBS)
    cg_val = 0
    try:
        dg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard")
        cg_val, _ = winreg.QueryValueEx(dg_key, "EnableVirtualizationBasedSecurity")
    except Exception:
        pass

    if cg_val == 1:
        findings.append({
            "check": "Windows Credential Guard (VBS)",
            "status": "SECURE",
            "risk_level": "CLEAN",
            "value": "Habilitado (1)",
            "description": "Aislamiento por virtualización activo para secretos de autenticación."
        })
    else:
        findings.append({
            "check": "Windows Credential Guard (VBS)",
            "status": "WARNING",
            "risk_level": "MEDIUM",
            "value": "Deshabilitado o no configurado",
            "description": "La seguridad basada en virtualización (VBS) no está forzada en el sistema."
        })

    return findings

# ==============================================================================
# AUDITORÍA 2: UNQUOTED SERVICE PATHS (T1574.009)
# ==============================================================================
def audit_unquoted_services():
    vulnerable_services = []
    if os.name != 'nt':
        return vulnerable_services

    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        num_sub = winreg.QueryInfoKey(key)[0]
        for i in range(num_sub):
            s_name = winreg.EnumKey(key, i)
            try:
                s_key = winreg.OpenKey(key, s_name)
                img, _ = winreg.QueryValueEx(s_key, "ImagePath")
                if not img:
                    continue

                # Extraer binario antes de argumentos
                clean_img = img.strip()
                if clean_img.startswith('"'):
                    continue  # Ya está entrecomillado

                # Buscar si la ruta hasta .exe tiene espacios
                m = re.match(r"^([^.]+\.exe)", clean_img, re.IGNORECASE)
                exe_part = m.group(1) if m else clean_img

                if " " in exe_part and not exe_part.lower().startswith("c:\\windows\\system32"):
                    vulnerable_services.append({
                        "service_name": s_name,
                        "image_path": img,
                        "vulnerable_binary_path": exe_part,
                        "risk_level": "HIGH",
                        "technique": "T1574.009",
                        "description": "Ruta de servicio con espacios sin comillas. Vector de escalada local de privilegios."
                    })
            except Exception:
                pass
    except Exception:
        pass

    return vulnerable_services

# ==============================================================================
# AUDITORÍA 3: PROCESOS EN RAM, MASQUERADING & ÁRBOL ANÓMALO
# ==============================================================================
def get_running_processes():
    processes = []
    if os.name != 'nt':
        return processes

    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, Path, CommandLine, CreationDate | ConvertTo-Json -Depth 2"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            raw_data = json.loads(res.stdout)
            if isinstance(raw_data, dict):
                raw_data = [raw_data]
            processes = raw_data
    except Exception:
        pass

    return processes

def analyze_processes(processes):
    analyzed = []
    pid_map = {p.get("ProcessId"): p for p in processes}

    suspicious_paths = [
        r"appdata\local\temp", r"appdata\roaming", r"\downloads",
        r"\public", r"\perflogs", r"c:\windows\temp"
    ]

    for p in processes:
        pid = p.get("ProcessId")
        ppid = p.get("ParentProcessId")
        name = p.get("Name", "").lower()
        path = p.get("Path") or ""
        cmdline = p.get("CommandLine") or ""
        creation = p.get("CreationDate") or ""
        
        # Formatear fecha WMI si viene como string
        date_str = ""
        m_date = re.match(r"^/Date\((\d+)\)/", creation)
        if m_date:
            ts_ms = int(m_date.group(1))
            date_str = datetime.datetime.fromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')
        elif creation:
            date_str = str(creation)[:19]

        parent_proc = pid_map.get(ppid, {})
        parent_name = parent_proc.get("Name", "").lower()

        score = 0
        reasons = []

        # 1. Masquerading de Binarios de Sistema
        if name in SYSTEM_BINARIES:
            if path and not path.lower().startswith(r"c:\windows\system32") and not path.lower().startswith(r"c:\windows\syswow64") and not (name == "explorer.exe" and path.lower() == r"c:\windows\explorer.exe"):
                score += 90
                reasons.append(f"Masquerading Crítico: '{name}' ejecutándose fuera de System32 ({path})")

        # 2. Anomalías Padre-Hijo
        if name in SUSPICIOUS_PARENTS:
            valid_parents = SUSPICIOUS_PARENTS[name]
            if parent_name and parent_name not in valid_parents:
                score += 80
                reasons.append(f"Padre Anómalo: '{name}' engendrado por '{parent_name}' (Esperado: {', '.join(valid_parents)})")

        # 3. Macro / Document Exploit (Office o PDF lanzando PowerShell o CMD)
        if name in ["cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe"]:
            if parent_name in OFFICE_PARENT_BLACKLIST:
                score += 95
                reasons.append(f"Alerta de Exploit: '{name}' lanzado directamente por '{parent_name}' (Posible phishing / macro maliciosa)")

        # 4. Ejecución de proceso desde ruta temporal
        for sp in suspicious_paths:
            if sp in path.lower():
                score += 40
                reasons.append(f"Proceso en memoria corriendo desde ruta sospechosa: '{sp}'")
                break

        # 5. Comandos altamente sospechosos / Ofuscación
        cmd_lower = cmdline.lower()
        if "-enc " in cmd_lower or "-encodedcommand " in cmd_lower:
            score += 65
            reasons.append("PowerShell con comando codificado en Base64 (-enc / -EncodedCommand)")
        if "procdump" in cmd_lower and "lsass" in cmd_lower:
            score += 100
            reasons.append("Intento de volcado de memoria de LSASS mediante ProcDump")
        if "comsvcs" in cmd_lower and "minidump" in cmd_lower:
            score += 100
            reasons.append("Técnica de evasión LOLBin: Volcado de LSASS con comsvcs.dll MiniDump")
        if "reg save" in cmd_lower and ("sam" in cmd_lower or "system" in cmd_lower):
            score += 90
            reasons.append("Extracción de claves SAM/SYSTEM del registro de Windows")

        if score >= 75:
            risk = "CRITICAL"
        elif score >= 50:
            risk = "HIGH"
        elif score >= 25:
            risk = "MEDIUM"
        else:
            risk = "CLEAN"

        analyzed.append({
            "pid": pid,
            "ppid": ppid,
            "name": p.get("Name"),
            "path": path,
            "parent_name": parent_proc.get("Name", f"PID {ppid}"),
            "cmdline": cmdline,
            "creation_date": date_str,
            "risk_level": risk,
            "risk_score": score,
            "reasons": reasons
        })

    analyzed.sort(key=lambda x: x["risk_score"], reverse=True)
    return analyzed

# ==============================================================================
# EXPORTACIONES: JSON & CSV
# ==============================================================================
def export_json(lsass_data, unquoted_data, proc_data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"MemSentry_Report_{ts}.json"
    else:
        output_path = Path(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "tool": "MemSentry",
                "version": VERSION,
                "author": AUTHOR,
                "timestamp": datetime.datetime.now().isoformat(),
                "is_admin": is_admin(),
                "total_processes": len(proc_data),
                "unquoted_services": len(unquoted_data)
            },
            "lsass_guard": lsass_data,
            "unquoted_services": unquoted_data,
            "suspicious_processes": [p for p in proc_data if p["risk_level"] != "CLEAN"],
            "all_processes": proc_data
        }, f, indent=2, ensure_ascii=False)
    return output_path

def export_csv(proc_data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"MemSentry_Processes_{ts}.csv"
    else:
        output_path = Path(output_path)

    keys = ["pid", "ppid", "risk_level", "risk_score", "name", "parent_name", "path", "cmdline", "reasons"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for p in proc_data:
            row = {k: p.get(k, "") for k in keys}
            if isinstance(row["reasons"], list):
                row["reasons"] = " | ".join(row["reasons"])
            writer.writerow(row)
    return output_path

# ==============================================================================
# GENERADOR DASHBOARD HTML CYBERPUNK
# ==============================================================================
def generate_html_dashboard(lsass_data, unquoted_data, proc_data, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"MemSentry_Dashboard_{ts}.html"
    else:
        output_path = Path(output_path)

    total_procs = len(proc_data)
    crit_procs = sum(1 for p in proc_data if p["risk_level"] == "CRITICAL")
    high_procs = sum(1 for p in proc_data if p["risk_level"] == "HIGH")
    med_procs = sum(1 for p in proc_data if p["risk_level"] == "MEDIUM")

    # Filas de LSASS Guard
    lsass_rows = []
    for l in lsass_data:
        b_cls = "badge-crit" if l["risk_level"] == "CRITICAL" else ("badge-high" if l["risk_level"] == "MEDIUM" else "badge-clean")
        lsass_rows.append(f"""
        <tr>
            <td><strong style="color:#0f172a;">{html.escape(l['check'])}</strong></td>
            <td><span class="badge {b_cls}">{html.escape(l['status'])}</span></td>
            <td><code class="mono-code">{html.escape(str(l['value']))}</code></td>
            <td style="color:#475569; font-size:0.85rem;">{html.escape(l['description'])}</td>
        </tr>
        """)

    # Filas de Unquoted Services
    unquoted_rows = []
    for u in unquoted_data:
        unquoted_rows.append(f"""
        <tr>
            <td><strong style="color:#b45309;">{html.escape(u['service_name'])}</strong></td>
            <td><span class="badge badge-high">T1574.009</span></td>
            <td style="font-family:ui-monospace, monospace; font-size:0.8rem; color:#b91c1c;">{html.escape(u['vulnerable_binary_path'])}</td>
            <td style="font-family:ui-monospace, monospace; font-size:0.78rem; color:#64748b;">{html.escape(u['image_path'])}</td>
        </tr>
        """)

    # Filas de Procesos
    proc_rows = []
    for p in proc_data:
        risk = p["risk_level"]
        b_cls = {
            "CRITICAL": "badge-crit",
            "HIGH": "badge-high",
            "MEDIUM": "badge-med",
            "CLEAN": "badge-clean"
        }.get(risk, "badge-clean")

        reasons = p.get("reasons", [])
        if reasons:
            reasons_html = f'<span class="ioc-alert">⚠️ {" • ".join(html.escape(r) for r in reasons)}</span>'
        else:
            reasons_html = '<span class="ioc-ok">✓ Comportamiento normal</span>'

        proc_rows.append(f"""
        <tr class="proc-row" data-risk="{risk}">
            <td><span class="badge {b_cls}">{risk}</span></td>
            <td><span class="pid-badge">{p['pid']}</span> <small style="color:#64748b;">(PPID: {p['ppid']})</small></td>
            <td><strong style="color:#0f172a;">{html.escape(str(p['name']))}</strong></td>
            <td><span class="parent-badge">{html.escape(str(p['parent_name']))}</span></td>
            <td class="mono-path">{html.escape(str(p['path']))}</td>
            <td class="mono-cmd">{html.escape(str(p['cmdline'])[:140])}</td>
            <td>{reasons_html}</td>
        </tr>
        """)

    metrics = [


        {"label": "Procesos en RAM", "value": total_procs, "icon": "🧠"},


        {"label": "LSASS RunAsPPL Guard", "value": "BLINDADO [PPL]" if lsass_data.get("is_protected_ppl") else "VULNERABLE", "icon": "🛡️"},


        {"label": "PPID Spoofing", "value": crit_count, "icon": "🚨"},


        {"label": "Unquoted Path Services", "value": len(unquoted_data), "icon": "⚠️"},


        {"label": "Procesos Normales", "value": clean_count, "icon": "✓"}


    ]


    headers = [


        "Severidad", "PID & PPID", "Proceso", "Proceso Padre",


        "Ruta Ejecutable", "Línea de Comandos", "Diagnóstico Forense"


    ]


    try:


        import forensic_theme


    except ImportError:


        base_dir = Path(__file__).resolve().parent.parent


        if str(base_dir) not in sys.path:


            sys.path.insert(0, str(base_dir))


        import forensic_theme



    html_content = forensic_theme.render_homologated_dashboard(


        title="Procesos en RAM, Inyección & LSASS Guard",


        sentry_id="9",


        sentry_name="MemSentry",


        sentry_icon="🧠",


        subtitle="Árbol de procesos en vivo, linaje padre-hijo, auditoría RunAsPPL y Unquoted Paths",


        metrics=metrics,


        table_headers=headers,


        table_rows_html="".join(proc_rows),


        risk_score=0 if crit_count == 0 else 80,


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
        print(f"  {BOLD}{WHITE}MENU FORENSE DE MEMORIA Y PROCESOS:{RESET}")
        print(f"  {CYAN}[1]{RESET} Triage Completo (Árbol de Procesos + LSASS Guard + Unquoted Services)")
        print(f"  {CYAN}[2]{RESET} Inspección de Seguridad LSASS Guard (RunAsPPL, WDigest & Credential Guard)")
        print(f"  {CYAN}[3]{RESET} Caza de Procesos Anómalos, Masquerading & Comandos Codificados")
        print(f"  {CYAN}[4]{RESET} Scanner de Rutas de Servicio sin Comillas (Unquoted Service Paths)")
        print(f"  {CYAN}[5]{RESET} Generar Reportes Forenses (JSON, CSV y Dashboard HTML)")
        print(f"  {RED}[0]{RESET} Volver al Menú Principal de la Suite")
        print()

        opt = input(f"  {YELLOW}Selecciona una opción [0-5]: {RESET}").strip()
        if opt == "0":
            break
        elif opt in ["1", "3", "5"]:
            print(f"\n  {CYAN}[*] Capturando e inspeccionando árbol de procesos en memoria RAM...{RESET}")
            raw_procs = get_running_processes()
            analyzed = analyze_processes(raw_procs)
            print(f"  {GREEN}[+] Procesos en memoria auditados: {len(analyzed)}{RESET}")

            lsass_data = audit_lsass_protection()
            unquoted_data = audit_unquoted_services()

            if opt == "3":
                threats = [p for p in analyzed if p["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM"]]
                print(f"\n  {RED}{BOLD}[!] PROCESOS CON COMPORTAMIENTO SOSPECHOSO ({len(threats)}):{RESET}")
                for t in threats[:12]:
                    print(f"   • [{t['risk_level']}] PID {t['pid']} | {t['name']} (Padre: {t['parent_name']})")
                    for r in t.get("reasons", []):
                        print(f"      -> {YELLOW}{r}{RESET}")
            else:
                for p in analyzed[:10]:
                    print(f"   • PID {p['pid']} | {p['name'][:25]} | Padre: {p['parent_name'][:20]}")

            if opt == "5" or input(f"\n  {YELLOW}¿Deseas exportar reportes y abrir el Dashboard HTML ahora? (s/n): {RESET}").strip().lower() == "s":
                j_out = export_json(lsass_data, unquoted_data, analyzed)
                c_out = export_csv(analyzed)
                h_out = generate_html_dashboard(lsass_data, unquoted_data, analyzed)
                print(f"\n  {GREEN}[+] Reporte JSON:{RESET} {j_out}")
                print(f"  {GREEN}[+] Reporte CSV:{RESET}  {c_out}")
                print(f"  {GREEN}[+] Dashboard:{RESET}    {h_out}")
                if os.name == 'nt':
                    os.system(f'start "" "{h_out}"')

            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

        elif opt == "2":
            print(f"\n  {CYAN}[*] Verificando protección criptográfica y aislamiento de LSASS...{RESET}")
            l_data = audit_lsass_protection()
            for l in l_data:
                color = GREEN if l["status"] == "SECURE" else RED
                print(f"   • {l['check']}: {color}{l['status']}{RESET} ({l['value']})")
                print(f"     -> {l['description']}")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

        elif opt == "4":
            print(f"\n  {CYAN}[*] Escaneando claves de servicios en busca de rutas sin entrecomillar...{RESET}")
            u_data = audit_unquoted_services()
            print(f"  {GREEN}[+] Servicios vulnerables detectados: {len(u_data)}{RESET}\n")
            for u in u_data[:15]:
                print(f"   • {RED}{u['service_name']}{RESET} -> {u['vulnerable_binary_path']}")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description=f"MemSentry v{VERSION} | Forense de Procesos en RAM & LSASS Guard")
    parser.add_argument("--all", action="store_true", help="Ejecutar triage completo en modo headless y exportar reportes")
    parser.add_argument("--html", type=str, help="Ruta de salida personalizada para el dashboard HTML")
    parser.add_argument("--json", type=str, help="Ruta de salida personalizada para el reporte JSON")
    args = parser.parse_args()

    if args.all or args.html or args.json:
        lsass_data = audit_lsass_protection()
        unquoted_data = audit_unquoted_services()
        raw_procs = get_running_processes()
        analyzed = analyze_processes(raw_procs)

        j_out = export_json(lsass_data, unquoted_data, analyzed, args.json)
        h_out = generate_html_dashboard(lsass_data, unquoted_data, analyzed, args.html)
        c_out = export_csv(analyzed)
        print(f"[+] MemSentry finalizado:")
        print(f"    Total procesos en memoria: {len(analyzed)}")
        print(f"    Servicios unquoted: {len(unquoted_data)}")
        print(f"    JSON: {j_out}")
        print(f"    CSV:  {c_out}")
        print(f"    HTML: {h_out}")
        return

    interactive_menu()

if __name__ == "__main__":
    main()
