#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BrowserSentry v3.0.0 - Framework Forense de Navegadores Web y Descargas
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
WinAudit-DFIR Suite | Licencia MIT
Zero Dependencias Externas (0-pip: 100% Python Standard Library)
"""

import os
import sys
import glob
import json
import csv
import sqlite3
import shutil
import tempfile
import datetime
import html
import re
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

# Firmas de extensiones y dominios peligrosos
HIGH_RISK_EXTS = [
    ".iso", ".vhd", ".img", ".exe", ".scr", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi", ".dll", ".reg"
]

MEDIUM_RISK_EXTS = [
    ".zip", ".rar", ".7z", ".tar", ".gz", ".docm", ".xlsm", ".pptm"
]

SUSPICIOUS_DOMAINS = [
    "duckdns.org", "ngrok-free.app", "ngrok.io", "serveo.net",
    "localtunnel.me", "trycloudflare.com", "cdn.discordapp.com/attachments",
    "anonfiles.com", "gofile.io", "transfer.sh", "tempmail", "10minutemail"
]

SUSPICIOUS_SEARCH_TERMS = [
    "mimikatz", "c2 framework", "cobalt strike", "reverse shell",
    "sqlmap", "keylogger", "payload", "exploit", "metasploit",
    "rat download", "wifi hack", "credential dumper", "bypass uac"
]

def webkit_to_datetime(ts):
    if not ts or ts <= 0:
        return None
    try:
        # Microseconds since 1601-01-01 UTC
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts)
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt
    except Exception:
        return None

def firefox_to_datetime(ts):
    if not ts or ts <= 0:
        return None
    try:
        # Microseconds since 1970-01-01 UTC
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=ts)
        return dt
    except Exception:
        return None

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""==============================================================================
   ____                                   _____             _              
  |  _ \                                 / ____|           | |             
  | |_) |_ __ _____      _____  ___ _ __| (___   ___ _ __ | |_ _ __ _   _ 
  |  _ <| '__/ _ \ \ /\ / / __|/ _ \ '__\___ \ / _ \ '_ \| __| '__| | | |
  | |_) | | | (_) \ V  V /\__ \  __/ |  ____) |  __/ | | | |_| |  | |_| |
  |____/|_|  \___/ \_/\_/ |___/\___|_| |_____/ \___|_| |_|\__|_|   \__, |
                                                                   |___/ 
=============================================================================="""
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print(f"  Framework Forense de Navegadores Web, Descargas y Extensiones | v{VERSION}")
    print(f"  Ecosistema Cru9 | Chrome, Edge, Brave & Firefox | Multi-Profile Triage")
    print(f"=============================================================================={RESET}\n")

# ==============================================================================
# DISCOVERY DE BASES DE DATOS DE NAVEGADORES
# ==============================================================================
def discover_browsers():
    local_app = os.environ.get('LOCALAPPDATA', '')
    app_data = os.environ.get('APPDATA', '')
    found = []

    targets = [
        ("Google Chrome", "Chromium", os.path.join(local_app, r"Google\Chrome\User Data")),
        ("Microsoft Edge", "Chromium", os.path.join(local_app, r"Microsoft\Edge\User Data")),
        ("Brave Browser", "Chromium", os.path.join(local_app, r"BraveSoftware\Brave-Browser\User Data")),
        ("Mozilla Firefox", "Firefox", os.path.join(app_data, r"Mozilla\Firefox\Profiles"))
    ]

    for browser_name, engine, base_path in targets:
        if not os.path.exists(base_path):
            continue

        if engine == "Chromium":
            # Perfiles típicos: Default, Profile 1, Profile 2...
            profiles = ["Default"]
            for p in os.listdir(base_path):
                if p.startswith("Profile ") and os.path.isdir(os.path.join(base_path, p)):
                    profiles.append(p)
                    
            for prof in profiles:
                hist_path = os.path.join(base_path, prof, "History")
                ext_path = os.path.join(base_path, prof, "Extensions")
                if os.path.exists(hist_path):
                    found.append({
                        "browser": browser_name,
                        "profile": prof,
                        "engine": "Chromium",
                        "history_db": hist_path,
                        "extensions_dir": ext_path if os.path.exists(ext_path) else None
                    })
        elif engine == "Firefox":
            for prof_dir in glob.glob(os.path.join(base_path, "*")):
                places_db = os.path.join(prof_dir, "places.sqlite")
                if os.path.exists(places_db):
                    found.append({
                        "browser": browser_name,
                        "profile": os.path.basename(prof_dir),
                        "engine": "Firefox",
                        "history_db": places_db,
                        "extensions_dir": os.path.join(prof_dir, "extensions")
                    })

    return found

# ==============================================================================
# EXTRACCIÓN FORENSE DE DESCARGAS
# ==============================================================================
def extract_downloads(browser_info):
    downloads = []
    db_path = browser_info["history_db"]
    engine = browser_info["engine"]

    # Copiar a temporal para evitar error de archivo bloqueado
    tmp_dir = tempfile.gettempdir()
    tmp_db = os.path.join(tmp_dir, f"bs_dl_{os.getpid()}_{hash(db_path)}.db")

    try:
        shutil.copy2(db_path, tmp_db)
        wal = f"{db_path}-wal"
        if os.path.exists(wal):
            try: shutil.copy2(wal, f"{tmp_db}-wal")
            except Exception: pass
            
        conn = sqlite3.connect(tmp_db)
        cur = conn.cursor()

        if engine == "Chromium":
            query = """
            SELECT d.target_path, d.total_bytes, d.start_time, d.state, c.url, d.referrer
            FROM downloads d
            LEFT JOIN downloads_url_chains c ON d.id = c.id
            ORDER BY d.start_time DESC
            """
            cur.execute(query)
            for r in cur.fetchall():
                target = r[0] or ""
                size = r[1] or 0
                ts = r[2]
                state = r[3]
                url = r[4] or ""
                ref = r[5] or ""
                
                dt = webkit_to_datetime(ts)
                filename = os.path.basename(target)
                ext = os.path.splitext(filename)[1].lower()
                
                # Evaluar riesgo
                risk = "CLEAN"
                reasons = []
                if ext in HIGH_RISK_EXTS:
                    risk = "CRITICAL"
                    reasons.append(f"Extensión altamente peligrosa / ejecutable: '{ext}'")
                elif ext in MEDIUM_RISK_EXTS:
                    risk = "MEDIUM"
                    reasons.append(f"Archivo comprimido / ofimática con macros: '{ext}'")

                for dom in SUSPICIOUS_DOMAINS:
                    if dom in url.lower() or dom in ref.lower():
                        risk = "CRITICAL" if risk != "CRITICAL" else risk
                        reasons.append(f"Descargado desde dominio o servicio sospechoso: '{dom}'")
                        break

                downloads.append({
                    "browser": browser_info["browser"],
                    "profile": browser_info["profile"],
                    "filename": filename,
                    "target_path": target,
                    "file_size": size,
                    "file_size_mb": round(size / (1024 * 1024), 2) if size else 0,
                    "download_time": dt.strftime('%Y-%m-%d %H:%M:%S') if dt else "Desconocido",
                    "raw_timestamp": dt.timestamp() if dt else 0,
                    "url": url,
                    "referrer": ref,
                    "state": "Completada" if state == 1 else "Interrumpida / En curso",
                    "risk_level": risk,
                    "reasons": reasons
                })
        conn.close()
    except Exception as e:
        pass
    finally:
        if os.path.exists(tmp_db):
            try: os.remove(tmp_db)
            except Exception: pass
        if os.path.exists(f"{tmp_db}-wal"):
            try: os.remove(f"{tmp_db}-wal")
            except Exception: pass

    return downloads

# ==============================================================================
# EXTRACCIÓN FORENSE DE HISTORIAL WEB & BÚSQUEDAS
# ==============================================================================
def extract_history(browser_info, limit=1000):
    history = []
    db_path = browser_info["history_db"]
    engine = browser_info["engine"]

    tmp_dir = tempfile.gettempdir()
    tmp_db = os.path.join(tmp_dir, f"bs_hi_{os.getpid()}_{hash(db_path)}.db")

    try:
        shutil.copy2(db_path, tmp_db)
        wal = f"{db_path}-wal"
        if os.path.exists(wal):
            try: shutil.copy2(wal, f"{tmp_db}-wal")
            except Exception: pass

        conn = sqlite3.connect(tmp_db)
        cur = conn.cursor()

        if engine == "Chromium":
            cur.execute("""
            SELECT url, title, visit_count, typed_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
            """, (limit,))

            for r in cur.fetchall():
                u = r[0] or ""
                t = r[1] or ""
                vc = r[2] or 1
                tc = r[3] or 0
                ts = r[4]
                dt = webkit_to_datetime(ts)

                # Heurística de búsqueda sospechosa
                risk = "CLEAN"
                reasons = []
                content_lower = f"{u} {t}".lower()

                for term in SUSPICIOUS_SEARCH_TERMS:
                    if term in content_lower:
                        risk = "HIGH"
                        reasons.append(f"Término de ataque o hacking detectado: '{term}'")
                        break

                for dom in SUSPICIOUS_DOMAINS:
                    if dom in u.lower():
                        risk = "CRITICAL"
                        reasons.append(f"Visita a túnel dinámico / hosting malicioso: '{dom}'")
                        break

                history.append({
                    "browser": browser_info["browser"],
                    "profile": browser_info["profile"],
                    "url": u,
                    "title": t,
                    "visit_count": vc,
                    "typed_count": tc,
                    "last_visit": dt.strftime('%Y-%m-%d %H:%M:%S') if dt else "Desconocido",
                    "raw_timestamp": dt.timestamp() if dt else 0,
                    "risk_level": risk,
                    "reasons": reasons
                })
        conn.close()
    except Exception:
        pass
    finally:
        if os.path.exists(tmp_db):
            try: os.remove(tmp_db)
            except Exception: pass
        if os.path.exists(f"{tmp_db}-wal"):
            try: os.remove(f"{tmp_db}-wal")
            except Exception: pass

    return history

# ==============================================================================
# AUDITORÍA DE EXTENSIONES INSTALADAS
# ==============================================================================
def extract_extensions(browser_info):
    extensions = []
    ext_dir = browser_info.get("extensions_dir")
    if not ext_dir or not os.path.exists(ext_dir):
        return extensions

    try:
        for ext_id in os.listdir(ext_dir):
            ext_path = os.path.join(ext_dir, ext_id)
            if not os.path.isdir(ext_path):
                continue

            # Buscar manifest.json en subcarpetas de version
            name = ext_id
            ver = "1.0"
            for v in os.listdir(ext_path):
                manifest_file = os.path.join(ext_path, v, "manifest.json")
                if os.path.exists(manifest_file):
                    try:
                        with open(manifest_file, "r", encoding="utf-8", errors="ignore") as mf:
                            m_data = json.load(mf)
                            raw_name = m_data.get("name", ext_id)
                            # Si es clave de localizacion __MSG_...
                            if raw_name.startswith("__MSG_"):
                                raw_name = ext_id
                            name = raw_name
                            ver = m_data.get("version", v)
                    except Exception:
                        pass
                    break

            extensions.append({
                "browser": browser_info["browser"],
                "profile": browser_info["profile"],
                "extension_id": ext_id,
                "name": name,
                "version": ver,
                "path": ext_path,
                "risk_level": "INFO"
            })
    except Exception:
        pass

    return extensions

# ==============================================================================
# EXPORTACIÓN JSON & CSV
# ==============================================================================
def export_json(downloads, history, extensions, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"BrowserSentry_Report_{ts}.json"
    else:
        output_path = Path(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "tool": "BrowserSentry",
                "version": VERSION,
                "author": AUTHOR,
                "timestamp": datetime.datetime.now().isoformat(),
                "total_downloads": len(downloads),
                "total_history": len(history),
                "total_extensions": len(extensions)
            },
            "downloads": downloads,
            "suspicious_history": [h for h in history if h.get("risk_level") != "CLEAN"],
            "extensions": extensions
        }, f, indent=2, ensure_ascii=False)
    return output_path

def export_csv(downloads, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"BrowserSentry_Downloads_{ts}.csv"
    else:
        output_path = Path(output_path)

    keys = ["browser", "profile", "risk_level", "download_time", "filename", "file_size_mb", "url", "reasons"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for d in downloads:
            row = {k: d.get(k, "") for k in keys}
            if isinstance(row["reasons"], list):
                row["reasons"] = " | ".join(row["reasons"])
            writer.writerow(row)
    return output_path

# ==============================================================================
# GENERADOR DASHBOARD HTML CYBERPUNK
# ==============================================================================
def generate_html_dashboard(downloads, history, extensions, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"BrowserSentry_Dashboard_{ts}.html"
    else:
        output_path = Path(output_path)

    crit_dl = sum(1 for d in downloads if d.get("risk_level") == "CRITICAL")
    med_dl = sum(1 for d in downloads if d.get("risk_level") == "MEDIUM")
    susp_hist = [h for h in history if h.get("risk_level") != "CLEAN"]

    # Generar filas de descargas
    dl_rows = []
    for d in downloads:
        risk = d.get("risk_level", "CLEAN")
        b_cls = {
            "CRITICAL": "badge-crit",
            "HIGH": "badge-high",
            "MEDIUM": "badge-med",
            "CLEAN": "badge-clean"
        }.get(risk, "badge-clean")

        reasons = d.get("reasons", [])
        if reasons:
            reasons_html = f'<span class="ioc-alert">⚠️ {" • ".join(html.escape(r) for r in reasons)}</span>'
        else:
            reasons_html = '<span class="ioc-ok">✓ Descarga habitual</span>'

        dl_rows.append(f"""
        <tr class="dl-row" data-risk="{risk}">
            <td><span class="badge {b_cls}">{risk}</span></td>
            <td><span class="ts-badge">{d.get('download_time')}</span></td>
            <td><span class="browser-pill">{html.escape(d.get('browser'))} ({html.escape(d.get('profile'))})</span></td>
            <td><strong style="color:#0f172a;">{html.escape(d.get('filename'))}</strong><br><small style="color:#64748b;">{d.get('file_size_mb')} MB</small></td>
            <td class="mono-url">{html.escape(d.get('url')[:130])}</td>
            <td>{reasons_html}</td>
        </tr>
        """)

    # Generar filas de historial sospechoso
    hist_rows = []
    for h_item in susp_hist:
        risk = h_item.get("risk_level", "CLEAN")
        b_cls = "badge-crit" if risk == "CRITICAL" else "badge-high"
        reasons = " • ".join(h_item.get("reasons", []))

        hist_rows.append(f"""
        <tr>
            <td><span class="badge {b_cls}">{risk}</span></td>
            <td><span class="ts-badge">{h_item.get('last_visit')}</span></td>
            <td><span class="browser-pill">{html.escape(h_item.get('browser'))}</span></td>
            <td><strong style="color:#0f172a;">{html.escape(h_item.get('title')[:70])}</strong></td>
            <td class="mono-url">{html.escape(h_item.get('url')[:130])}</td>
            <td><span class="ioc-alert">⚠️ {html.escape(reasons)}</span></td>
        </tr>
        """)

    # Generar tarjetas de extensiones
    ext_cards = []
    for ext in extensions:
        ext_cards.append(f"""
        <div class="ext-card">
            <div class="ext-browser">{html.escape(ext.get('browser'))} • {html.escape(ext.get('profile'))}</div>
            <div class="ext-name">{html.escape(ext.get('name'))}</div>
            <div class="ext-version">Versión: <strong>{html.escape(ext.get('version'))}</strong></div>
            <div class="ext-id">ID: {html.escape(ext.get('extension_id'))}</div>
        </div>
        """)

    metrics = [


        {"label": "Descargas Auditadas", "value": total_downloads, "icon": "📥"},


        {"label": "Descargas Críticas", "value": crit_count, "icon": "🚨"},


        {"label": "URLs en Historial", "value": total_history, "icon": "🌐"},


        {"label": "Extensiones Instaladas", "value": total_exts, "icon": "🧩"}


    ]


    headers = [


        "Riesgo", "Timestamp Descarga", "Navegador & Perfil", "Archivo / URL",


        "Ruta Local", "Diagnóstico Forense"


    ]


    try:


        import forensic_theme


    except ImportError:


        base_dir = Path(__file__).resolve().parent.parent


        if str(base_dir) not in sys.path:


            sys.path.insert(0, str(base_dir))


        import forensic_theme



    html_content = forensic_theme.render_homologated_dashboard(


        title="Forense de Navegadores Web & Descargas",


        sentry_id="8",


        sentry_name="BrowserSentry",


        sentry_icon="🌍",


        subtitle="Triage SQLite en Chrome, Edge, Brave, Opera y Firefox: descargas, historial y extensiones",


        metrics=metrics,


        table_headers=headers,


        table_rows_html="".join(dl_rows),


        risk_score=0 if crit_count == 0 else 70,


        back_url="../../index.html"


    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

# ==============================================================================
# MENU INTERACTIVO CLI
# ==============================================================================
def interactive_menu():
    browsers = discover_browsers()
    while True:
        show_banner()
        print(f"  {BOLD}{WHITE}NAVEGADORES DETECTADOS EN ESTE HOST:{RESET}")
        for b in browsers:
            print(f"   • {CYAN}{b['browser']}{RESET} ({b['profile']}) [{b['engine']}]")
        print()

        print(f"  {BOLD}{WHITE}MENU FORENSE DE NAVEGADORES WEB:{RESET}")
        print(f"  {CYAN}[1]{RESET} Triage Completo (Descargas + Historial Sospechoso + Extensiones)")
        print(f"  {CYAN}[2]{RESET} Auditoría Forense de Descargas (Detección de Payloads, ISOs y EXEs)")
        print(f"  {CYAN}[3]{RESET} Caza de Búsquedas Sospechosas y URLs C2 / Túneles Dinámicos")
        print(f"  {CYAN}[4]{RESET} Auditoría de Extensiones de Navegador Instaladas")
        print(f"  {CYAN}[5]{RESET} Generar Reportes Forenses (JSON, CSV y Dashboard HTML)")
        print(f"  {RED}[0]{RESET} Volver al Menú Principal de la Suite")
        print()

        opt = input(f"  {YELLOW}Selecciona una opción [0-5]: {RESET}").strip()
        if opt == "0":
            break
        elif opt in ["1", "2", "5"]:
            print(f"\n  {CYAN}[*] Extrayendo historial de descargas en todos los navegadores...{RESET}")
            all_downloads = []
            for b in browsers:
                all_downloads.extend(extract_downloads(b))
            print(f"  {GREEN}[+] Descargas procesadas: {len(all_downloads)}{RESET}")

            all_history = []
            all_extensions = []
            if opt in ["1", "5"]:
                print(f"  {CYAN}[*] Extrayendo historial web y extensiones...{RESET}")
                for b in browsers:
                    all_history.extend(extract_history(b))
                    all_extensions.extend(extract_extensions(b))
                print(f"  {GREEN}[+] URLs analizadas: {len(all_history)} | Extensiones: {len(all_extensions)}{RESET}")

            # Mostrar descargas críticas
            crit = [d for d in all_downloads if d.get("risk_level") in ["CRITICAL", "MEDIUM"]]
            if crit:
                print(f"\n  {RED}{BOLD}[!] DESCARGAS CON POTENCIAL RIESGO DE AMENAZA ({len(crit)}):{RESET}")
                for c in crit[:12]:
                    print(f"   • [{c['risk_level']}] {c['download_time']} | {c['filename']} ({c['file_size_mb']} MB)")
                    for r in c.get("reasons", []):
                        print(f"      -> {YELLOW}{r}{RESET}")

            if opt == "5" or input(f"\n  {YELLOW}¿Deseas generar los reportes y abrir el Dashboard HTML ahora? (s/n): {RESET}").strip().lower() == "s":
                if not all_history:
                    for b in browsers:
                        all_history.extend(extract_history(b))
                        all_extensions.extend(extract_extensions(b))
                j_out = export_json(all_downloads, all_history, all_extensions)
                c_out = export_csv(all_downloads)
                h_out = generate_html_dashboard(all_downloads, all_history, all_extensions)
                print(f"\n  {GREEN}[+] Reporte JSON:{RESET} {j_out}")
                print(f"  {GREEN}[+] Reporte CSV:{RESET}  {c_out}")
                print(f"  {GREEN}[+] Dashboard:{RESET}    {h_out}")
                if os.name == 'nt':
                    os.system(f'start "" "{h_out}"')

            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

        elif opt == "3":
            print(f"\n  {CYAN}[*] Inspeccionando historial web en busca de términos de ataque y túneles...{RESET}")
            all_history = []
            for b in browsers:
                all_history.extend(extract_history(b, limit=2000))
            susp = [h for h in all_history if h.get("risk_level") != "CLEAN"]
            print(f"  {GREEN}[+] Búsquedas sospechosas detectadas: {len(susp)}{RESET}\n")
            for s in susp[:15]:
                print(f"   • {s['last_visit']} | {s['title'][:50]} | {s['url'][:65]}")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

        elif opt == "4":
            print(f"\n  {CYAN}[*] Extrayendo extensiones instaladas...{RESET}")
            all_extensions = []
            for b in browsers:
                all_extensions.extend(extract_extensions(b))
            print(f"  {GREEN}[+] Extensiones encontradas: {len(all_extensions)}{RESET}\n")
            for ext in all_extensions:
                print(f"   • [{ext['browser']}] {ext['name']} (v{ext['version']})")
            input(f"\n  {CYAN}Presiona ENTER para continuar...{RESET}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description=f"BrowserSentry v{VERSION} | Forense de Navegadores y Descargas")
    parser.add_argument("--all", action="store_true", help="Ejecutar triage completo en modo headless y exportar reportes")
    parser.add_argument("--html", type=str, help="Ruta de salida personalizada para el dashboard HTML")
    parser.add_argument("--json", type=str, help="Ruta de salida personalizada para el reporte JSON")
    args = parser.parse_args()

    browsers = discover_browsers()
    if args.all or args.html or args.json:
        all_downloads = []
        all_history = []
        all_extensions = []
        for b in browsers:
            all_downloads.extend(extract_downloads(b))
            all_history.extend(extract_history(b))
            all_extensions.extend(extract_extensions(b))

        j_out = export_json(all_downloads, all_history, all_extensions, args.json)
        h_out = generate_html_dashboard(all_downloads, all_history, all_extensions, args.html)
        c_out = export_csv(all_downloads)
        print(f"[+] BrowserSentry finalizado:")
        print(f"    Total descargas: {len(all_downloads)}")
        print(f"    Total historial analizado: {len(all_history)}")
        print(f"    Total extensiones: {len(all_extensions)}")
        print(f"    JSON: {j_out}")
        print(f"    CSV:  {c_out}")
        print(f"    HTML: {h_out}")
        return

    interactive_menu()

if __name__ == "__main__":
    main()
