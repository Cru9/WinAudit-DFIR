#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DnsSentry v3.0.0 - Framework Forense de Caché DNS y Manipulación de Hosts en Windows
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
WinAudit-DFIR Suite | Licencia MIT
Zero Dependencias Externas (0-pip: 100% Python Standard Library)
"""

import os
import sys
import re
import math
import json
import csv
import hashlib
import datetime
import html
import subprocess
import platform
from pathlib import Path

# Activar secuencias de escape ANSI en consola Windows
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

DYNAMIC_DNS_DOMAINS = [
    "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net",
    "localtunnel.me", "pagekite.me", "portmap.io", "hopto.org", "no-ip.org",
    "no-ip.com", "ddns.net", "zapto.org", "sytes.net", "myftp.org", "bounceme.net",
    "freeddns.org", "dynu.net", "dynu.com", "mooo.com"
]

SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
    ".work", ".icu", ".cam", ".kim", ".monster", ".rest", ".fit"
]

SECURITY_SINKHOLE_TARGETS = [
    "microsoft.com", "windowsupdate.com", "update.microsoft.com", "defender.microsoft.com",
    "virustotal.com", "kaspersky.com", "symantec.com", "bitdefender.com", "eset.com",
    "sophos.com", "malwarebytes.com", "crowdstrike.com", "sentinelone.com"
]

KNOWN_SAFE_DNS_SERVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220"
]

def shannon_entropy(data_str):
    if not data_str:
        return 0.0
    entropy = 0.0
    for x in set(data_str):
        p_x = float(data_str.count(x)) / len(data_str)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""==============================================================================
   _____              _____             _              
  |  __ \            / ____|           | |             
  | |  | |_ __  ___ | (___   ___ _ __ | |_ _ __ _   _ 
  | |  | | '_ \/ __| \___ \ / _ \ '_ \| __| '__| | | |
  | |__| | | | \__ \ ____) |  __/ | | | |_| |  | |_| |
  |_____/|_| |_|___/|_____/ \___|_| |_|\__|_|   \__, |
                                                 |___/ 
=============================================================================="""
    admin_tag = f"{GREEN}[ADMINISTRADOR]{RESET}" if is_admin() else f"{YELLOW}[USUARIO ESTANDAR]{RESET}"
    print(f"{CYAN}{BOLD}{banner}{MAGENTA}")
    print(f"  Framework Forense de Caché DNS y Manipulación de Hosts | v{VERSION}")
    print(f"  Ecosistema Cru9 | DNS Spoofing, DGA, Túneles C2 & Sinkholes | Estado: {admin_tag}")
    print(f"=============================================================================={RESET}\n")

def audit_hosts_file():
    hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    findings = {
        "exists": hosts_path.exists(),
        "path": str(hosts_path),
        "sha256": "N/A",
        "last_modified": "N/A",
        "entries": [],
        "suspicious_entries": []
    }
    
    if not hosts_path.exists():
        return findings

    try:
        raw_bytes = hosts_path.read_bytes()
        findings["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
        mtime = datetime.datetime.fromtimestamp(hosts_path.stat().st_mtime)
        findings["last_modified"] = mtime.strftime('%Y-%m-%d %H:%M:%S')

        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                
                parts = re.split(r"\s+", clean)
                if len(parts) >= 2:
                    ip = parts[0]
                    domains = parts[1:]
                    for dom in domains:
                        entry = {
                            "line": line_no,
                            "ip": ip,
                            "domain": dom,
                            "is_loopback": ip in ["127.0.0.1", "0.0.0.0", "::1"],
                            "risk": "CLEAN",
                            "reasons": []
                        }

                        dom_lower = dom.lower()
                        if entry["is_loopback"] and any(sec in dom_lower for sec in SECURITY_SINKHOLE_TARGETS):
                            entry["risk"] = "CRITICAL"
                            entry["reasons"].append("Anti-Forensics / Evasión: Bloqueo de telemetría de seguridad o antivirus (Sinkhole T1562.001)")
                        elif not entry["is_loopback"] and any(sec in dom_lower for sec in ["google.com", "microsoft.com", "bank", "banco", "paypal", "github"]):
                            entry["risk"] = "CRITICAL"
                            entry["reasons"].append("Pharming / DNS Hijacking: Redirección maliciosa de dominio sensible hacia IP externa (T1566)")
                        elif entry["domain"] not in ["localhost", "localhost.localdomain", "broadcasthost"]:
                            entry["risk"] = "MEDIUM"
                            entry["reasons"].append("Modificación personalizada del archivo Hosts (T1565.001)")

                        findings["entries"].append(entry)
                        if entry["risk"] in ["CRITICAL", "HIGH", "MEDIUM"]:
                            findings["suspicious_entries"].append(entry)

    except Exception as e:
        findings["error"] = str(e)

    return findings

def audit_dns_adapters():
    """Audita los servidores DNS configurados en cada interfaz de red."""
    adapters = []
    ps_cmd = "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses | ConvertTo-Json -Compress"
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout.strip())
            if isinstance(raw, dict):
                raw = [raw]
            for it in raw:
                alias = it.get("InterfaceAlias", "Unknown")
                servers = it.get("ServerAddresses", [])
                if isinstance(servers, str):
                    servers = [servers]
                for s in servers:
                    is_private = s.startswith("192.168.") or s.startswith("10.") or s.startswith("172.") or s == "127.0.0.1"
                    is_known = s in KNOWN_SAFE_DNS_SERVERS
                    risk = "CLEAN" if (is_private or is_known) else "MEDIUM"
                    adapters.append({
                        "interface": alias,
                        "server": s,
                        "is_private_gateway": is_private,
                        "is_known_resolver": is_known,
                        "risk": risk
                    })
    except Exception:
        pass
    return adapters

def get_dns_client_cache():
    entries = []
    
    ps_cmd = "Get-DnsClientCache | Select-Object Entry, Type, Status, Section, TimeToLive, Data | ConvertTo-Json -Compress"
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        if proc.returncode == 0 and proc.stdout.strip():
            raw_json = proc.stdout.strip()
            data = json.loads(raw_json)
            if isinstance(data, dict):
                data = [data]
            for it in data:
                entry_name = str(it.get("Entry", "")).rstrip(".")
                if not entry_name:
                    continue
                entries.append({
                    "domain": entry_name,
                    "type": str(it.get("Type", "1")),
                    "ttl": it.get("TimeToLive", 0),
                    "data": str(it.get("Data", "")),
                    "status": str(it.get("Status", "Success")),
                    "source": "Get-DnsClientCache"
                })
    except Exception:
        pass

    if not entries:
        try:
            res = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, encoding="cp1252", errors="replace", timeout=10)
            cur_entry = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if "Record Name" in line or "Nombre de registro" in line:
                    if cur_entry and cur_entry.get("domain"):
                        entries.append(cur_entry)
                    cur_entry = {
                        "domain": line.split(":")[-1].strip().rstrip("."),
                        "type": "A",
                        "ttl": 0,
                        "data": "",
                        "status": "Success",
                        "source": "ipconfig"
                    }
                elif "Time To Live" in line or "Tiempo de vida" in line:
                    try:
                        cur_entry["ttl"] = int(re.search(r"\d+", line).group(0))
                    except Exception:
                        pass
                elif "A (IPv4)" in line or "AAAA" in line or "CNAME" in line:
                    cur_entry["data"] = line.split(":")[-1].strip()
            if cur_entry and cur_entry.get("domain"):
                entries.append(cur_entry)
        except Exception:
            pass

    return entries

def evaluate_dns_entry(item):
    dom = item.get("domain", "").lower()
    score = 0
    reasons = []

    for dd in DYNAMIC_DNS_DOMAINS:
        if dom.endswith(dd) or dd in dom:
            score += 85
            reasons.append(f"C2 Tunnel / Dynamic DNS detectado: '{dd}' (T1071.004)")
            break

    if dom.endswith(".onion") or "torproject" in dom:
        score += 90
        reasons.append("Tráfico o resolución de red Onion / Tor (T1090.003)")

    for tld in SUSPICIOUS_TLDS:
        if dom.endswith(tld):
            score += 45
            reasons.append(f"TLD sospechoso de alta tasa de malware: '{tld}'")
            break

    subparts = dom.split(".")
    first_label = subparts[0] if subparts else ""
    if len(first_label) > 42:
        score += 80
        reasons.append("DNS Tunneling / Data Exfiltration: Longitud anómala de etiqueta > 42 caracteres (T1071.004)")

    if len(subparts) >= 5:
        score += 35
        reasons.append(f"Profundidad excesiva de subdominios ({len(subparts)} niveles)")

    label_entropy = shannon_entropy(first_label)
    item["entropy"] = label_entropy
    if len(first_label) >= 12 and label_entropy >= 3.75:
        score += 65
        reasons.append(f"DGA sospechoso: Alta entropía aleatoria en dominio ({label_entropy})")

    ttl = item.get("ttl", 100)
    if isinstance(ttl, int) and 0 < ttl <= 15:
        reasons.append(f"Fast-Flux Indicator: TTL ultra-corto ({ttl}s)")
        score += 20

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

def run_dns_audit():
    hosts_info = audit_hosts_file()
    adapters_info = audit_dns_adapters()
    raw_cache = get_dns_client_cache()
    
    analyzed_cache = []
    seen = set()
    for it in raw_cache:
        dom = it.get("domain")
        if not dom or dom in seen:
            continue
        seen.add(dom)
        analyzed_cache.append(evaluate_dns_entry(it))

    analyzed_cache.sort(key=lambda x: x["risk_score"], reverse=True)
    return hosts_info, adapters_info, analyzed_cache

def export_json(hosts_info, adapters_info, cache_entries, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"DnsSentry_Report_{ts}.json"
    else:
        output_path = Path(output_path)
        
    crit_count = sum(1 for e in cache_entries if e["risk_level"] == "CRITICAL")
    high_count = sum(1 for e in cache_entries if e["risk_level"] == "HIGH")
    
    payload = {
        "metadata": {
            "tool": "DnsSentry",
            "version": VERSION,
            "author": AUTHOR,
            "ecosystem": ECOSYSTEM,
            "hostname": os.environ.get("COMPUTERNAME", platform.node()),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_cache_entries": len(cache_entries),
            "critical_threats": crit_count,
            "high_threats": high_count,
            "hosts_file_sha256": hosts_info.get("sha256"),
            "hosts_suspicious_entries": len(hosts_info.get("suspicious_entries", []))
        },
        "hosts_audit": hosts_info,
        "dns_adapters": adapters_info,
        "dns_cache": cache_entries
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return output_path

def export_csv(cache_entries, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"DnsSentry_Cache_{ts}.csv"
    else:
        output_path = Path(output_path)
        
    keys = ["domain", "risk_level", "risk_score", "ttl", "data", "entropy", "reasons"]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in cache_entries:
            row = {k: item.get(k, "") for k in keys}
            if isinstance(row["reasons"], list):
                row["reasons"] = "; ".join(row["reasons"])
            writer.writerow(row)
    return output_path

def generate_html_dashboard(hosts_info, adapters_info, cache_entries, output_path=None):
    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"DnsSentry_Dashboard_{ts}.html"
    else:
        output_path = Path(output_path)
        
    crit_count = sum(1 for e in cache_entries if e["risk_level"] == "CRITICAL")
    high_count = sum(1 for e in cache_entries if e["risk_level"] == "HIGH")
    med_count = sum(1 for e in cache_entries if e["risk_level"] == "MEDIUM")
    clean_count = sum(1 for e in cache_entries if e["risk_level"] == "CLEAN")
    hosts_tamper_count = len(hosts_info.get("suspicious_entries", []))
    
    dns_rows = []
    for item in cache_entries:
        risk = item.get("risk_level", "CLEAN")
        b_cls = {
            "CRITICAL": "badge-crit",
            "HIGH": "badge-high",
            "MEDIUM": "badge-med",
            "LOW": "badge-low"
        }.get(risk, "badge-clean")
        
        reasons = item.get("reasons", [])
        if reasons:
            reasons_html = f'<span class="ioc-alert">⚠️ {" • ".join(html.escape(r) for r in reasons)}</span>'
        else:
            reasons_html = '<span class="ioc-ok">✓ Resolución habitual</span>'
            
        dns_rows.append(f"""
        <tr class="dns-row">
            <td><strong style="color:#0f172a;">{html.escape(item.get('domain', ''))}</strong></td>
            <td><span class="badge {b_cls}">{risk}</span></td>
            <td><span class="score-pill">{item.get('risk_score', 0)}</span></td>
            <td><code class="mono-code">{html.escape(str(item.get('data', '')))}</code></td>
            <td>{item.get('ttl', 0)}s</td>
            <td><strong>{item.get('entropy', 0.0)}</strong></td>
            <td>{reasons_html}</td>
        </tr>
        """)
        
    hosts_rows = []
    for h in hosts_info.get("entries", []):
        r_cls = "badge-crit" if h["risk"] == "CRITICAL" else ("badge-med" if h["risk"] == "MEDIUM" else "badge-clean")
        r_txt = "; ".join(h.get("reasons", [])) or "Predeterminado"
        hosts_rows.append(f"""
        <tr>
            <td><span class="line-badge">Línea {h.get('line')}</span></td>
            <td><code class="mono-code">{html.escape(h.get('ip', ''))}</code></td>
            <td><strong style="color:#0f172a;">{html.escape(h.get('domain', ''))}</strong></td>
            <td><span class="badge {r_cls}">{h.get('risk')}</span></td>
            <td>{html.escape(r_txt)}</td>
        </tr>
        """)

    adapters_rows = []
    for ad in adapters_info:
        r_cls = "badge-clean" if ad["risk"] == "CLEAN" else "badge-med"
        adapters_rows.append(f"""
        <tr>
            <td><strong style="color:#0f172a;">{html.escape(ad.get('interface'))}</strong></td>
            <td><code class="mono-code">{html.escape(ad.get('server'))}</code></td>
            <td>{'Puerta de enlace local' if ad.get('is_private_gateway') else ('Resolver público conocido' if ad.get('is_known_resolver') else 'Servidor externo personalizado')}</td>
            <td><span class="badge {r_cls}">{ad.get('risk')}</span></td>
        </tr>
        """)

    metrics = [


        {"label": "Caché DNS en Vivo", "value": total_entries, "icon": "🌐"},


        {"label": "Alta Entropía (DGA)", "value": crit_count, "icon": "🎲"},


        {"label": "Integridad Archivo Hosts", "value": "LIMPIO" if hosts_tamper_count == 0 else "MANIPULADO", "icon": "✓"},


        {"label": "Resolvers DNS Seguros", "value": len(adapters_info), "icon": "🔒"}


    ]


    headers = [


        "Dominio / Host", "Riesgo", "Threat Score", "IP / Datos Resueltos",


        "TTL Restante", "Entropía Shannon", "Diagnóstico Forense"


    ]


    try:


        import forensic_theme


    except ImportError:


        base_dir = Path(__file__).resolve().parent.parent


        if str(base_dir) not in sys.path:


            sys.path.insert(0, str(base_dir))


        import forensic_theme



    html_content = forensic_theme.render_homologated_dashboard(


        title="Forense de Caché DNS & Manipulación de Hosts",


        sentry_id="4",


        sentry_name="DnsSentry",


        sentry_icon="🌐",


        subtitle="Extracción de caché DNS, entropía DGA, túneles C2 y verificación de integridad de Hosts",


        metrics=metrics,


        table_headers=headers,


        table_rows_html="".join(dns_rows),


        risk_score=0 if crit_count == 0 else 90,


        back_url="../../index.html"


    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

def main():
    if len(sys.argv) > 1:
        hosts_info, adapters_info, cache_entries = run_dns_audit()
        export_all = "--all" in sys.argv
        if export_all or "--json" in sys.argv:
            jp = export_json(hosts_info, adapters_info, cache_entries)
            print(f"[+] JSON: {jp}")
        if export_all or "--csv" in sys.argv:
            cp = export_csv(cache_entries)
            print(f"[+] CSV:  {cp}")
        if export_all or "--html" in sys.argv:
            hp = generate_html_dashboard(hosts_info, adapters_info, cache_entries)
            print(f"[+] HTML: {hp}")
        print(f"[+] DnsSentry completado: {len(cache_entries)} dominios en cache, {len(adapters_info)} servidores DNS y {len(hosts_info.get('entries', []))} registros hosts analizados.")
        return

    show_banner()
    print(f"  {CYAN}[*] Recolectando cache DNS en vivo y analizando archivo Hosts...{RESET}")
    hosts_info, adapters_info, cache_entries = run_dns_audit()
    print(f"  {GREEN}[+] Analisis completado: {len(cache_entries)} dominios resueltos.{RESET}\n")
    
    crit_count = sum(1 for e in cache_entries if e["risk_level"] == "CRITICAL")
    high_count = sum(1 for e in cache_entries if e["risk_level"] == "HIGH")
    tamper_count = len(hosts_info.get("suspicious_entries", []))

    print(f"  {BOLD}Resumen Pericial:{RESET}")
    print(f"    - Amenazas Criticas DNS: {RED if crit_count > 0 else GREEN}{crit_count}{RESET}")
    print(f"    - Alertas Altas DNS:     {YELLOW if high_count > 0 else GREEN}{high_count}{RESET}")
    print(f"    - Alteraciones Hosts:    {RED if tamper_count > 0 else GREEN}{tamper_count}{RESET}\n")

    jp = export_json(hosts_info, adapters_info, cache_entries)
    cp = export_csv(cache_entries)
    hp = generate_html_dashboard(hosts_info, adapters_info, cache_entries)

    print(f"  {GREEN}[+] JSON exportado:{RESET} {jp.name}")
    print(f"  {GREEN}[+] CSV exportado: {RESET} {cp.name}")
    print(f"  {GREEN}[+] Dashboard HTML:{RESET} {hp.name}\n")

    if os.name == 'nt' and "--no-open" not in sys.argv:
        os.system(f'start "" "{hp}"')

if __name__ == "__main__":
    main()
