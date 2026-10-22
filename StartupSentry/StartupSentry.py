#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
========================================================================================
   STARTUPSENTRY v1.2.1 - FORENSIC AUTOSTART & TASK PERSISTENCE HUNTER
   Framework de Detección de Persistencia, Tareas Programadas y Firmas Authenticode
   Ecosistema WinAudit-DFIR | Desarrollado por Cru9
========================================================================================
Capacidades Forenses:
  1. Triage exhaustivo de programas de inicio (Win32_StartupCommand y Registry Run Keys).
  2. Detección de tareas programadas en la raíz (\\) no-Microsoft e intervalos de recurrencia.
  3. Verificación criptográfica de firmas digitales Authenticode (Get-AuthenticodeSignature).
  4. Heurísticas avanzadas: detección de masquerading, rutas temporales y LOLBins.
  5. Exportación estructurada (JSON, CSV) y generación de Dashboard HTML Cyberpunk interactivo.
========================================================================================
"""

import os
import sys
import json
import csv
import subprocess
import datetime
import re
import platform
import webbrowser
from pathlib import Path
from typing import Dict, List, Any, Optional

# Directorios de ejecución y reportes
SCRIPT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SCRIPT_DIR / "Reportes"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Tokens de color ANSI para terminales compatibles
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
GRAY = "\033[90m"

class StartupSentry:
    """Motor central de Threat Hunting y triage forense de persistencia en Windows."""

    def __init__(self):
        self.hostname = platform.node()
        self.username = os.environ.get("USERNAME", "Unknown")
        self.os_version = f"{platform.system()} {platform.release()}"
        self.scan_time = datetime.datetime.now()
        self.items: List[Dict[str, Any]] = []
        self.ps_script_path = SCRIPT_DIR / "StartupSentry.ps1"

    def run_ps_audit(self) -> List[Dict[str, Any]]:
        """Invoca el motor PowerShell nativo para recopilar artefactos con firmas Authenticode."""
        if not self.ps_script_path.exists():
            print(f"{RED}[!] Error: No se encontró el motor nativo {self.ps_script_path.name}{RESET}")
            return []

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(self.ps_script_path),
            "-Json"
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=60)
            raw = proc.stdout.strip()
            if not raw:
                if proc.stderr:
                    print(f"{YELLOW}[!] Advertencia en PowerShell: {proc.stderr[:200]}{RESET}")
                return []

            data = json.loads(raw)
            if isinstance(data, dict):
                self.items = [data]
            elif isinstance(data, list):
                self.items = data
            else:
                self.items = []
        except Exception as e:
            print(f"{RED}[!] Error al ejecutar auditoría de persistencia: {e}{RESET}")
            self.items = []

        return self.items

    def calculate_threat_score(self) -> int:
        """Calcula el índice de riesgo global de persistencia (0 a 100)."""
        score = 0
        if not self.items:
            return 0

        for it in self.items:
            sev = str(it.get("Severidad", "")).upper()
            if sev == "CRITICA":
                score += 35
            elif sev == "ALTA":
                score += 20
            elif sev == "MEDIA":
                score += 10
            elif it.get("Sospechoso"):
                score += 5

        return min(score, 100)

    def print_summary(self, solo_sospechosos: bool = False, filtro_categoria: Optional[str] = None):
        """Imprime un resumen formateado de alta fidelidad en la terminal."""
        if not self.items:
            print(f"{YELLOW}[!] No hay datos recopilados. Ejecute primero el análisis.{RESET}")
            return

        filtrados = self.items
        if solo_sospechosos:
            filtrados = [x for x in filtrados if x.get("Sospechoso")]
        if filtro_categoria:
            filtrados = [x for x in filtrados if str(x.get("Categoria", "")).lower() == filtro_categoria.lower()]

        tot_analizados = len(self.items)
        tot_sospechosos = len([x for x in self.items if x.get("Sospechoso")])
        tot_sin_firma = len([x for x in self.items if x.get("Firma") not in ("Valid", "N/A")])
        tot_criticos = len([x for x in self.items if x.get("Severidad") == "CRITICA"])
        tot_altos = len([x for x in self.items if x.get("Severidad") == "ALTA"])
        score = self.calculate_threat_score()

        score_color = GREEN if score < 25 else (YELLOW if score < 60 else RED)

        print(f"\n{CYAN}+---------------------------------------------------------------------------------------+{RESET}")
        print(f"{CYAN}|  {BOLD}{WHITE}STARTUPSENTRY v1.2.1 - METRICAS DE AMENAZAS EN ARRANQUE Y PERSISTENCIA{RESET}               {CYAN}|{RESET}")
        print(f"{CYAN}+---------------------------------------------------------------------------------------+{RESET}")
        print(f"   {GRAY}Host:{WHITE} {self.hostname}  {GRAY}|  Usuario:{WHITE} {self.username}  {GRAY}|  Score de Riesgo: {score_color}{BOLD}{score}/100{RESET}")
        print(f"   {GRAY}Total Evaluados:    {WHITE}{tot_analizados:<5}{RESET}  {GRAY}|  Alertas Sospechosas: {RED if tot_sospechosos else GREEN}{tot_sospechosos:<5}{RESET}")
        print(f"   {GRAY}Sin Firma Válida:   {YELLOW if tot_sin_firma else GREEN}{tot_sin_firma:<5}{RESET}  {GRAY}|  Críticos: {RED}{tot_criticos:<3}{RESET}  {GRAY}|  Altos: {YELLOW}{tot_altos:<3}{RESET}")
        print(f"{CYAN}+---------------------------------------------------------------------------------------+{RESET}\n")

        print(f"{BLUE}.-[ DETALLE DE REGISTROS EVALUADOS ({len(filtrados)}) ]-------------------------------------------------.{RESET}")
        for r in filtrados:
            sev = r.get("Severidad", "BAJA")
            badge = f"{GREEN}[OK]{RESET}"
            color_nombre = CYAN
            if sev == "CRITICA":
                badge = f"{RED}[CRITICO]{RESET}"
                color_nombre = RED
            elif sev == "ALTA":
                badge = f"{YELLOW}[ALTO]{RESET}"
                color_nombre = YELLOW
            elif sev == "MEDIA":
                badge = f"{MAGENTA}[SOSPECHOSO]{RESET}"
                color_nombre = MAGENTA

            print(f"  {badge} {color_nombre}{r.get('Categoria')}: {r.get('Nombre')}{RESET}")
            print(f"       - Comando:    {GRAY}{r.get('Comando')}{RESET}")
            print(f"       - Ruta:       {GRAY}{r.get('Ruta')}{RESET}")
            sig_col = GREEN if r.get('Firma') == 'Valid' else (YELLOW if r.get('Firma') == 'N/A' else RED)
            print(f"       - Firma:      {sig_col}{r.get('Firma')}{RESET}  |  Firmante: {GRAY}{r.get('Firmante', '-')[:45]}{RESET}")
            print(f"       - Ubicación:  {GRAY}{r.get('Ubicacion')}  |  Intervalo: {r.get('Intervalo')}  |  Usuario: {r.get('Usuario')}{RESET}")
            if r.get("Motivo"):
                print(f"       - {YELLOW}ALERTA:{RESET}     {YELLOW}{r.get('Motivo')}{RESET}")
            print()
        print(f"{BLUE}'---------------------------------------------------------------------------------------'{RESET}\n")

    def export_json(self) -> Path:
        """Exporta los hallazgos en formato JSON estructurado."""
        ts = self.scan_time.strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"StartupSentry_Audit_{ts}.json"
        payload = {
            "metadata": {
                "tool": "StartupSentry",
                "version": "1.2.1",
                "author": "Cru9",
                "timestamp": self.scan_time.isoformat(),
                "hostname": self.hostname,
                "username": self.username,
                "os": self.os_version,
                "threat_score": self.calculate_threat_score()
            },
            "findings": self.items
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return out_path

    def export_csv(self) -> Path:
        """Exporta los hallazgos en formato CSV tabulado."""
        ts = self.scan_time.strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"StartupSentry_Audit_{ts}.csv"
        headers = ["Id", "Categoria", "Nombre", "Comando", "Ruta", "Firma", "Firmante", "Ubicacion", "Usuario", "Intervalo", "Sospechoso", "Severidad", "Motivo"]
        with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for it in self.items:
                writer.writerow(it)
        return out_path

    def generate_html_dashboard(self) -> Path:
        """Genera un Dashboard HTML interactivo Cyberpunk Glassmorphism con gráficos SVG y MITRE ATT&CK."""
        ts = self.scan_time.strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"StartupSentry_Dashboard_{ts}.html"

        tot_analizados = len(self.items)
        tot_sospechosos = len([x for x in self.items if x.get("Sospechoso")])
        tot_sin_firma = len([x for x in self.items if x.get("Firma") not in ("Valid", "N/A")])
        tot_firmados = len([x for x in self.items if x.get("Firma") == "Valid"])
        tot_criticos = len([x for x in self.items if x.get("Severidad") == "CRITICA"])
        tot_altos = len([x for x in self.items if x.get("Severidad") == "ALTA"])
        tot_tareas = len([x for x in self.items if x.get("Categoria") == "TareaProgramada"])
        score = self.calculate_threat_score()

        # Filas de tabla HTML
        table_rows = []
        for r in self.items:
            sev = r.get("Severidad", "BAJA")
            badge_cls = "badge-green"
            if sev == "CRITICA":
                badge_cls = "badge-red"
            elif sev == "ALTA":
                badge_cls = "badge-yellow"
            elif sev == "MEDIA":
                badge_cls = "badge-magenta"

            sig_cls = "sig-valid" if r.get("Firma") == "Valid" else ("sig-na" if r.get("Firma") == "N/A" else "sig-invalid")
            
            row = f"""
            <tr data-sospechoso="{str(r.get('Sospechoso', False)).lower()}" data-categoria="{r.get('Categoria', '')}" data-firma="{r.get('Firma', '')}">
                <td><span class="badge {badge_cls}">{sev}</span></td>
                <td><strong>{r.get('Categoria')}</strong></td>
                <td><div class="proc-name">{r.get('Nombre')}</div><div class="cmd-text">{r.get('Comando')}</div></td>
                <td><div class="path-text" title="{r.get('Ruta')}">{r.get('Ruta')}</div></td>
                <td><span class="sig-tag {sig_cls}">{r.get('Firma')}</span></td>
                <td><div class="signer-text" title="{r.get('Firmante')}">{r.get('Firmante', '-')}</div></td>
                <td>{r.get('Intervalo')}</td>
                <td><span class="motivo-tag {'has-alert' if r.get('Motivo') else ''}">{r.get('Motivo') if r.get('Motivo') else 'Parámetros legítimos'}</span></td>
            </tr>
            """
            table_rows.append(row)

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StartupSentry v1.2.1 | Forensic Autostart & Task Persistence Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700;800&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #07090e;
            --bg-panel: rgba(13, 17, 27, 0.82);
            --bg-card: rgba(20, 27, 45, 0.65);
            --border-glow: rgba(0, 240, 255, 0.28);
            --border-card: rgba(255, 255, 255, 0.08);
            --cyan: #00f0ff;
            --magenta: #ff0055;
            --yellow: #ffd000;
            --green: #00ff9d;
            --purple: #9d4edd;
            --text-main: #e2e8f0;
            --text-dim: #798ba3;
            --font-mono: 'JetBrains Mono', monospace;
            --font-display: 'Orbitron', sans-serif;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            background: radial-gradient(circle at 15% 15%, #0f172a 0%, var(--bg-base) 100%);
            color: var(--text-main);
            font-family: var(--font-mono);
            min-height: 100vh;
            padding: 2rem;
            position: relative;
            overflow-x: hidden;
        }}
        body::before {{
            content: "";
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
            background-size: 100% 3px, 6px 100%;
            pointer-events: none;
            z-index: 999;
        }}
        .container {{ max-width: 1440px; margin: 0 auto; }}
        header {{
            background: var(--bg-panel);
            backdrop-filter: blur(14px);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 1.8rem 2.2rem;
            margin-bottom: 2rem;
            box-shadow: 0 0 35px rgba(0, 240, 255, 0.08);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.5rem;
        }}
        .header-title h1 {{
            font-family: var(--font-display);
            font-size: 1.9rem;
            letter-spacing: 2px;
            background: linear-gradient(90deg, #ffffff, var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-dim); font-size: 0.85rem; margin-top: 0.4rem; }}
        .header-meta {{
            display: flex;
            gap: 1.5rem;
            font-size: 0.82rem;
            background: rgba(0,0,0,0.35);
            padding: 0.8rem 1.4rem;
            border-radius: 8px;
            border: 1px solid var(--border-card);
        }}
        .header-meta span strong {{ color: var(--cyan); }}
        
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.2rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1.4rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, border-color 0.2s;
        }}
        .kpi-card:hover {{ transform: translateY(-3px); border-color: var(--cyan); }}
        .kpi-card::before {{
            content: "";
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
            background: var(--cyan);
        }}
        .kpi-card.alert::before {{ background: var(--magenta); }}
        .kpi-card.warn::before {{ background: var(--yellow); }}
        .kpi-card.ok::before {{ background: var(--green); }}
        .kpi-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 1px; }}
        .kpi-val {{ font-family: var(--font-display); font-size: 2.2rem; margin: 0.4rem 0; font-weight: 700; }}
        .kpi-desc {{ font-size: 0.78rem; color: var(--text-dim); }}

        .dashboard-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 1024px) {{ .dashboard-grid {{ grid-template-columns: 1fr; }} }}

        .panel {{
            background: var(--bg-panel);
            backdrop-filter: blur(14px);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        .panel-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.2rem;
            padding-bottom: 0.8rem;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        .panel-header h3 {{
            font-family: var(--font-display);
            font-size: 1.1rem;
            color: var(--cyan);
            letter-spacing: 1px;
        }}

        /* MITRE ATT&CK Matrix */
        .mitre-list {{ display: flex; flex-direction: column; gap: 0.9rem; }}
        .mitre-card {{
            background: var(--bg-card);
            border-left: 3px solid var(--cyan);
            padding: 0.9rem 1.1rem;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.82rem;
        }}
        .mitre-card.red {{ border-left-color: var(--magenta); }}
        .mitre-card.yellow {{ border-left-color: var(--yellow); }}
        .mitre-id {{ font-weight: 700; color: #fff; }}
        .mitre-tactic {{ color: var(--text-dim); font-size: 0.74rem; }}

        /* Filter Controls */
        .filter-bar {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 1.2rem;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border-card);
            color: #fff;
            padding: 0.65rem 1rem;
            border-radius: 8px;
            font-family: var(--font-mono);
            font-size: 0.85rem;
        }}
        .search-box:focus {{ outline: none; border-color: var(--cyan); box-shadow: 0 0 10px rgba(0, 240, 255, 0.2); }}
        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            color: var(--text-main);
            padding: 0.6rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.8rem;
            font-family: var(--font-mono);
            transition: all 0.2s;
        }}
        .filter-btn.active, .filter-btn:hover {{
            background: rgba(0, 240, 255, 0.15);
            border-color: var(--cyan);
            color: var(--cyan);
        }}

        /* Table */
        .table-wrap {{
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--border-card);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
            text-align: left;
        }}
        th {{
            background: rgba(10, 14, 23, 0.95);
            color: var(--cyan);
            padding: 0.9rem 1rem;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-card);
            white-space: nowrap;
        }}
        td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            vertical-align: middle;
        }}
        tr:hover td {{ background: rgba(0, 240, 255, 0.03); }}
        .proc-name {{ font-weight: 600; color: #fff; margin-bottom: 0.2rem; }}
        .cmd-text {{ font-size: 0.72rem; color: var(--text-dim); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .path-text {{ font-size: 0.74rem; color: var(--text-dim); max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .signer-text {{ font-size: 0.74rem; color: var(--text-dim); max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            display: inline-block;
        }}
        .badge-green {{ background: rgba(0, 255, 157, 0.12); color: var(--green); border: 1px solid var(--green); }}
        .badge-yellow {{ background: rgba(255, 208, 0, 0.12); color: var(--yellow); border: 1px solid var(--yellow); }}
        .badge-red {{ background: rgba(255, 0, 85, 0.15); color: var(--magenta); border: 1px solid var(--magenta); }}
        .badge-magenta {{ background: rgba(157, 78, 221, 0.15); color: var(--purple); border: 1px solid var(--purple); }}

        .sig-tag {{
            font-size: 0.72rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        .sig-valid {{ color: var(--green); background: rgba(0, 255, 157, 0.08); }}
        .sig-invalid {{ color: var(--magenta); background: rgba(255, 0, 85, 0.1); }}
        .sig-na {{ color: var(--text-dim); background: rgba(255,255,255,0.05); }}

        .motivo-tag {{ font-size: 0.74rem; color: var(--text-dim); }}
        .motivo-tag.has-alert {{ color: var(--yellow); font-weight: 600; }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            font-size: 0.78rem;
            color: var(--text-dim);
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-card);
        }}
        footer a {{ color: var(--cyan); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>STARTUPSENTRY // FORENSIC DASHBOARD</h1>
                <p>Framework de Triage de Persistencia en Inicio, Tareas Programadas y Validación Authenticode</p>
            </div>
            <div class="header-meta">
                <span>HOST: <strong>{self.hostname}</strong></span>
                <span>USUARIO: <strong>{self.username}</strong></span>
                <span>OS: <strong>{self.os_version}</strong></span>
                <span>FECHA: <strong>{self.scan_time.strftime('%Y-%m-%d %H:%M')}</strong></span>
            </div>
        </header>

        <!-- KPI SUMMARY -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Persistencia Evaluada</div>
                <div class="kpi-val" style="color:var(--cyan);">{tot_analizados}</div>
                <div class="kpi-desc">Auto-Arranque + Tareas Raíz</div>
            </div>
            <div class="kpi-card {'ok' if tot_firmados > 0 else ''}">
                <div class="kpi-label">Firmas Authenticode Válidas</div>
                <div class="kpi-val" style="color:var(--green);">{tot_firmados}</div>
                <div class="kpi-desc">Certificados verificados</div>
            </div>
            <div class="kpi-card {'alert' if tot_sospechosos > 0 else 'ok'}">
                <div class="kpi-label">Alertas Sospechosas</div>
                <div class="kpi-val" style="color:{'var(--magenta)' if tot_sospechosos > 0 else 'var(--green)'};">{tot_sospechosos}</div>
                <div class="kpi-desc">Heurísticas anómalas activas</div>
            </div>
            <div class="kpi-card {'warn' if tot_sin_firma > 0 else 'ok'}">
                <div class="kpi-label">Sin Firma Válida</div>
                <div class="kpi-val" style="color:{'var(--yellow)' if tot_sin_firma > 0 else 'var(--green)'};">{tot_sin_firma}</div>
                <div class="kpi-desc">Binarios NotSigned / Corruptos</div>
            </div>
            <div class="kpi-card {'alert' if score >= 50 else ('warn' if score >= 20 else 'ok')}">
                <div class="kpi-label">Índice Global de Amenaza</div>
                <div class="kpi-val" style="color:{'var(--magenta)' if score >= 50 else ('var(--yellow)' if score >= 20 else 'var(--green)')};">{score}/100</div>
                <div class="kpi-desc">Nivel de Exposición de Host</div>
            </div>
        </div>

        <!-- MAIN DASHBOARD CONTENT -->
        <div class="dashboard-grid">
            <!-- MITRE ATT&CK MATRIX -->
            <div class="panel">
                <div class="panel-header">
                    <h3>// COBERTURA MITRE ATT&CK DEFENSIVA</h3>
                    <span style="font-size:0.75rem; color:var(--text-dim);">Tácticas de Persistencia & Evasión</span>
                </div>
                <div class="mitre-list">
                    <div class="mitre-card {'red' if tot_sospechosos > 0 else ''}">
                        <div>
                            <div class="mitre-id">T1547.001 - Registry Run Keys / Startup Folder</div>
                            <div class="mitre-tactic">Táctica: Persistencia | Detección de binarios residentes en claves Run y Startup de usuario/sistema</div>
                        </div>
                        <span class="badge {'badge-red' if tot_sospechosos > 0 else 'badge-green'}">{'Amenaza' if tot_sospechosos > 0 else 'Protegido'}</span>
                    </div>
                    <div class="mitre-card {'yellow' if tot_tareas > 0 else ''}">
                        <div>
                            <div class="mitre-id">T1053.005 - Scheduled Task/Job: Scheduled Task</div>
                            <div class="mitre-tactic">Táctica: Persistencia / Ejecución | Tareas en raíz (\\) con intervalos recurrentes de alta frecuencia</div>
                        </div>
                        <span class="badge {'badge-yellow' if tot_tareas > 0 else 'badge-green'}">{tot_tareas} Tareas</span>
                    </div>
                    <div class="mitre-card {'red' if tot_sin_firma > 0 else ''}">
                        <div>
                            <div class="mitre-id">T1553.002 - Subvert Trust Controls: Code Signing</div>
                            <div class="mitre-tactic">Táctica: Evasión de Defensa | Binarios sin firma digital Authenticode o con HashMismatch</div>
                        </div>
                        <span class="badge {'badge-red' if tot_sin_firma > 0 else 'badge-green'}">{'Auditar' if tot_sin_firma > 0 else 'Validado'}</span>
                    </div>
                    <div class="mitre-card">
                        <div>
                            <div class="mitre-id">T1036.005 - Masquerading: Match Legitimate Name</div>
                            <div class="mitre-tactic">Táctica: Evasión de Defensa | Procesos del sistema simulados ejecutados fuera de System32</div>
                        </div>
                        <span class="badge badge-green">Monitoreado</span>
                    </div>
                </div>
            </div>

            <!-- FORENSIC RECOMMENDATIONS -->
            <div class="panel">
                <div class="panel-header">
                    <h3>// GUÍA DE RESPUESTA A INCIDENTES</h3>
                </div>
                <div style="font-size:0.8rem; line-height:1.6; color:var(--text-main);">
                    <p style="margin-bottom:0.8rem;">
                        <strong style="color:var(--cyan);">1. Análisis de Firmas Authenticode:</strong> Los binarios marcados como <code>NotSigned</code> o <code>HashMismatch</code> en carpetas <code>AppData</code> o <code>Temp</code> deben someterse de inmediato a correlación en VirusTotal o sandbox estática.
                    </p>
                    <p style="margin-bottom:0.8rem;">
                        <strong style="color:var(--yellow);">2. Tareas de Alta Frecuencia:</strong> Tareas no-Microsoft que repitan su ejecución cada 5 a 30 minutos (ej. <code>PT5M</code>) suelen actuar como mecanismos de revinculación (Keep-Alive) o beacons de C2.
                    </p>
                    <p>
                        <strong style="color:var(--green);">3. Exportación de Evidencia:</strong> Adjunte los archivos CSV y JSON generados en este mismo reporte a su informe forense de cadena de custodia.
                    </p>
                </div>
            </div>
        </div>

        <!-- FULL FINDINGS TABLE -->
        <div class="panel">
            <div class="panel-header">
                <h3>// INVENTARIO FORENSE DE PERSISTENCIA Y FIRMAS</h3>
                <span style="font-size:0.75rem; color:var(--text-dim);">{len(self.items)} Entradas Registradas</span>
            </div>

            <div class="filter-bar">
                <input type="text" id="searchInput" class="search-box" placeholder="Buscar por nombre, comando, ruta o firmante...">
                <button class="filter-btn active" onclick="applyFilter('todos')">Todos ({len(self.items)})</button>
                <button class="filter-btn" onclick="applyFilter('alertas')">Solo Alertas ({tot_sospechosos})</button>
                <button class="filter-btn" onclick="applyFilter('sin_firma')">Sin Firma ({tot_sin_firma})</button>
                <button class="filter-btn" onclick="applyFilter('tareas')">Tareas ({tot_tareas})</button>
            </div>

            <div class="table-wrap">
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th>Severidad</th>
                            <th>Categoría</th>
                            <th>Elemento / Comando</th>
                            <th>Ruta Binaria</th>
                            <th>Authenticode</th>
                            <th>Firmante</th>
                            <th>Intervalo</th>
                            <th>Diagnóstico / Alerta</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(table_rows)}
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            Generado por <a href="https://github.com/Cru9/WinAudit-DFIR" target="_blank">WinAudit-DFIR Suite // StartupSentry v1.2.1</a> • Autor: Cru9 • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <script>
        function applyFilter(mode) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            const rows = document.querySelectorAll('#findingsTable tbody tr');
            const q = document.getElementById('searchInput').value.toLowerCase();

            rows.forEach(r => {{
                let show = true;
                const sospechoso = r.getAttribute('data-sospechoso') === 'true';
                const cat = (r.getAttribute('data-categoria') || '').toLowerCase();
                const firma = (r.getAttribute('data-firma') || '');

                if (mode === 'alertas' && !sospechoso) show = false;
                if (mode === 'sin_firma' && (firma === 'Valid' || firma === 'N/A')) show = false;
                if (mode === 'tareas' && !cat.includes('tarea')) show = false;

                if (q) {{
                    const text = r.innerText.toLowerCase();
                    if (!text.includes(q)) show = false;
                }}

                r.style.display = show ? '' : 'none';
            }});
        }}

        document.getElementById('searchInput').addEventListener('input', function() {{
            const q = this.value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            rows.forEach(r => {{
                const text = r.innerText.toLowerCase();
                r.style.display = text.includes(q) ? '' : 'none';
            }});
        }});
    </script>
</body>
</html>
        """

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return out_path


def interactive_menu():
    """Menú interactivo de línea de comandos para el analista forense."""
    sentry = StartupSentry()

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        score = sentry.calculate_threat_score() if sentry.items else 0
        score_badge = f"{GREEN}[RIESGO BAJO: {score}/100]{RESET}" if score < 25 else (f"{YELLOW}[RIESGO MEDIO: {score}/100]{RESET}" if score < 60 else f"{RED}[RIESGO CRITICO: {score}/100]{RESET}")

        print(f"{CYAN}+---------------------------------------------------------------------------------------+{RESET}")
        print(f"{CYAN}|   {BOLD}{WHITE}STARTUPSENTRY v1.2.1 - FORENSIC AUTOSTART & TASK PERSISTENCE HUNTER{RESET}                 {CYAN}|{RESET}")
        print(f"{CYAN}|   {GRAY}Ecosistema WinAudit-DFIR | Desarrollado por Cru9{RESET}                                    {CYAN}|{RESET}")
        print(f"{CYAN}+---------------------------------------------------------------------------------------+{RESET}")
        print(f"  {GRAY}[+] Host:{WHITE} {sentry.hostname}  {GRAY}|  Usuario:{WHITE} {sentry.username}  {GRAY}|  Registros:{WHITE} {len(sentry.items)}  {GRAY}|  {score_badge}")
        print(f"  ───────────────────────────────────────────────────────────────────────────────────────")
        print(f"  {BOLD}{WHITE}[1]{RESET}  {CYAN}🔍 Triage Completo de Persistencia (Arranque + Tareas + Firmas Authenticode){RESET}")
        print(f"  {BOLD}{WHITE}[2]{RESET}  {CYAN}⚡ Inspeccionar Programas de Auto-Arranque (Startup & Registry Run Keys){RESET}")
        print(f"  {BOLD}{WHITE}[3]{RESET}  {CYAN}⏱️  Inspeccionar Tareas Programadas Raíz (\\) y Repeticiones Críticas (<= 30 min){RESET}")
        print(f"  {BOLD}{WHITE}[4]{RESET}  {YELLOW}🎯 Filtrar Solo Elementos Sospechosos / Sin Firma Válida (Threat Hunting){RESET}")
        print(f"  {BOLD}{WHITE}[5]{RESET}  {MAGENTA}📊 Generar y Abrir Dashboard HTML Cyberpunk (Reporte Ejecutivo DFIR){RESET}")
        print(f"  {BOLD}{WHITE}[6]{RESET}  {GREEN}💾 Exportar Evidencias Multi-formato (JSON + CSV en /Reportes){RESET}")
        print(f"  {BOLD}{WHITE}[0]{RESET}  {RED}🚪 Salir de StartupSentry{RESET}")
        print(f"  ───────────────────────────────────────────────────────────────────────────────────────")

        opt = input(f"\n  {BOLD}{CYAN}Cru9@StartupSentry{WHITE} [{GREEN}PERSISTENCE-CONSOLE{WHITE}] {CYAN}>> {RESET}").strip()

        if opt == "1":
            print(f"\n{CYAN}[*] Iniciando auditoría forense de persistencia en Windows...{RESET}")
            sentry.run_ps_audit()
            sentry.print_summary()
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "2":
            if not sentry.items:
                print(f"\n{CYAN}[*] Recopilando datos de auto-arranque...{RESET}")
                sentry.run_ps_audit()
            sentry.print_summary(filtro_categoria="AutoArranque")
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "3":
            if not sentry.items:
                print(f"\n{CYAN}[*] Recopilando datos de tareas programadas...{RESET}")
                sentry.run_ps_audit()
            sentry.print_summary(filtro_categoria="TareaProgramada")
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "4":
            if not sentry.items:
                print(f"\n{CYAN}[*] Ejecutando análisis para filtrado de amenazas...{RESET}")
                sentry.run_ps_audit()
            sentry.print_summary(solo_sospechosos=True)
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "5":
            if not sentry.items:
                print(f"\n{CYAN}[*] Ejecutando análisis antes de generar dashboard...{RESET}")
                sentry.run_ps_audit()
            dash = sentry.generate_html_dashboard()
            print(f"\n{GREEN}[✓] Dashboard generado con éxito:{RESET} {dash}")
            try:
                webbrowser.open(dash.as_uri())
            except Exception:
                pass
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "6":
            if not sentry.items:
                print(f"\n{CYAN}[*] Ejecutando análisis antes de exportar evidencias...{RESET}")
                sentry.run_ps_audit()
            j = sentry.export_json()
            c = sentry.export_csv()
            print(f"\n{GREEN}[✓] Evidencia JSON exportada:{RESET} {j}")
            print(f"{GREEN}[✓] Evidencia CSV exportada:{RESET}  {c}")
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "0":
            print(f"\n{CYAN}[*] Finalizando StartupSentry. Hasta la próxima investigación forense.{RESET}\n")
            sys.exit(0)


if __name__ == "__main__":
    interactive_menu()
