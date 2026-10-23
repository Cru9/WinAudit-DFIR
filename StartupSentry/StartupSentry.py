#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
========================================================================================
   STARTUPSENTRY v3.0.0 - FORENSIC AUTOSTART & TASK PERSISTENCE HUNTER
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
import html
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
            if filtro_categoria.lower() == "arranque":
                filtrados = [x for x in filtrados if str(x.get("Categoria", "")).lower() in ("autoarranque", "registrorun", "carpetainicio")]
            else:
                filtrados = [x for x in filtrados if str(x.get("Categoria", "")).lower() == filtro_categoria.lower()]

        tot_analizados = len(self.items)
        tot_sospechosos = len([x for x in self.items if x.get("Sospechoso")])
        tot_sin_firma = len([x for x in self.items if x.get("Firma") not in ("Valid", "N/A")])
        tot_criticos = len([x for x in self.items if x.get("Severidad") == "CRITICA"])
        tot_altos = len([x for x in self.items if x.get("Severidad") == "ALTA"])
        score = self.calculate_threat_score()

        score_color = GREEN if score < 25 else (YELLOW if score < 60 else RED)

        print(f"\n{CYAN}+---------------------------------------------------------------------------------------+{RESET}")
        print(f"{CYAN}|  {BOLD}{WHITE}STARTUPSENTRY v3.0.0 - METRICAS DE AMENAZAS EN ARRANQUE Y PERSISTENCIA{RESET}               {CYAN}|{RESET}")
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
                "version": "3.0.0",
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
        """Genera un Dashboard HTML interactivo con colores claros y diseño ejecutivo (0 CDNs)."""
        ts = self.scan_time.strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"StartupSentry_Dashboard_{ts}.html"

        tot_analizados = len(self.items)
        tot_sospechosos = len([x for x in self.items if x.get("Sospechoso")])
        tot_sin_firma = len([x for x in self.items if x.get("Firma") not in ("Valid", "N/A")])
        tot_criticos = len([x for x in self.items if x.get("Severidad") == "CRITICA"])
        tot_altos = len([x for x in self.items if x.get("Severidad") == "ALTA"])
        score = self.calculate_threat_score()

        if score >= 60:
            score_color = "#b91c1c"
            score_bg = "#fef2f2"
            score_border = "#fecaca"
        elif score >= 25:
            score_color = "#b45309"
            score_bg = "#fffbeb"
            score_border = "#fde68a"
        else:
            score_color = "#15803d"
            score_bg = "#f0fdf4"
            score_border = "#bbf7d0"

        # Filas de tabla HTML
        table_rows = []
        for r in self.items:
            sev = r.get("Severidad", "BAJA")
            badge_cls = {
                "CRITICA": "badge-crit",
                "ALTA": "badge-high",
                "MEDIA": "badge-med"
            }.get(sev, "badge-clean")

            sig_cls = "sig-valid" if r.get("Firma") == "Valid" else ("sig-na" if r.get("Firma") == "N/A" else "sig-invalid")
            
            motivo_txt = r.get("Motivo")
            if motivo_txt:
                motivo_cell = f'<span class="ioc-alert">⚠️ {html.escape(motivo_txt)}</span>'
            else:
                motivo_cell = '<span class="ioc-ok">✓ Parámetros legítimos</span>'

            row = f"""
            <tr class="startup-row" data-sospechoso="{str(r.get('Sospechoso', False)).lower()}" data-categoria="{r.get('Categoria', '')}">
                <td><span class="badge {badge_cls}">{sev}</span></td>
                <td><span class="cat-badge">{r.get('Categoria')}</span></td>
                <td>
                    <strong style="color:#0f172a;">{r.get('Nombre')}</strong>
                    <div style="font-size:0.75rem; color:#64748b; font-family:ui-monospace, monospace; min-width:380px; word-break:break-word; overflow-wrap:anywhere;">{html.escape(str(r.get('Comando', '')))}</div>
                </td>
                <td style="min-width:380px; word-break:break-word; overflow-wrap:anywhere; font-family:ui-monospace, monospace; font-size:0.8rem; color:#334155;">{r.get('Ruta')}</td>
                <td><span class="sig-badge {sig_cls}">{r.get('Firma')}</span></td>
                <td style="font-size:0.82rem; color:#475569;">{r.get('Firmante', '-')}</td>
                <td>{r.get('Intervalo')}</td>
                <td>{motivo_cell}</td>
            </tr>
            """
            table_rows.append(row)

        metrics = [


            {"label": "Puntos ASEP Auditados", "value": len(results), "icon": "🚀"},


            {"label": "Firmas Microsoft Válidas", "value": len([r for r in results if "Microsoft" in str(r.get("Firmante", ""))]), "icon": "🛡️"},


            {"label": "Binarios No Firmados", "value": len([r for r in results if "No firmada" in str(r.get("Firma", ""))]), "icon": "⚠️"},


            {"label": "Persistencias Críticas", "value": len(criticos), "icon": "🚨"}


        ]


        headers = [


            "Severidad", "Categoría ASEP", "Nombre & Comando", "Ruta de Archivo",


            "Firma Digital", "Firmante", "Disparador", "Diagnóstico Forense"


        ]


        try:


            import forensic_theme


        except ImportError:


            base_dir = Path(__file__).resolve().parent.parent


            if str(base_dir) not in sys.path:


                sys.path.insert(0, str(base_dir))


            import forensic_theme



        html_content = forensic_theme.render_homologated_dashboard(


            title="Triage de Persistencia en Arranque & ASEPs",


            sentry_id="5",


            sentry_name="StartupSentry",


            sentry_icon="🚀",


            subtitle="Inspección de claves Run/RunOnce, tareas programadas, servicios y validación Authenticode",


            metrics=metrics,


            table_headers=headers,


            table_rows_html="".join(table_rows),


            risk_score=self.threat_score,


            back_url="../../index.html"


        )
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
        print(f"{CYAN}|   {BOLD}{WHITE}STARTUPSENTRY v3.0.0 - FORENSIC AUTOSTART & TASK PERSISTENCE HUNTER{RESET}                 {CYAN}|{RESET}")
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
                print(f"\n{CYAN}[*] Recopilando datos de auto-arranque, registro y carpetas Startup...{RESET}")
                sentry.run_ps_audit()
            sentry.print_summary(filtro_categoria="arranque")
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
                print(f"\n{CYAN}[*] Ejecutando análisis antes de generar reporte...{RESET}")
                sentry.run_ps_audit()
            dash = sentry.generate_html_dashboard()
            print(f"\n{GREEN}[✓] Reporte generado con éxito en disco:{RESET} {dash}")
            print(f"  {GRAY}[i] Guardado para preservación pericial (modo consola activo).{RESET}")
            input(f"  {GRAY}Presione Enter para continuar...{RESET}")

        elif opt == "6":
            if not sentry.items:
                print(f"\n{CYAN}[*] Ejecutando análisis antes de exportar evidencias...{RESET}")
                sentry.run_ps_audit()
            j = sentry.export_json()
            c = sentry.export_csv()
            print(f"\n{GREEN}[✓] Evidencia JSON exportada:{RESET} {j}")
        elif opt == "0":
            print(f"\n{CYAN}[*] Finalizando StartupSentry. Hasta la próxima investigación forense.{RESET}\n")
            sys.exit(0)


def main():
    if len(sys.argv) > 1:
        sentry = StartupSentry()
        sentry.run_ps_audit()
        export_all = "--all" in sys.argv
        if export_all or "--json" in sys.argv:
            jp = sentry.export_json()
            print(f"[+] JSON: {jp}")
        if export_all or "--csv" in sys.argv:
            cp = sentry.export_csv()
            print(f"[+] CSV: {cp}")
        if export_all or "--html" in sys.argv:
            hp = sentry.generate_html_dashboard()
            print(f"[+] HTML: {hp}")
        print(f"[+] StartupSentry completado: {len(sentry.items)} persistencias analizadas.")
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
