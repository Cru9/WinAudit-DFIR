#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
UsbSentry v2.0.0 - Framework Forense de Dispositivos USB y BadUSB Hunter
Ecosistema Cru9 | WinAudit-DFIR Suite
==============================================================================
Inspecciona y correlaciona artefactos forenses de almacenamiento USB en Windows:
- Historial de dispositivos USB conectados (USBSTOR)
- Mapeo de letras de unidad históricas (MountedDevices)
- Discos USB actualmente conectados en vivo (Win32_DiskDrive)
- Caza de dispositivos de inyección de pulsaciones BadUSB / HID (Rubber Ducky, Flipper Zero)
- Marcas temporales de conexión (LastWriteTime del registro)
- Generación de reportes forenses en JSON, CSV y Dashboards HTML Cyberpunk
==============================================================================
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

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import winreg
except ImportError:
    winreg = None

VERSION = "2.0.0"
AUTHOR = "Cru9"
TOOL_NAME = "UsbSentry"

# Base de datos de firmas de hardware BadUSB y emuladores conocidos
BADUSB_SIGNATURES = {
    "0483:5740": {"nombre": "Flipper Zero / ST VCP Virtual COM", "riesgo": "CRITICO", "score": 95},
    "1FC9:0003": {"nombre": "Hak5 USB Rubber Ducky (NXP)", "riesgo": "CRITICO", "score": 100},
    "0483:0003": {"nombre": "Hak5 Rubber Ducky Generic Clone", "riesgo": "CRITICO", "score": 95},
    "F000:FFF0": {"nombre": "Hak5 Bash Bunny Multi-Payload", "riesgo": "CRITICO", "score": 100},
    "2341:8036": {"nombre": "Arduino Leonardo (BadUSB HID Keyboard)", "riesgo": "CRITICO", "score": 90},
    "2341:0036": {"nombre": "Arduino Micro (BadUSB HID Keyboard)", "riesgo": "CRITICO", "score": 90},
    "2E8A:0003": {"nombre": "Raspberry Pi Pico (CircuitPython BadUSB HID)", "riesgo": "CRITICO", "score": 90},
    "16C0:0478": {"nombre": "Teensyduino / PJRC RawHID", "riesgo": "ALTO", "score": 80},
}


class UsbForensicCollector:
    """Recolector forense de bajo nivel de almacenamiento y dispositivos USB en Windows."""

    def __init__(self):
        self.script_dir = Path(__file__).resolve().parent
        self.report_dir = self.script_dir / "Reportes"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.drive_mappings: Dict[str, str] = {}
        self.live_drives: Dict[str, Dict[str, Any]] = {}
        self.devices: List[Dict[str, Any]] = []

    def get_drive_mappings(self) -> Dict[str, str]:
        """Extrae la asignación histórica de letras de unidad desde HKLM\\SYSTEM\\MountedDevices."""
        mappings = {}
        if not winreg:
            return mappings
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    val_name, val_data, val_type = winreg.EnumValue(key, i)
                    if val_name.startswith(r"\DosDevices\\"):
                        drive_letter = val_name.replace(r"\DosDevices\\", "")
                        try:
                            decoded = val_data.decode("utf-16le", errors="ignore")
                            mappings[drive_letter] = decoded
                        except Exception:
                            pass
        except Exception:
            pass
        self.drive_mappings = mappings
        return mappings

    def detect_live_usb_drives(self) -> Dict[str, Dict[str, Any]]:
        """Detecta dispositivos de disco USB conectados actualmente mediante WMI/PowerShell."""
        live = {}
        ps_cmd = (
            "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | "
            "Select-Object Model, DeviceID, Size, SerialNumber | ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="ignore"
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    ser = re.sub(r"[^\w\-&]", "", str(item.get("SerialNumber", "")).strip())
                    size_bytes = item.get("Size") or 0
                    size_gb = round(size_bytes / (1024**3), 2) if size_bytes else 0
                    if ser:
                        live[ser] = {
                            "model": item.get("Model", "USB Drive"),
                            "size_gb": size_gb,
                            "device_id": item.get("DeviceID", "")
                        }
        except Exception:
            pass
        self.live_drives = live
        return live

    def collect_usbstor_history(self) -> List[Dict[str, Any]]:
        """Inspecciona HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR y correlaciona con letras de unidad y timestamps."""
        devices = []
        if not winreg:
            return devices

        try:
            usbstor_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        except FileNotFoundError:
            return devices
        except Exception:
            return devices

        num_subkeys = winreg.QueryInfoKey(usbstor_key)[0]
        for i in range(num_subkeys):
            device_type = winreg.EnumKey(usbstor_key, i)
            # Parsear Vendor, Product y Rev
            ven = "Desconocido"
            prod = "Dispositivo de Almacenamiento"
            rev = ""

            m_ven = re.search(r"Ven_([^&]+)", device_type, re.IGNORECASE)
            if m_ven:
                ven = m_ven.group(1).replace("_", " ").strip()
            m_prod = re.search(r"Prod_([^&]+)", device_type, re.IGNORECASE)
            if m_prod:
                prod = m_prod.group(1).replace("_", " ").strip()
            m_rev = re.search(r"Rev_([^\\]+)", device_type, re.IGNORECASE)
            if m_rev:
                rev = m_rev.group(1).strip()

            try:
                dev_key = winreg.OpenKey(usbstor_key, device_type)
            except Exception:
                continue

            num_instances = winreg.QueryInfoKey(dev_key)[0]
            for j in range(num_instances):
                serial_instance = winreg.EnumKey(dev_key, j)
                try:
                    inst_key = winreg.OpenKey(dev_key, serial_instance)
                    _, _, last_write_time = winreg.QueryInfoKey(inst_key)
                    # Convertir FILETIME (100-nanosecond intervals since 1601-01-01)
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_write_time // 10)
                    last_conn_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_conn_str = "No disponible"
                    dt = datetime.datetime.min

                # FriendlyName
                friendly = ""
                try:
                    friendly, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                except Exception:
                    friendly = f"{ven} {prod}"

                # HardwareID
                hwid = ""
                try:
                    val, _ = winreg.QueryValueEx(inst_key, "HardwareID")
                    hwid = "; ".join(val) if isinstance(val, list) else str(val)
                except Exception:
                    pass

                # Mapear letra de unidad
                assigned_drive = "N/A"
                for letter, raw_str in self.drive_mappings.items():
                    if serial_instance.lower() in raw_str.lower() or device_type.lower() in raw_str.lower():
                        assigned_drive = letter
                        break

                # Comprobar si está conectado en vivo
                is_live = False
                live_cap = "N/A"
                for live_ser, info in self.live_drives.items():
                    if live_ser.lower() in serial_instance.lower() or serial_instance.lower() in live_ser.lower():
                        is_live = True
                        live_cap = f"{info['size_gb']} GB"
                        break

                # Heurística y Threat Score
                threat_score = 15
                alerts = []

                # Serial genérico o sin serial de hardware
                if re.search(r"&\d+$|&_&", serial_instance):
                    threat_score += 30
                    alerts.append("Descriptor genérico (Dispositivo sin serial único de fábrica)")

                if ven in ["", "Desconocido", "General", "_"]:
                    threat_score += 25
                    alerts.append("Fabricante (Vendor) no registrado o genérico")

                if dt != datetime.datetime.min:
                    diff_hours = (datetime.datetime.now() - dt).total_seconds() / 3600
                    if 0 <= diff_hours <= 48:
                        threat_score += 10
                        alerts.append("Actividad reciente en las últimas 48 horas")

                if threat_score >= 70:
                    nivel = "CRITICO"
                elif threat_score >= 40:
                    nivel = "SOSPECHOSO"
                else:
                    nivel = "CONFIABLE"

                dev_item = {
                    "friendly_name": friendly,
                    "vendor": ven,
                    "product": prod,
                    "revision": rev,
                    "serial_number": serial_instance,
                    "assigned_drive": assigned_drive,
                    "estado": "CONECTADO (LIVE)" if is_live else "HISTORICO",
                    "capacidad": live_cap,
                    "ultima_conexion": last_conn_str,
                    "threat_score": min(threat_score, 100),
                    "nivel_riesgo": nivel,
                    "alertas": " | ".join(alerts) if alerts else "Ninguna (Parámetros estándar)",
                    "hardware_id": hwid,
                    "tipo": "ALMACENAMIENTO (USBSTOR)"
                }
                devices.append(dev_item)
                inst_key.Close()
            dev_key.Close()
        usbstor_key.Close()
        return devices

    def check_badusb_signatures(self) -> List[Dict[str, Any]]:
        """Escanea HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB en busca de emuladores BadUSB / Rubber Ducky."""
        bad_devices = []
        if not winreg:
            return bad_devices

        try:
            usb_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB")
        except Exception:
            return bad_devices

        num_subkeys = winreg.QueryInfoKey(usb_key)[0]
        for i in range(num_subkeys):
            sub_name = winreg.EnumKey(usb_key, i).upper()
            for sig, info in BADUSB_SIGNATURES.items():
                sig_pattern = sig.upper().replace(":", "&PID_")
                if f"VID_{sig_pattern}" in sub_name:
                    bad_devices.append({
                        "friendly_name": info["nombre"],
                        "vendor": "EMULADOR HARDWARE",
                        "product": "BadUSB / Keystroke Injection",
                        "revision": "HID/VCP",
                        "serial_number": sub_name,
                        "assigned_drive": "HID Emulation",
                        "estado": "REGISTRADO EN SISTEMA",
                        "capacidad": "N/A",
                        "ultima_conexion": "Registro Persistente",
                        "threat_score": info["score"],
                        "nivel_riesgo": info["riesgo"],
                        "alertas": "FIRMA BADUSB DETECTADA: Identificador coincide con hardware de inyección de pulsaciones",
                        "hardware_id": f"USB\\{sub_name}",
                        "tipo": "BADUSB / HARDWARE ATTACK"
                    })
        usb_key.Close()
        return bad_devices

    def run_audit(self) -> List[Dict[str, Any]]:
        """Ejecuta la correlación completa de dispositivos."""
        self.get_drive_mappings()
        self.detect_live_usb_drives()
        devices = self.collect_usbstor_history()
        bad_devices = self.check_badusb_signatures()
        self.devices = devices + bad_devices
        return self.devices

    def export_json(self, output_path: Optional[str] = None) -> str:
        if not output_path:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.report_dir / f"UsbSentry_Audit_{ts}.json")
        payload = {
            "herramienta": TOOL_NAME,
            "version": VERSION,
            "autor": AUTHOR,
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": platform.node(),
            "total_auditados": len(self.devices),
            "dispositivos": self.devices
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4, ensure_ascii=False)
        return output_path

    def export_csv(self, output_path: Optional[str] = None) -> str:
        if not output_path:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.report_dir / f"UsbSentry_Audit_{ts}.csv")
        fieldnames = [
            "friendly_name", "vendor", "product", "serial_number",
            "assigned_drive", "estado", "capacidad", "ultima_conexion",
            "threat_score", "nivel_riesgo", "alertas", "hardware_id", "tipo"
        ]
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for dev in self.devices:
                writer.writerow(dev)
        return output_path

    def generate_html_dashboard(self, output_path: Optional[str] = None) -> str:
        """Genera un dashboard interactivo Cyberpunk Glassmorphism autónomo (0 CDNs)."""
        if not output_path:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.report_dir / f"UsbSentry_Dashboard_{ts}.html")

        total = len(self.devices)
        conectados = len([d for d in self.devices if "CONECTADO" in d["estado"]])
        alertas = len([d for d in self.devices if d["nivel_riesgo"] != "CONFIABLE"])
        criticos = len([d for d in self.devices if d["nivel_riesgo"] == "CRITICO"])
        avg_score = round(sum(d["threat_score"] for d in self.devices) / total, 1) if total > 0 else 0

        # Dial color
        if avg_score >= 60:
            score_color = "#ff3366"
        elif avg_score >= 35:
            score_color = "#ffbb00"
        else:
            score_color = "#00ff9d"

        rows_html = []
        for d in self.devices:
            riesgo = d["nivel_riesgo"]
            if riesgo == "CRITICO":
                badge_class = "badge-danger"
            elif riesgo == "SOSPECHOSO":
                badge_class = "badge-warning"
            else:
                badge_class = "badge-success"

            estado_class = "badge-live" if "CONECTADO" in d["estado"] else "badge-hist"

            row = f"""
            <tr>
                <td style="font-weight: 600; color: #fff;">
                    {d['friendly_name']}
                    <div style="font-size: 0.75rem; color: #64748b; font-family: monospace;">{d['tipo']}</div>
                </td>
                <td style="color: #94a3b8;">{d['vendor']}</td>
                <td style="font-family: monospace; color: #00f0ff;">{d['serial_number']}</td>
                <td style="font-weight: bold; color: #ffbb00;">{d['assigned_drive']}</td>
                <td><span class="badge {estado_class}">{d['estado']}</span></td>
                <td><span class="badge {badge_class}">{riesgo} ({d['threat_score']})</span></td>
                <td style="font-size: 0.8rem; color: #94a3b8;">{d['ultima_conexion']}</td>
                <td style="font-size: 0.8rem; color: #cbd5e1;">{d['alertas']}</td>
            </tr>
            """
            rows_html.append(row)

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UsbSentry - Cyberpunk Forensic Dashboard</title>
    <style>
        :root {{
            --bg-base: #060814;
            --bg-card: rgba(15, 23, 42, 0.75);
            --border-glow: rgba(0, 240, 255, 0.2);
            --cyan: #00f0ff;
            --emerald: #00ff9d;
            --amber: #ffbb00;
            --rose: #ff3366;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg-base);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(0, 240, 255, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(255, 51, 102, 0.08) 0%, transparent 40%);
            color: var(--text-main);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            padding: 30px 20px;
            min-height: 100vh;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        .header {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }}
        .header-title {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .header-title h1 {{
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--cyan), var(--emerald));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 1px;
        }}
        .header-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        
        /* Grid de KPIs */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, border-color 0.2s;
        }}
        .kpi-card:hover {{
            transform: translateY(-3px);
            border-color: var(--cyan);
        }}
        .kpi-title {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1.5px; color: var(--text-muted); }}
        .kpi-value {{ font-size: 2.2rem; font-weight: 800; margin-top: 8px; color: #fff; }}
        .kpi-indicator {{ position: absolute; top: 0; left: 0; width: 4px; height: 100%; }}
        
        /* Matriz MITRE ATT&CK */
        .mitre-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .mitre-title {{ font-size: 1rem; font-weight: 700; color: var(--cyan); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
        .mitre-tags {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .mitre-tag {{
            background: rgba(0, 240, 255, 0.08);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 0.8rem;
            color: #e2e8f0;
        }}
        
        /* Tabla de Dispositivos */
        .table-panel {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }}
        .table-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 16px;
            flex-wrap: wrap;
        }}
        .search-box {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            padding: 10px 16px;
            color: #fff;
            width: 320px;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-box:focus {{ border-color: var(--cyan); box-shadow: 0 0 10px rgba(0, 240, 255, 0.3); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            padding: 12px 14px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: var(--text-muted);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        td {{
            padding: 14px;
            font-size: 0.85rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: middle;
        }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        
        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-success {{ background: rgba(0, 255, 157, 0.15); color: var(--emerald); border: 1px solid var(--emerald); }}
        .badge-warning {{ background: rgba(255, 187, 0, 0.15); color: var(--amber); border: 1px solid var(--amber); }}
        .badge-danger {{ background: rgba(255, 51, 102, 0.15); color: var(--rose); border: 1px solid var(--rose); }}
        .badge-live {{ background: rgba(0, 240, 255, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }}
        .badge-hist {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }}
        
        .footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <div style="font-size: 2.2rem;">💾</div>
                <div>
                    <h1>UsbSentry :: Forensic Dashboard</h1>
                    <div style="font-size: 0.85rem; color: var(--text-muted);">
                        Auditoría Forense de Almacenamiento USB y Detección de BadUSB | WinAudit-DFIR
                    </div>
                </div>
            </div>
            <div class="header-meta">
                <div><strong>Host Auditado:</strong> {platform.node()}</div>
                <div><strong>Fecha:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                <div><strong>Autor:</strong> Cru9 / DFIR Suite</div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-indicator" style="background: var(--cyan);"></div>
                <div class="kpi-title">Dispositivos Auditados</div>
                <div class="kpi-value">{total}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-indicator" style="background: var(--emerald);"></div>
                <div class="kpi-title">Conectados en Vivo (Live)</div>
                <div class="kpi-value" style="color: var(--emerald);">{conectados}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-indicator" style="background: var(--amber);"></div>
                <div class="kpi-title">Alertas / Sospechosos</div>
                <div class="kpi-value" style="color: var(--amber);">{alertas}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-indicator" style="background: {score_color};"></div>
                <div class="kpi-title">Threat Score Global</div>
                <div class="kpi-value" style="color: {score_color};">{avg_score} <span style="font-size: 1rem; color: var(--text-muted);">/ 100</span></div>
            </div>
        </div>

        <div class="mitre-panel">
            <div class="mitre-title">🎯 Cobertura MITRE ATT&CK® Mapeada</div>
            <div class="mitre-tags">
                <div class="mitre-tag"><strong>T1091</strong> :: Replication Through Removable Media</div>
                <div class="mitre-tag"><strong>T1052.001</strong> :: Exfiltration Over Physical Medium</div>
                <div class="mitre-tag"><strong>T1200</strong> :: Hardware Additions (BadUSB / Rubber Ducky)</div>
                <div class="mitre-tag"><strong>T1025</strong> :: Data from Removable Media</div>
            </div>
        </div>

        <div class="table-panel">
            <div class="table-header">
                <h2 style="font-size: 1.2rem; font-weight: 700; color: #fff;">Historial y Registro Forense de Dispositivos</h2>
                <input type="text" id="searchInput" class="search-box" placeholder="Buscar por modelo, serial, fabricante o letra..." onkeyup="filterTable()">
            </div>
            <div style="overflow-x: auto;">
                <table id="deviceTable">
                    <thead>
                        <tr>
                            <th>Dispositivo / Modelo</th>
                            <th>Fabricante</th>
                            <th>Serial de Hardware</th>
                            <th>Unidad</th>
                            <th>Estado</th>
                            <th>Nivel de Riesgo</th>
                            <th>Última Conexión</th>
                            <th>Hallazgos Forenses</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            UsbSentry v{VERSION} &bull; Desarrollado por <strong>Cru9</strong> &bull; WinAudit-DFIR Suite &bull; Distribuido bajo Licencia MIT
        </div>
    </div>

    <script>
        function filterTable() {{
            const input = document.getElementById("searchInput");
            const filter = input.value.toUpperCase();
            const table = document.getElementById("deviceTable");
            const tr = table.getElementsByTagName("tr");

            for (let i = 1; i < tr.length; i++) {{
                const tdText = tr[i].textContent || tr[i].innerText;
                if (tdText.toUpperCase().indexOf(filter) > -1) {{
                    tr[i].style.display = "";
                }} else {{
                    tr[i].style.display = "none";
                }}
            }}
        }}
    </script>
</body>
</html>
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path


def show_banner():
    banner = rf"""
==============================================================================
   _   _   ___   ____    ____  _____ _   _ _____ ______   __
  | | | | / _ \ | __ )  / ___|| ____| \ | |_   _|  _ \ \ / /
  | | | || | | ||  _ \  \___ \|  _| |  \| | | | | |_) \ V / 
  | |_| || |_| || |_) |  ___) | |___| |\  | | | |  _ < | |  
   \___/  \___/ |____/  |____/|_____|_| \_| |_| |_| \_\|_|  
                                                            
  UsbSentry v{VERSION} - Forense de Dispositivos USB y BadUSB Hunter
  Cru9 DFIR Suite | Deteccion de Exfiltracion Fisica y Almacenamiento
==============================================================================
    """
    print(banner)


def interactive_menu():
    collector = UsbForensicCollector()
    collector.run_audit()

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        show_banner()
        print(f" [i] Host Auditado: {platform.node()} | Dispositivos Descubiertos: {len(collector.devices)}\n")
        print(" SELECCIONA UNA OPCION:")
        print(" [1] Ver Auditoria Forense Completa de Dispositivos USB")
        print(" [2] Filtrar Solo Dispositivos Conectados Actualmente (LIVE)")
        print(" [3] Filtrar Solo Dispositivos Sospechosos / BadUSB Hunter")
        print(" [4] Generar y Abrir Dashboard HTML Cyberpunk")
        print(" [5] Exportar Evidencias Forenses (JSON y CSV)")
        print(" [6] Re-escanear Dispositivos")
        print(" [0] Salir\n")

        opcion = input(" Selecciona una opcion [0-6]: ").strip()

        if opcion == "1":
            print("\n" + "="*80)
            print(" DISPOSITIVOS USB HISTORICOS Y CONECTADOS:")
            print("="*80)
            for d in collector.devices:
                print(f"  * {d['friendly_name']}")
                print(f"    - Fabricante    : {d['vendor']} | Modelo: {d['product']}")
                print(f"    - Serial        : {d['serial_number']}")
                print(f"    - Unidad / Estado: {d['assigned_drive']} | {d['estado']}")
                print(f"    - Ultima Vez    : {d['ultima_conexion']}")
                print(f"    - Riesgo        : [{d['nivel_riesgo']}] (Score: {d['threat_score']})")
                if d['nivel_riesgo'] != "CONFIABLE":
                    print(f"    - ALERTA        : {d['alertas']}")
                print("-" * 80)
            input("\n Presiona Enter para volver al menu...")

        elif opcion == "2":
            live = [d for d in collector.devices if "CONECTADO" in d["estado"]]
            print(f"\n Dispositivos Conectados en Vivo: {len(live)}")
            for d in live:
                print(f"  * [{d['assigned_drive']}] {d['friendly_name']} | Capacidad: {d['capacidad']} | Serial: {d['serial_number']}")
            if not live:
                print("  [i] Ningun dispositivo de almacenamiento USB conectado actualmente.")
            input("\n Presiona Enter para volver al menu...")

        elif opcion == "3":
            sos = [d for d in collector.devices if d["nivel_riesgo"] != "CONFIABLE"]
            print(f"\n Dispositivos Sospechosos o con Alerta: {len(sos)}")
            for d in sos:
                print(f"  * [{d['nivel_riesgo']}] {d['friendly_name']} ({d['vendor']})")
                print(f"    Serial: {d['serial_number']}")
                print(f"    Alerta: {d['alertas']}\n")
            if not sos:
                print("  [✓] Todos los dispositivos presentan parametros normales.")
            input("\n Presiona Enter para volver al menu...")

        elif opcion == "4":
            html_path = collector.generate_html_dashboard()
            print(f"\n [+] Dashboard interactivo generado en: {html_path}")
            webbrowser.open(f"file://{html_path}")
            input(" Presiona Enter para volver al menu...")

        elif opcion == "5":
            j_path = collector.export_json()
            c_path = collector.export_csv()
            print(f"\n [+] JSON guardado en: {j_path}")
            print(f" [+] CSV guardado en : {c_path}")
            input(" Presiona Enter para volver al menu...")

        elif opcion == "6":
            print("\n [*] Re-escaneando dispositivos...")
            collector.run_audit()
            print(f" [+] Escaneo actualizado: {len(collector.devices)} dispositivos encontrados.")
            input(" Presiona Enter para volver al menu...")

        elif opcion == "0":
            print("\n Saliendo de UsbSentry...")
            break


def main():
    if len(sys.argv) > 1:
        collector = UsbForensicCollector()
        collector.run_audit()
        if "--json" in sys.argv:
            collector.export_json()
        if "--csv" in sys.argv:
            collector.export_csv()
        if "--html" in sys.argv:
            p = collector.generate_html_dashboard()
            print(f"Dashboard generado: {p}")
        print(f"[+] Auditoria completada: {len(collector.devices)} dispositivos analizados.")
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
