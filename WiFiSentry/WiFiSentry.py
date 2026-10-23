#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFiSentry v3.0.0 | Suite de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
"""

import os
import sys
import math
import subprocess
import platform
import re
import html
import datetime
import time
from pathlib import Path

# Configuracion de terminal ANSI
os.system('')  # Habilitar soporte VT100 en Windows CMD

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
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner_art = r"""==============================================================================
  __        ___ _____ _ ____             _              
  \ \      / (_)  ___(_) ___|  ___ _ __ | |_ _ __ _   _ 
   \ \ /\ / /| | |_  | \___ \ / _ \ '_ \| __| '__| | | |
    \ V  V / | |  _| | |___) |  __/ | | | |_| |  | |_| |
     \_/\_/  |_|_|   |_|____/ \___|_| |_|\__|_|   \__, |
                                                  |___/ 
=============================================================================="""
    print(f"{CYAN}{BOLD}{banner_art}{MAGENTA}")
    print("  Suite DFIR de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo")
    print("  Ecosistema Cru9 | Multiplataforma (Windows, Linux, macOS) | v3.0.0")
    print(f"=============================================================================={RESET}\n")


# ==============================================================================
# MOTOR FORENSE: PERFILES WLAN GUARDADOS
# ==============================================================================
def get_windows_wifi_profiles():
    profiles = []
    try:
        raw = subprocess.check_output("netsh wlan show profiles", shell=True, text=True, errors="ignore")
    except Exception:
        return profiles

    profile_names = []
    for line in raw.splitlines():
        if (":") in line and ("Perfil de todos los usuarios" in line or "All User Profile" in line):
            parts = line.split(":", 1)
            if len(parts) > 1:
                name = parts[1].strip()
                if name and name not in ["<Ninguno>", "<None>"]:
                    profile_names.append(name)

    for idx, p_name in enumerate(profile_names, start=1):
        try:
            cmd = f'netsh wlan show profile name="{p_name}" key=clear'
            detail = subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
        except Exception:
            detail = ""

        auth = "Desconocida"
        cipher = "Desconocido"
        key_present = "No"
        key_content = ""
        auto_connect = "Manual"

        for line in detail.splitlines():
            line_str = line.strip()
            if ":" in line_str:
                k, v = [x.strip() for x in line_str.split(":", 1)]
                k_lower = k.lower()

                if "modo de conexi" in k_lower or "connection mode" in k_lower:
                    auto_connect = "Automatica" if ("auto" in v.lower()) else "Manual"
                elif "autenticaci" in k_lower or "authentication" in k_lower:
                    if auth == "Desconocida" or "WPA3" in v:
                        auth = v
                elif "cifrado" in k_lower or "cipher" in k_lower:
                    if cipher == "Desconocido" or "GCMP" in v or "CCMP" in v:
                        cipher = v
                elif "clave de seguridad" in k_lower or "security key" in k_lower:
                    key_present = v
                elif "contenido de la clave" in k_lower or "key content" in k_lower:
                    key_content = v

        # Heuristica de Riesgo Forense
        risk_level = "SEGURO"
        reasons = []

        if any(x in auth.lower() for x in ["abierta", "open", "ninguna", "none"]) or cipher.lower() in ["ninguno", "none"]:
            risk_level = "CRITICO"
            reasons.append("Red abierta (sin cifrado). Susceptible a sniffing pasivo y clonacion Rogue AP.")
            if auto_connect == "Automatica":
                reasons.append("Auto-conexion activa en red abierta: vector de ataque Evil Twin.")
        elif "wep" in auth.lower():
            risk_level = "CRITICO"
            reasons.append("Cifrado WEP obsoleto (crackeable en segundos con FMS/PTW).")
        else:
            if key_content:
                if len(key_content) < 8:
                    risk_level = "CRITICO"
                    reasons.append("Contrasena con menos de 8 caracteres.")
                elif key_content.isdigit():
                    risk_level = "ADVERTENCIA"
                    reasons.append("Contrasena solo numerica: vulnerable a fuerza bruta por GPU.")
                elif re.match(r'^[0-9a-fA-F]{8,16}$', key_content):
                    risk_level = "ADVERTENCIA"
                    reasons.append("Patron hexadecimal: posible clave de fabrica router ISP.")

        if not reasons:
            reasons.append(f"Perfil solido con cifrado moderno ({auth}/{cipher}).")

        profiles.append({
            "id": idx,
            "ssid": p_name,
            "auth": auth,
            "cipher": cipher,
            "auto_connect": auto_connect,
            "key_present": "Si" if key_content else ("No" if key_present.lower() in ["ausente", "absent", "no"] else "No"),
            "key_content": key_content,
            "risk_level": risk_level,
            "reasons": " | ".join(reasons)
        })

    return profiles


def get_stored_profiles():
    os_type = platform.system().lower()
    if "windows" in os_type:
        return get_windows_wifi_profiles()
    return []


# ==============================================================================
# ESCANEO EN VIVO DE REDES (BSSID / ROGUE AP HUNTER)
# ==============================================================================
def get_live_wlan_networks():
    networks = []
    os_type = platform.system().lower()

    if "windows" in os_type:
        try:
            raw = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True, errors="ignore")
        except Exception:
            return networks

        current_ssid = ""
        current_auth = "Desconocida"
        current_cipher = "Desconocido"

        for line in raw.splitlines():
            line_str = line.strip()
            if re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line_str, re.IGNORECASE):
                m = re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line_str, re.IGNORECASE)
                current_ssid = m.group(1).strip() if m else ""
                if not current_ssid:
                    current_ssid = "<SSID Oculto>"
            elif any(x in line_str.lower() for x in ["autenticaci", "authentication"]) and ":" in line_str:
                current_auth = line_str.split(":", 1)[1].strip()
            elif any(x in line_str.lower() for x in ["cifrado", "cipher"]) and ":" in line_str:
                current_cipher = line_str.split(":", 1)[1].strip()
            elif re.match(r'^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line_str, re.IGNORECASE):
                m = re.match(r'^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line_str, re.IGNORECASE)
                bssid = m.group(1).strip()
                networks.append({
                    "ssid": current_ssid,
                    "auth": current_auth,
                    "cipher": current_cipher,
                    "bssid": bssid,
                    "signal": "0%",
                    "channel": "0",
                    "band": "2.4 GHz",
                    "radio": "Desconocido"
                })
            elif re.search(r':\s*(\d+%)', line_str) and networks:
                m = re.search(r':\s*(\d+%)', line_str)
                if m:
                    networks[-1]["signal"] = m.group(1).strip()
            elif re.match(r'^(?:Canal|Channel)\s*:\s*(\d+)', line_str, re.IGNORECASE) and networks:
                m = re.match(r'^(?:Canal|Channel)\s*:\s*(\d+)', line_str, re.IGNORECASE)
                ch_val = int(m.group(1).strip())
                networks[-1]["channel"] = str(ch_val)
                if ch_val > 177: networks[-1]["band"] = "6 GHz"
                elif ch_val > 14: networks[-1]["band"] = "5 GHz"
                else: networks[-1]["band"] = "2.4 GHz"
            elif any(x in line_str.lower() for x in ["banda", "band"]) and ":" in line_str:
                if networks:
                    networks[-1]["band"] = line_str.split(":", 1)[1].strip()
            elif any(x in line_str.lower() for x in ["radio"]) and ":" in line_str:
                if networks:
                    networks[-1]["radio"] = line_str.split(":", 1)[1].strip()

    return networks


# ==============================================================================
# MOTOR DE ANALISIS EVIL TWIN / ROGUE AP
# ==============================================================================
def get_evil_twin_analysis(live_networks=None, stored_profiles=None):
    if live_networks is None:
        live_networks = get_live_wlan_networks()
    if stored_profiles is None:
        stored_profiles = get_stored_profiles()

    stored_dict = {p["ssid"]: p for p in stored_profiles}
    analysis = []

    for ap in live_networks:
        ssid = ap["ssid"]
        matched_stored = stored_dict.get(ssid)

        status = "NEIGHBOR"
        severity = "Bajo"
        badge = "Red Vecina"
        diagnostic = "Punto de acceso vecino no registrado en el equipo local."

        if matched_stored:
            st_auth = matched_stored["auth"]
            is_live_open = any(x in ap["auth"].lower() for x in ["abierta", "open", "none", "ninguno"])
            is_stored_prot = any(x in st_auth.lower() for x in ["wpa", "wpa2", "wpa3", "802.1x"])

            if is_live_open and is_stored_prot:
                status = "EVIL_TWIN_CRITICAL"
                severity = "Critico"
                badge = "ALERTA EVIL TWIN"
                diagnostic = f"PELIGRO CRITICO: El perfil guardado '{ssid}' exige {st_auth}, pero este AP emite SIN CIFRADO. Ataque Rogue AP activo clonando la red!"
            elif ap["auth"].lower() != st_auth.lower() and st_auth != "Desconocida":
                status = "WARNING_DOWNGRADE"
                severity = "Medio"
                badge = "Downgrade Cifrado"
                diagnostic = f"Discrepancia de seguridad: Guardada {st_auth} vs Detectada {ap['auth']}. Posible intento de degradacion de suite criptografica."
            else:
                status = "LEGITIMATE_MATCH"
                severity = "Informativo"
                badge = "Legitimo / Coincide"
                diagnostic = f"Coincide con perfil almacenado legitimo ({st_auth}). BSSID activo verificado."
        elif any(x in ap["auth"].lower() for x in ["abierta", "open", "none", "ninguno"]):
            status = "OPEN_UNENCRYPTED"
            severity = "Advertencia"
            badge = "Red Abierta Cercana"
            diagnostic = "Punto de acceso abierto no cifrado en el entorno. Susceptible a sniffing pasivo y captive portal phishing."

        analysis.append({
            "ssid": ssid,
            "bssid": ap["bssid"],
            "auth": ap["auth"],
            "cipher": ap["cipher"],
            "signal": ap["signal"],
            "channel": ap["channel"],
            "radio": ap["radio"],
            "status": status,
            "severity": severity,
            "badge": badge,
            "diagnostic": diagnostic
        })

    return analysis


# ==============================================================================
# CALCULADORA DE ENTROPIA Y ESTIMACION DE CRACKEO GPU (HASHCAT / AIRCRACK)
# ==============================================================================
def get_password_audit_stats(password):
    if not password:
        return {
            "length": 0,
            "pool_size": 0,
            "entropy_bits": 0.0,
            "complexity_class": "Sin Clave / Abierta",
            "pattern_type": "Red Abierta (0 bits)",
            "time_cpu": "Instantaneo (<1s)",
            "time_3060": "Instantaneo (<1s)",
            "time_4090": "Instantaneo (<1s)",
            "time_cluster": "Instantaneo (<1s)",
            "nist_compliance": "No Cumple (Sin contrasena)"
        }

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_special: pool += 33
    if pool == 0: pool = 10

    entropy = round(length * (math.log(pool) / math.log(2)), 1)

    # Deteccion de patrones
    pattern = "Alfanumerica Personalizada"
    if password.isdigit():
        pattern = "Solo Numerica (Vulnerable a PIN/Telefono)"
    elif re.match(r'^[0-9a-fA-F]{8,16}$', password):
        pattern = "Patron Hexadecimal (Clave de fabrica Router ISP)"
    elif re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8}$', password):
        pattern = "8 Caracteres Alfanumericos (Patron tipico ISP modem)"
    elif length >= 16 and not has_special:
        pattern = "Frase de Paso Extensa (Passphrase tipo Diceware)"
    elif length >= 14 and has_special and has_digit:
        pattern = "Frase de Paso Robusta de Alta Seguridad"

    # Clasificacion
    if entropy >= 80:
        complexity = "Nivel Militar / Extra Robusta"
        nist = "Excelente (Cumple NIST SP 800-63B / WPA3)"
    elif entropy >= 60:
        complexity = "Robusta"
        nist = "Adecuado para WPA2-PSK Domestico"
    elif entropy >= 40:
        complexity = "Moderada"
        nist = "Vulnerable a ataques de diccionario dirigidos"
    else:
        complexity = "Critica"
        nist = "No Cumple (<64 bits de entropia)"

    def format_crack_time(seconds):
        if seconds < 1: return "< 1 seg"
        if seconds < 60: return f"{round(seconds)} seg"
        if seconds < 3600: return f"{round(seconds / 60, 1)} min"
        if seconds < 86400: return f"{round(seconds / 3600, 1)} horas"
        if seconds < 31536000: return f"{round(seconds / 86400, 1)} dias"
        years = seconds / 31536000.0
        if years < 100: return f"{round(years, 1)} anos"
        if years < 1000: return f"{round(years)} anos"
        if years < 1000000: return f"{round(years / 1000, 1)}k anos"
        return "+1 Millon de anos (Inviable)"

    safe_exp = min(length, 16)
    combinations = math.pow(pool, safe_exp)
    if length > 16:
        combinations = math.pow(pool, 16) * math.pow(10, min(length - 16, 10))

    # Tasas de Hash reales en WPA2-PBKDF2 (Hashcat -m 2500 / -m 22000)
    # CPU: 30 kH/s, RTX 3060: 350 kH/s, RTX 4090: 2.4 MH/s, Cluster 8x: 19.2 MH/s
    return {
        "length": length,
        "pool_size": pool,
        "entropy_bits": entropy,
        "complexity_class": complexity,
        "pattern_type": pattern,
        "time_cpu": format_crack_time((combinations / 2.0) / 30000.0),
        "time_3060": format_crack_time((combinations / 2.0) / 350000.0),
        "time_4090": format_crack_time((combinations / 2.0) / 2400000.0),
        "time_cluster": format_crack_time((combinations / 2.0) / 19200000.0),
        "nist_compliance": nist
    }





# ==============================================================================
# VISTAS INTERACTIVAS CLI
# ==============================================================================
def show_evil_twin_radar():
    show_banner()
    print(f"{CYAN}=== RADAR DE CAZA DE ATAQUES EVIL TWIN Y ROGUE AP EN VIVO ===\n{RESET}")
    print(f"{YELLOW}[*] Escaneando frecuencias de radio 2.4 GHz, 5 GHz y 6 GHz via interfaz WLAN...{RESET}")

    analysis = get_evil_twin_analysis()
    if not analysis:
        print(f"\n{YELLOW}[!] No se detectaron redes inalambricas en vivo.{RESET}")
        print(f"{DIM}    Asegurate de que el adaptador Wi-Fi este encendido y habilitado.{RESET}")
        input(f"\nPresiona ENTER para volver al menu...")
        return

    print(f"\n{GREEN}[+] Puntos de Acceso detectados en el entorno: {len(analysis)}{RESET}")

    evil_alerts = [x for x in analysis if x["status"] == "EVIL_TWIN_CRITICAL"]
    downgrades = [x for x in analysis if x["status"] == "WARNING_DOWNGRADE"]

    if evil_alerts:
        print(f"\n{RED}{BOLD}[!!!] PELIGRO CRITICO: SE HAN DETECTADO {len(evil_alerts)} PUNTOS DE ACCESO SOSPECHOSOS DE EVIL TWIN!{RESET}")
    elif downgrades:
        print(f"\n{YELLOW}[!] ADVERTENCIA: Discrepancias de cifrado detectadas en redes conocidas.{RESET}")
    else:
        print(f"\n{GREEN}[OK] No se detectan anomalias directas de Evil Twin con los perfiles guardados.{RESET}")

    print("\n" + ("-" * 78))
    print(f"{CYAN}{'SSID':<20} {'BSSID (MAC AP)':<18} {'SEGURIDAD':<15} {'SENAL':<8} {'CANAL':<7} {'ESTADO':<14}{RESET}")
    print("-" * 78)

    for item in analysis:
        status_label = "[Vecina]"
        color = DIM
        if item["status"] == "EVIL_TWIN_CRITICAL":
            status_label = "[EVIL TWIN!]"
            color = RED
        elif item["status"] == "WARNING_DOWNGRADE":
            status_label = "[Downgrade]"
            color = YELLOW
        elif item["status"] == "LEGITIMATE_MATCH":
            status_label = "[Legitima]"
            color = GREEN
        elif item["status"] == "OPEN_UNENCRYPTED":
            status_label = "[Abierta]"
            color = MAGENTA

        ssid_disp = item["ssid"][:16] + "..." if len(item["ssid"]) > 19 else item["ssid"]
        auth_disp = item["auth"][:12] + ".." if len(item["auth"]) > 14 else item["auth"]

        print(f"{ssid_disp:<20} {item['bssid']:<18} {auth_disp:<15} {item['signal']:<8} {item['channel']:<7} {color}{status_label:<14}{RESET}")

    print("-" * 78)
    input(f"\nPresiona ENTER para volver al menu principal...")


# ==============================================================================
# MODULO 2: MAPA DE CALOR WI-FI EN TIEMPO REAL (SENSOR DE PROXIMIDAD & RSSI)
# ==============================================================================
def show_wifi_live_heatmap():
    prev_signals = {}
    sweep = 0
    keep_running = True

    try:
        import msvcrt
    except ImportError:
        msvcrt = None

    while keep_running:
        sweep += 1
        os.system('cls' if os.name == 'nt' else 'clear')
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        print(f"{CYAN}{BOLD}==========================================================================================")
        print("  MAPA DE CALOR WI-FI EN TIEMPO REAL (SENSOR DE PROXIMIDAD & RSSI TERMICO)")
        print(f"=========================================================================================={MAGENTA}")
        print(f"  Barrido #{sweep} | Hora: {now_str} | Refresco: 2.5s | [Presiona 'Q' o ESC para salir]")
        print(f"{DIM}==========================================================================================\n{RESET}")

        networks = get_live_wlan_networks()

        if not networks:
            print(f"{YELLOW}[!] No se detectaron redes en este barrido. Adaptador escaneando el espectro...{RESET}")
        else:
            networks.sort(key=lambda x: int(x.get("signal", "0%").replace('%', '') or 0), reverse=True)
            hottest = networks[0]

            print(f"{GREEN}  [+] Puntos de Acceso detectados: {len(networks)} | Fuente mas intensa: {hottest['ssid']} ({hottest['signal']}){RESET}")
            print(f"{DIM}{'-' * 105}{RESET}")
            print(f"{CYAN}{'SSID':<18} {'BSSID (MAC)':<18} {'CH':<5} {'BANDA':<8} {'SENAL':<6} {'EST.RSSI':<9} {'CALOR':<11} {'DELTA':<8} {'BARRA TERMICA (HEATMAP)'}{RESET}")
            print(f"{DIM}{'-' * 105}{RESET}")

            for ap in networks[:20]:
                sig_val = int(ap.get("signal", "0%").replace('%', '') or 0)
                rssi = round((sig_val / 2) - 100)

                if sig_val >= 80:
                    heat_lbl = "[!] CRITICO"
                    heat_color = RED
                elif sig_val >= 65:
                    heat_lbl = "[+] ALTO"
                    heat_color = YELLOW
                elif sig_val >= 45:
                    heat_lbl = "[~] MEDIO"
                    heat_color = YELLOW
                elif sig_val >= 25:
                    heat_lbl = "[-] BAJO"
                    heat_color = GREEN
                else:
                    heat_lbl = "[*] FRIO"
                    heat_color = CYAN

                delta_str = "  0%"
                delta_color = DIM
                bssid = ap.get("bssid", "")
                if bssid in prev_signals:
                    diff = sig_val - prev_signals[bssid]
                    if diff > 0:
                        delta_str = f"+{diff}%"
                        delta_color = RED
                    elif diff < 0:
                        delta_str = f"{diff}%"
                        delta_color = CYAN
                prev_signals[bssid] = sig_val

                bars_cnt = round((sig_val / 100) * 16)
                bar = ("\u2588" * bars_cnt) + ("\u2591" * (16 - bars_cnt))

                ssid_disp = (ap['ssid'][:15] + "..") if len(ap['ssid']) > 17 else ap['ssid']
                rssi_str = f"{rssi} dBm"
                band_str = ap.get("band", "2.4 GHz")

                print(f"{ssid_disp:<18} {bssid:<18} {ap.get('channel','0'):<5} {band_str:<8} {ap.get('signal','0%'):<6} {rssi_str:<9} ", end="")
                print(f"{heat_color}{heat_lbl:<11}{RESET} {delta_color}{delta_str:<8}{RESET} {heat_color}[{bar}]{RESET}")

            print(f"{DIM}{'-' * 105}{RESET}")

            # Congestion espectral
            print(f"\n{WHITE}TOP CANALES MAS CONGESTIONADOS (CARGA ESPECTRAL DE CALOR):{RESET}")
            ch_map = {}
            for ap in networks:
                ch = ap.get("channel", "0")
                sig = int(ap.get("signal", "0%").replace('%', '') or 0)
                if ch not in ch_map:
                    band = "5 GHz" if int(ch or 0) > 14 else "2.4 GHz"
                    ch_map[ch] = {"channel": ch, "band": band, "count": 0, "max_heat": 0}
                ch_map[ch]["count"] += 1
                if sig > ch_map[ch]["max_heat"]:
                    ch_map[ch]["max_heat"] = sig

            top_channels = sorted(ch_map.values(), key=lambda x: x["max_heat"], reverse=True)[:5]
            for ch in top_channels:
                ch_bar = round((ch["max_heat"] / 100) * 12)
                ch_bar_str = ("\u2588" * ch_bar) + ("\u2591" * (12 - ch_bar))
                ch_color = RED if ch["max_heat"] >= 75 else (YELLOW if ch["max_heat"] >= 50 else GREEN)
                print(f"  Canal {ch['channel']:>3} ({ch['band']:>7}): {ch_color}[{ch_bar_str}] {ch['max_heat']:>3}% Calor Max{RESET} {DIM}({ch['count']} APs saturando este canal){RESET}")

        print(f"\n{DIM}[Radar activo - Actualizando cada 2.5s. Presiona 'Q' o ESC para salir]{RESET}")

        # Non-blocking wait for 2.5s
        for _ in range(10):
            time.sleep(0.25)
            if msvcrt and msvcrt.kbhit():
                k = msvcrt.getch()
                if k.lower() in [b'q', b'\x1b']:
                    keep_running = False
                    break


def show_entropy_calculator():
    while True:
        show_banner()
        print(f"{CYAN}=== CALCULADORA DE ENTROPIA & ESTIMACION DE CRACKEO GPU (HASHCAT) ===\n{RESET}")
        print(f"{YELLOW}  [1] Auditar Entropia y Tiempos de Crackeo de Redes Guardadas{RESET}")
        print(f"{YELLOW}  [2] Probar una Contrasena o Frase de Paso Personalizada (Simulador en Vivo){RESET}")
        print(f"{RED}  [0] Volver al Menu Principal\n{RESET}")

        opt = input("Selecciona una opcion (0-2): ").strip()
        if opt == "1":
            profiles = [p for p in get_stored_profiles() if p["key_content"]]
            if not profiles:
                print(f"\n{YELLOW}[!] No se encontraron redes guardadas con clave visible para auditar.{RESET}")
                input("Presiona ENTER para continuar...")
                continue

            print("\n" + ("=" * 82))
            print(f"{CYAN}{'SSID':<18} {'LONG / ENTROPIA':<16} {'POOL':<8} {'ESTIMACION RTX 4090':<18} {'PATRON DETECTADO':<18}{RESET}")
            print("=" * 82)

            for p in profiles:
                stats = get_password_audit_stats(p["key_content"])
                col = GREEN
                if stats["entropy_bits"] < 45: col = RED
                elif stats["entropy_bits"] < 65: col = YELLOW

                ssid_s = p["ssid"][:14] + ".." if len(p["ssid"]) > 17 else p["ssid"]
                ent_s = f"{stats['length']} car | {stats['entropy_bits']} b"
                pat_s = stats["pattern_type"][:15] + ".." if len(stats["pattern_type"]) > 17 else stats["pattern_type"]

                print(f"{ssid_s:<18} {ent_s:<16} {stats['pool_size']:<8} {col}{stats['time_4090']:<18}{RESET} {DIM}{pat_s:<18}{RESET}")

            print("=" * 82)
            input("\nPresiona ENTER para continuar...")
        elif opt == "2":
            test_pass = input("\nIntroduce una contrasena o frase de paso a simular: ").strip()
            if not test_pass:
                continue

            s = get_password_audit_stats(test_pass)
            print(f"\n{CYAN}--- REPORTE DE ENTROPIA Y RESISTENCIA A FUERZA BRUTA ---{RESET}")
            print(f"  Longitud total:              {s['length']} caracteres")
            print(f"  Espacio de caracteres (Pool):{s['pool_size']} caracteres posibles")
            print(f"{YELLOW}  Entropia de Shannon/Keyspace:{s['entropy_bits']} bits{RESET}")
            print(f"  Clasificacion de robustez:   {s['complexity_class']}")
            print(f"  Patron identificado:         {s['pattern_type']}")
            print(f"  Cumplimiento NIST SP 800-63B:{s['nist_compliance']}")

            print(f"\n{MAGENTA}--- TIEMPO ESTIMADO DE CRACKEO WPA2 (PBKDF2 4096 Rondas) ---{RESET}")
            print(f"  [CPU] Multi-Core (30 kH/s):         {s['time_cpu']}")
            print(f"  [GPU] NVIDIA RTX 3060 (350 kH/s):   {s['time_3060']}")
            print(f"{YELLOW}  [GPU] NVIDIA RTX 4090 (2.4 MH/s):   {s['time_4090']}{RESET}")
            print(f"{GREEN}  [CLOUD] Cluster 8x RTX 4090 (19.2M):{s['time_cluster']}{RESET}")

            input("\nPresiona ENTER para continuar...")
        elif opt == "0":
            return





def show_audit_summary(reveal=False, interactive=True):
    show_banner()
    print(f"{CYAN}=== AUDITORIA COMPLETA DE PERFILES WI-FI (SEMAFORO DE RIESGO) ===\n{RESET}")

    profiles = get_stored_profiles()
    if not profiles:
        print(f"{YELLOW}[!] No se detectaron perfiles guardados.{RESET}")
        if interactive:
            input("\nPresiona ENTER para continuar...")
        return

    criticos = sum(1 for p in profiles if p["risk_level"] == "CRITICO")
    advertencias = sum(1 for p in profiles if p["risk_level"] == "ADVERTENCIA")
    seguros = sum(1 for p in profiles if p["risk_level"] == "SEGURO")

    print(f"Resumen Forense:")
    print(f"  Total de Redes Analizadas: {len(profiles)}")
    print(f"{YELLOW}  [!] Criticas: {criticos} | [~] Advertencias: {advertencias} | [OK] Seguras: {seguros}\n{RESET}")

    print(f"{CYAN}{'ID':<4} {'SSID':<20} {'SEGURIDAD':<15} {'AUTO-CONN':<10} {'RIESGO':<12} {'CLAVE':<16}{RESET}")
    print("-" * 80)

    for p in profiles:
        color = GREEN
        if p["risk_level"] == "CRITICO": color = RED
        elif p["risk_level"] == "ADVERTENCIA": color = YELLOW

        key_display = "--------"
        if not p["key_content"]:
            key_display = "<Sin Clave>"
        elif reveal:
            key_display = p["key_content"]
        else:
            key_display = "********"

        ssid_s = p["ssid"][:16] + "..." if len(p["ssid"]) > 19 else p["ssid"]
        auth_s = p["auth"][:12] + ".." if len(p["auth"]) > 14 else p["auth"]

        print(f"{p['id']:<4} {ssid_s:<20} {auth_s:<15} {p['auto_connect']:<10} {color}{p['risk_level']:<12}{RESET} {DIM}{key_display:<16}{RESET}")

    print("-" * 80)
    if not interactive:
        return

    print("\nOpciones:")
    print("  [R] Revelar contrasenas en consola")
    print("  [V] Volver al Menu Principal\n")

    opt = input("Selecciona una opcion: ").strip().lower()
    if opt in ["r", "revelar"]:
        show_audit_summary(reveal=True, interactive=True)


def invoke_network_hardening():
    show_banner()
    print(f"{CYAN}=== ASISTENTE DE LIMPIEZA & HARDENING DE REDES WI-FI ===\n{RESET}")
    print("  [1] Desactivar conexion automatica en redes abiertas o sospechosas")
    print("  [2] Eliminar un perfil Wi-Fi especifico (Higiene Digital)")
    print("  [3] Eliminar todas las redes abiertas (Sin contrasena)")
    print("  [0] Volver al Menu Principal\n")

    act = input("Introduce tu opcion (0-3): ").strip()
    if act == "1":
        profiles = [p for p in get_stored_profiles() if p["risk_level"] == "CRITICO" and p["auto_connect"] == "Automatica"]
        if not profiles:
            print(f"\n{GREEN}[OK] No hay redes criticas con conexion automatica activa.{RESET}")
        else:
            for p in profiles:
                print(f"[*] Desactivando conexion automatica para: {p['ssid']}...")
                subprocess.run(f'netsh wlan set profileparameter name="{p["ssid"]}" connectionmode=manual', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{GREEN}[+] Accion completada con exito.{RESET}")
    elif act == "2":
        target = input("\nIntroduce el nombre exacto de la red (SSID) que deseas eliminar: ").strip()
        if target:
            subprocess.run(f'netsh wlan delete profile name="{target}"', shell=True)
            print(f"{GREEN}[+] Perfil eliminado si existia.{RESET}")
    elif act == "3":
        open_profs = [p for p in get_stored_profiles() if any(x in p["auth"].lower() for x in ["abierta", "open", "none", "ninguno"])]
        if not open_profs:
            print(f"\n{GREEN}[OK] No tienes redes abiertas almacenadas.{RESET}")
        else:
            for op in open_profs:
                subprocess.run(f'netsh wlan delete profile name="{op["ssid"]}"', shell=True, stdout=subprocess.DEVNULL)
            print(f"{GREEN}[+] Todas las redes abiertas han sido eliminadas.{RESET}")
    input("\nPresiona ENTER para continuar...")


# ==============================================================================
# GENERACION DE DASHBOARD HTML
# ==============================================================================
def export_html_report(output_path=None):
    print(f"\n{YELLOW}[*] Generando Dashboard HTML forense interactivo...{RESET}")
    profiles = get_stored_profiles()
    live_nets = get_live_wlan_networks()
    evil_analysis = get_evil_twin_analysis(live_nets, profiles)

    total_count = len(profiles)
    critical_count = sum(1 for p in profiles if p["risk_level"] == "CRITICO")
    warning_count = sum(1 for p in profiles if p["risk_level"] == "ADVERTENCIA")
    secure_count = sum(1 for p in profiles if p["risk_level"] == "SEGURO")

    score = 100
    if total_count > 0:
        score -= (critical_count * 30)
        score -= (warning_count * 12)
        score = max(0, score)

    score_color = "#10b981"
    if score < 50: score_color = "#ef4444"
    elif score < 75: score_color = "#f59e0b"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_file = REPORTS_DIR / f"WiFiSentry_Dashboard_{timestamp}.html"
    if output_path:
        target_file = Path(output_path)

    # Filas de Inventario
    tbody_profiles = []
    for p in profiles:
        badge_cls = "badge-secure"
        if p["risk_level"] == "CRITICO": badge_cls = "badge-critical"
        elif p["risk_level"] == "ADVERTENCIA": badge_cls = "badge-warning"

        key_cell = "<span class='text-muted'>Sin Clave</span>"
        if p["key_content"]:
            enc_k = html.escape(p["key_content"])
            masked_k = "*" * min(len(p["key_content"]), 12)
            key_cell = f"<span class='masked-key'>{masked_k}</span><span class='revealed-key' style='display:none;'>{enc_k}</span> <button class='btn-toggle' onclick='toggleKey(this)'>[Ver]</button> <button class='btn-copy' data-key='{enc_k}' onclick='copyKey(this)'>Copiar</button>"

        tbody_profiles.append(f"""
        <tr>
            <td style="color: var(--cyan); font-weight: bold;">{p['id']}</td>
            <td class="ssid-title">{html.escape(p['ssid'])}</td>
            <td><span class="auth-pill">{html.escape(p['auth'])}</span></td>
            <td>{html.escape(p['cipher'])}</td>
            <td>{p['auto_connect']}</td>
            <td class="key-cell">{key_cell}</td>
            <td><span class="badge {badge_cls}">{p['risk_level']}</span></td>
            <td class="reasons-cell">{html.escape(p['reasons'])}</td>
        </tr>""")

    # Tarjetas de Mapa de Calor (Heatmap)
    heatmap_cards = []
    sorted_heat = sorted(live_nets, key=lambda x: int(x.get("signal", "0%").replace('%', '') or 0), reverse=True)

    for net in sorted_heat:
        sig_val = int(net.get("signal", "0%").replace('%', '') or 0)
        rssi = round((sig_val / 2) - 100)

        heat_class = "heat-cold"
        heat_status = "FRIO / DISTANTE"
        heat_dist = "> 20 metros"
        heat_color = "var(--heat-cold)"

        if sig_val >= 80:
            heat_class = "heat-critical"
            heat_status = "CRITICO / INMEDIATO"
            heat_dist = "< 3 metros (Mismo habitaculo)"
            heat_color = "var(--heat-critical)"
        elif sig_val >= 65:
            heat_class = "heat-high"
            heat_status = "ALTO / MUY CERCANO"
            heat_dist = "~3 a 8 metros"
            heat_color = "var(--heat-high)"
        elif sig_val >= 45:
            heat_class = "heat-medium"
            heat_status = "MEDIO / TEMPLADO"
            heat_dist = "~8 a 15 metros"
            heat_color = "var(--heat-medium)"
        elif sig_val >= 25:
            heat_class = "heat-low"
            heat_status = "BAJO / TIBIO"
            heat_dist = "~15 a 25 metros"
            heat_color = "var(--heat-low)"

        safe_ssid = html.escape(net.get("ssid", ""))
        band_str = net.get("band", "2.4 GHz")
        channel_str = net.get("channel", "0")

        heatmap_cards.append(f"""
        <div class="heat-card {heat_class}" data-bssid="{net.get('bssid','')}" data-signal="{sig_val}" data-channel="{channel_str}" data-band="{band_str}">
            <div class="heat-card-header">
                <div>
                    <h3 class="heat-ssid">{safe_ssid}</h3>
                    <span class="heat-bssid">{net.get('bssid','')}</span>
                </div>
                <span class="heat-badge" style="background: {heat_color}22; color: {heat_color}; border: 1px solid {heat_color}88;">{heat_status}</span>
            </div>
            
            <div class="heat-metrics">
                <div class="heat-metric">
                    <span class="heat-val heat-sig-display">{sig_val}%</span>
                    <span class="heat-lbl">Potencia RF</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val heat-rssi-display">{rssi} dBm</span>
                    <span class="heat-lbl">RSSI Estimado</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val" style="color: var(--cyan);">{channel_str}</span>
                    <span class="heat-lbl">Canal ({band_str})</span>
                </div>
                <div class="heat-metric">
                    <span class="heat-val heat-dist-display" style="font-size: 0.9rem; color: #cbd5e1;">{heat_dist}</span>
                    <span class="heat-lbl">Proximidad</span>
                </div>
            </div>

            <div class="heat-bar-container">
                <div class="heat-bar-fill" style="width: {sig_val}%;"></div>
            </div>
        </div>""")

    ch_groups = {}
    for net in sorted_heat:
        ch = net.get("channel", "0")
        sig = int(net.get("signal", "0%").replace('%', '') or 0)
        if ch not in ch_groups:
            band = "5 GHz" if int(ch or 0) > 14 else "2.4 GHz"
            ch_groups[ch] = {"channel": ch, "band": band, "count": 0, "max_heat": 0}
        ch_groups[ch]["count"] += 1
        if sig > ch_groups[ch]["max_heat"]:
            ch_groups[ch]["max_heat"] = sig

    spectrum_bars = []
    for ch_item in sorted(ch_groups.values(), key=lambda x: x["max_heat"], reverse=True):
        max_h = ch_item["max_heat"]
        ch_color = "var(--heat-cold)"
        if max_h >= 80: ch_color = "var(--heat-critical)"
        elif max_h >= 65: ch_color = "var(--heat-high)"
        elif max_h >= 45: ch_color = "var(--heat-medium)"
        elif max_h >= 25: ch_color = "var(--heat-low)"

        spectrum_bars.append(f"""
        <div class="spectrum-bar-item">
            <div class="spectrum-bar-header">
                <span><strong>Canal {ch_item['channel']}</strong> ({ch_item['band']})</span>
                <span style="color: {ch_color}; font-family: var(--font-mono); font-weight: bold;">{max_h}% Calor Max ({ch_item['count']} APs)</span>
            </div>
            <div class="spectrum-bar-track">
                <div class="spectrum-bar-fill" style="width: {max_h}%; background: {ch_color};"></div>
            </div>
        </div>""")

    # Filas de Radar
    tbody_radar = []
    for r in evil_analysis:
        badge_cls = "badge-secure"
        if r["status"] == "EVIL_TWIN_CRITICAL": badge_cls = "badge-critical"
        elif r["status"] in ["WARNING_DOWNGRADE", "OPEN_UNENCRYPTED"]: badge_cls = "badge-warning"

        sig_m = re.search(r'(\d+)', r["signal"])
        sig_val = int(sig_m.group(1)) if sig_m else 0

        tbody_radar.append(f"""
        <tr>
            <td class="ssid-title">{html.escape(r['ssid'])}</td>
            <td style="font-family: var(--font-mono); color: var(--cyan);">{r['bssid']}</td>
            <td><span class="auth-pill">{html.escape(r['auth'])}</span></td>
            <td>{r['channel']}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="signal-bar-bg"><div class="signal-bar-fill" style="width: {sig_val}%;"></div></div>
                    <span style="font-size: 0.8rem; font-family: var(--font-mono);">{r['signal']}</span>
                </div>
            </td>
            <td><span class="badge {badge_cls}">{r['badge']}</span></td>
            <td class="reasons-cell">{html.escape(r['diagnostic'])}</td>
        </tr>""")

    # Filas de Entropia
    tbody_entropy = []
    for p in profiles:
        if p["key_content"]:
            st = get_password_audit_stats(p["key_content"])
            ent_badge = "badge-secure"
            if st["entropy_bits"] < 45: ent_badge = "badge-critical"
            elif st["entropy_bits"] < 65: ent_badge = "badge-warning"

            tbody_entropy.append(f"""
            <tr>
                <td class="ssid-title">{html.escape(p['ssid'])}</td>
                <td style="font-family: var(--font-mono);">{st['length']} caracteres</td>
                <td style="font-family: var(--font-mono);">{st['pool_size']} vars</td>
                <td><span class="badge {ent_badge}">{st['entropy_bits']} bits</span></td>
                <td style="font-size: 0.85rem; color: #cbd5e1;">{html.escape(st['pattern_type'])}</td>
                <td style="font-family: var(--font-mono); font-size: 0.85rem;">{st['time_cpu']}</td>
                <td style="font-family: var(--font-mono); font-size: 0.85rem; color: #f59e0b;">{st['time_3060']}</td>
                <td style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--cyan); font-weight: bold;">{st['time_4090']}</td>
                <td style="font-family: var(--font-mono); font-size: 0.85rem; color: #10b981;">{st['time_cluster']}</td>
            </tr>""")



    fecha_str = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    metrics = [


        {"label": "Perfiles WLAN Extraídos", "value": total_profiles, "icon": "📡"},


        {"label": "Claves en Claro Auditadas", "value": len(claves_claras), "icon": "🔑"},


        {"label": "Rogue AP / Evil Twin", "value": len(rogue_aps), "icon": "🚨"},


        {"label": "Redes en Vivo", "value": len(live_networks), "icon": "📶"}


    ]


    headers = [


        "SSID / Red", "BSSID / MAC", "Seguridad & Auth", "Clave Recuperada",


        "Señal RSSI", "Canal / Frecuencia", "Alerta / Diagnóstico"


    ]


    try:


        import forensic_theme


    except ImportError:


        base_dir = Path(__file__).resolve().parent.parent


        if str(base_dir) not in sys.path:


            sys.path.insert(0, str(base_dir))


        import forensic_theme



    html_content = forensic_theme.render_homologated_dashboard(


        title="Wireless Forensic Suite & Evil Twin Hunter",


        sentry_id="2",


        sentry_name="WiFiSentry",


        sentry_icon="📡",


        subtitle="Auditoría de perfiles WLAN, claves en claro, telemetría de señal RF y detección de APs gemelos",


        metrics=metrics,


        table_headers=headers,


        table_rows_html="".join(tbody_live),


        risk_score=0 if len(rogue_aps) == 0 else 75,


        back_url="../../index.html"


    )

    with open(target_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n{GREEN}[+] Dashboard HTML interactivo generado con exito en:{RESET}")
    print(f"  {CYAN}{target_file}{RESET}")

    if not output_path:
        try:
            if platform.system().lower() == "windows":
                os.startfile(target_file)
            elif platform.system().lower() == "darwin":
                subprocess.Popen(["open", str(target_file)])
            else:
                subprocess.Popen(["xdg-open", str(target_file)])
        except Exception:
            pass


def show_cheatsheet():
    show_banner()
    print(f"{CYAN}=== CHEATSHEET MULTIPLATAFORMA DE AUDITORIA WLAN ===\n{RESET}")

    print(f"{WHITE}WINDOWS (PowerShell / CMD){RESET}")
    print(f"{YELLOW}  1. Ver perfiles guardados:{RESET}\n     netsh wlan show profiles")
    print(f"{YELLOW}  2. Ver contrasena en texto claro:{RESET}\n     netsh wlan show profile name=\"NOMBRE_RED\" key=clear")
    print(f"{YELLOW}  3. Escanear redes en vivo con BSSID y senal:{RESET}\n     netsh wlan show networks mode=bssid")
    print(f"{YELLOW}  4. Borrar red guardada (Higiene):{RESET}\n     netsh wlan delete profile name=\"NOMBRE_RED\"")
    print(f"{YELLOW}  5. Desactivar conexion automatica:{RESET}\n     netsh wlan set profileparameter name=\"NOMBRE_RED\" connectionmode=manual\n")

    print(f"{WHITE}macOS (Terminal){RESET}")
    print(f"{YELLOW}  1. Extraer contrasena del Keychain del sistema:{RESET}\n     security find-generic-password -wa \"NOMBRE_RED\"")
    print(f"{YELLOW}  2. Escanear puntos de acceso cercanos:{RESET}\n     /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s\n")

    print(f"{WHITE}LINUX (Terminal / Bash){RESET}")
    print(f"{YELLOW}  1. Ver contrasena de la red Wi-Fi actual (NetworkManager):{RESET}\n     nmcli device wifi show-password")
    print(f"{YELLOW}  2. Volcar todas las contrasenas guardadas en el sistema:{RESET}\n     sudo grep -r '^psk=' /etc/NetworkManager/system-connections/")
    print(f"{YELLOW}  3. Escanear redes cercanas con intensidad y canal:{RESET}\n     nmcli device wifi list\n")

    input("Presiona ENTER para volver al menu principal...")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="WiFiSentry v3.0.0 | Suite de Auditoria WLAN DFIR")
    parser.add_argument("--audit", action="store_true", help="Auditoria rapida en consola")
    parser.add_argument("--radar", action="store_true", help="Radar Evil Twin en vivo")
    parser.add_argument("--heatmap", action="store_true", help="Mapa de calor Wi-Fi en tiempo real")
    parser.add_argument("--entropy", action="store_true", help="Calculadora de entropia")
    parser.add_argument("--html", type=str, help="Ruta para exportar dashboard HTML")
    args = parser.parse_args()

    if args.audit:
        show_audit_summary(interactive=False)
        return
    if args.radar:
        show_evil_twin_radar()
        return
    if args.heatmap:
        show_wifi_live_heatmap()
        return
    if args.entropy:
        show_entropy_calculator()
        return
    if args.html:
        export_html_report(args.html)
        return

    while True:
        show_banner()
        print(f"{WHITE}   SELECCIONA UNA OPCION:{RESET}")
        print(f"{CYAN}  [1] Auditoria Completa de Perfiles (Tabla con Semaforo de Riesgo){RESET}")
        print(f"{GREEN}  [2] Radar Evil Twin en Vivo (Deteccion de Rogue AP y Downgrade Attack){RESET}")
        print(f"{RED}  [3] Mapa de Calor Wi-Fi en Tiempo Real (Heatmap de Senal & Proximidad){RESET}")
        print(f"{YELLOW}  [4] Calculadora de Entropia & Estimacion de Crackeo (Hashcat / GPU){RESET}")
        print(f"{CYAN}  [5] Asistente de Limpieza & Hardening (Eliminar redes / Auto-conectar){RESET}")
        print(f"{CYAN}  [6] Generar Reporte Visual Interactivo (Dashboard HTML Cyberpunk){RESET}")
        print(f"{CYAN}  [7] Guia de Comandos Multiplataforma (Cheatsheet Windows / Mac / Linux){RESET}")
        print(f"{RED}  [0] Salir\n{RESET}")

        choice = input("Introduce tu opcion (0-7): ").strip()
        if choice == "1": show_audit_summary()
        elif choice == "2": show_evil_twin_radar()
        elif choice == "3": show_wifi_live_heatmap()
        elif choice == "4": show_entropy_calculator()
        elif choice == "5": invoke_network_hardening()
        elif choice == "6": export_html_report()
        elif choice == "7": show_cheatsheet()
        elif choice == "0":
            print(f"\n{GREEN}[+] Gracias por usar WiFiSentry! Cuida tu postura de seguridad inalambrica.{RESET}")
            sys.exit(0)
        else:
            print(f"\n{RED}[!] Opcion no reconocida.{RESET}")


if __name__ == "__main__":
    main()
