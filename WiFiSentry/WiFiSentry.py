#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFiSentry v1.2 | Suite de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo
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
    print("  Ecosistema Cru9 | Multiplataforma (Windows, Linux, macOS) | v1.2")
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

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFiSentry v1.2 | Centro de Operaciones Forenses WLAN</title>
    <style>
        :root {{
            --bg-base: #080c14;
            --bg-card: rgba(15, 23, 42, 0.78);
            --bg-card-hover: rgba(30, 41, 59, 0.85);
            --border-glow: rgba(0, 242, 254, 0.2);
            --border-card: rgba(255, 255, 255, 0.08);
            --cyan: #00f2fe;
            --purple: #8b5cf6;
            --green: #10b981;
            --yellow: #f59e0b;
            --red: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --font-mono: 'Consolas', 'Fira Code', monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(at 0% 0%, rgba(0, 242, 254, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.12) 0px, transparent 50%);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            min-height: 100vh;
            line-height: 1.6;
        }}

        .header {{
            background: rgba(8, 12, 20, 0.95);
            border-bottom: 1px solid var(--border-glow);
            padding: 16px 36px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 1000;
            backdrop-filter: blur(12px);
        }}
        .header-title h1 {{
            font-size: 1.7rem;
            font-weight: 900;
            letter-spacing: 1px;
            background: linear-gradient(135deg, var(--cyan), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-muted); font-size: 0.85rem; margin-top: 2px; }}
        .author-tag {{
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid var(--border-glow);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--cyan);
            font-weight: 600;
        }}

        .container {{ max-width: 1380px; margin: 0 auto; padding: 25px 20px 60px 20px; }}

        /* NAVEGACION TABULADA */
        .tabs-nav {{
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            border-bottom: 1px solid var(--border-card);
            padding-bottom: 12px;
        }}
        .tab-btn {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-card);
            color: var(--text-muted);
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .tab-btn:hover {{ background: rgba(0, 242, 254, 0.1); color: #fff; }}
        .tab-btn.active {{
            background: linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(139, 92, 246, 0.2));
            border-color: var(--cyan);
            color: var(--cyan);
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.3);
        }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; animation: fadeIn 0.3s ease; }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(6px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* METRIC CARDS */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 18px;
            margin-bottom: 25px;
        }}
        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        .metric-card:hover {{ transform: translateY(-3px); border-color: rgba(0,242,254,0.4); }}
        .metric-title {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}
        .metric-value {{ font-size: 2.2rem; font-weight: 800; margin: 8px 0; font-family: var(--font-mono); }}
        .metric-desc {{ font-size: 0.78rem; color: var(--text-muted); }}

        .section-box {{
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            backdrop-filter: blur(10px);
        }}
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            border-bottom: 1px solid var(--border-card);
            padding-bottom: 12px;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .section-header h2 {{ font-size: 1.25rem; color: var(--text-main); display: flex; align-items: center; gap: 8px; }}
        
        .table-responsive {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
        th {{ background: rgba(0,0,0,0.3); color: var(--text-muted); text-align: left; padding: 12px 10px; font-weight: 600; text-transform: uppercase; font-size: 0.74rem; letter-spacing: 0.5px; }}
        td {{ padding: 12px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }}
        tr:hover td {{ background: var(--bg-card-hover); }}

        .ssid-title {{ font-weight: 600; color: #fff; font-size: 0.92rem; }}
        .auth-pill {{ background: rgba(255,255,255,0.06); padding: 4px 8px; border-radius: 6px; font-family: var(--font-mono); font-size: 0.78rem; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block; }}
        .badge-critical {{ background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.4); }}
        .badge-warning {{ background: rgba(245,158,11,0.15); color: var(--yellow); border: 1px solid rgba(245,158,11,0.4); }}
        .badge-secure {{ background: rgba(16,185,129,0.15); color: var(--green); border: 1px solid rgba(16,185,129,0.4); }}

        .key-cell {{ font-family: var(--font-mono); white-space: nowrap; }}
        .btn-toggle, .btn-copy {{ background: rgba(255,255,255,0.08); border: none; color: #fff; padding: 4px 8px; border-radius: 4px; cursor: pointer; margin-left: 4px; font-size: 0.75rem; }}
        .btn-toggle:hover, .btn-copy:hover {{ background: rgba(0,242,254,0.3); }}

        .signal-bar-bg {{ width: 90px; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }}
        .signal-bar-fill {{ height: 100%; background: linear-gradient(90deg, var(--yellow), var(--green)); border-radius: 4px; }}

        .reasons-cell {{ font-size: 0.8rem; color: #cbd5e1; max-width: 320px; }}

        .search-bar {{
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border-glow);
            padding: 8px 16px;
            border-radius: 8px;
            color: #fff;
            width: 260px;
            outline: none;
            font-size: 0.85rem;
        }}
        .search-bar:focus {{ border-color: var(--cyan); }}

        /* SIMULADOR DE ENTROPIA WIDGET */
        .simulator-box {{
            background: linear-gradient(135deg, rgba(0,242,254,0.06), rgba(139,92,246,0.06));
            border: 1px solid rgba(0,242,254,0.3);
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 25px;
        }}
        .sim-input {{
            width: 100%;
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--border-glow);
            padding: 12px 18px;
            border-radius: 8px;
            color: #fff;
            font-size: 1.1rem;
            font-family: var(--font-mono);
            outline: none;
            margin: 12px 0 16px 0;
        }}
        .sim-input:focus {{ border-color: var(--cyan); box-shadow: 0 0 15px rgba(0,242,254,0.25); }}

        .entropy-meter-wrap {{
            height: 12px;
            background: rgba(255,255,255,0.08);
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 18px;
        }}
        .entropy-meter-fill {{
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--red), var(--yellow), var(--green), var(--cyan));
            transition: width 0.3s ease;
        }}

        .sim-stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }}
        .sim-stat-card {{
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border-card);
            padding: 12px;
            border-radius: 8px;
            text-align: center;
        }}
        .sim-stat-val {{ font-size: 1.3rem; font-weight: 700; font-family: var(--font-mono); color: var(--cyan); }}
        .sim-stat-lbl {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }}

        .crack-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 12px;
        }}
        .crack-card {{
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--border-card);
            border-radius: 8px;
            padding: 12px 14px;
        }}
        .crack-hw {{ font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; }}
        .crack-rate {{ font-size: 0.75rem; color: var(--cyan); font-family: var(--font-mono); }}
        .crack-time {{ font-size: 1.15rem; font-weight: 700; color: #fff; margin-top: 6px; font-family: var(--font-mono); }}


        .educational-box {{
            background: linear-gradient(135deg, rgba(0,242,254,0.05), rgba(16,185,129,0.03));
            border: 1px solid rgba(0,242,254,0.25);
            border-radius: 12px;
            padding: 22px;
            margin-top: 15px;
        }}
        .educational-box h3 {{ color: var(--cyan); margin-bottom: 10px; font-size: 1.1rem; }}
        .educational-box ul {{ padding-left: 20px; color: #cbd5e1; font-size: 0.88rem; }}
        .educational-box li {{ margin-bottom: 8px; }}

        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.82rem; margin-top: 45px; }}
        .footer a {{ color: var(--cyan); text-decoration: none; }}
    </style>
</head>
<body>

    <header class="header">
        <div class="header-title">
            <h1>WiFiSentry v1.2</h1>
            <p>Suite DFIR de Auditoria WLAN, Radar Evil Twin & Mapa de Calor en Vivo</p>
        </div>
        <div>
            <span class="author-tag">Ezequiel Diaz (Cru9)</span>
        </div>
    </header>

    <div class="container">

        <!-- NAVEGACION POR TABULADORES -->
        <div class="tabs-nav">
            <button class="tab-btn active" onclick="openTab('tab-dashboard')">📊 Resumen Ejecutivo</button>
            <button class="tab-btn" onclick="openTab('tab-heatmap')">🔥 Mapa de Calor Espectral ({len(live_nets)})</button>
            <button class="tab-btn" onclick="openTab('tab-radar')">📡 Radar Evil Twin (Hunter)</button>
            <button class="tab-btn" onclick="openTab('tab-entropy')">🔐 Calculadora de Entropia & Crackeo</button>
            <button class="tab-btn" onclick="openTab('tab-profiles')">📋 Inventario Forense ({total_count})</button>
            <button class="tab-btn" onclick="openTab('tab-hardening')">🔒 Manual & Cheatsheet</button>
        </div>

        <!-- TAB 1: DASHBOARD EJECUTIVO -->
        <div id="tab-dashboard" class="tab-content active">
            <div style="text-align: center; margin-bottom: 25px;">
                <img src="../assets/banner.jpg" alt="WiFiSentry Banner" style="width: 100%; max-height: 260px; object-fit: cover; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,242,254,0.25);" onerror="this.style.display='none'" />
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-title">Indice de Salud Inalambrica</div>
                    <div class="metric-value" style="color: {score_color};">{score} / 100</div>
                    <div class="metric-desc">Puntuacion de postura defensiva y riesgo del endpoint</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Perfiles Guardados</div>
                    <div class="metric-value" style="color: var(--cyan);">{total_count}</div>
                    <div class="metric-desc">Redes registradas en el servicio WLAN AutoConfig</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Redes en Vivo Detectadas</div>
                    <div class="metric-value" style="color: var(--purple);">{len(live_nets)}</div>
                    <div class="metric-desc">BSSIDs activos transmitiendo en el entorno radial</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Perfiles Criticos / Abiertos</div>
                    <div class="metric-value" style="color: var(--red);">{critical_count}</div>
                    <div class="metric-desc">Expuestas a clonacion Rogue AP y captura de trafico</div>
                </div>
            </div>

            <div class="section-box">
                <div class="section-header">
                    <h2>Estado Global de Seguridad Inalambrica</h2>
                </div>
                <p style="color: #cbd5e1; font-size: 0.95rem;">
                    Este informe fue generado de manera forense inspeccionando la configuracion WLAN del sistema.
                    Se evaluaron perfiles de red persistentes en Windows (protegidos mediante DPAPI), la presencia de puntos de acceso
                    en vivo transmitiendo en las inmediaciones y el grado de exposicion a ataques de clonacion <em>Evil Twin</em> y crackeo offline de contrasenas WPA2 mediante GPU clusters.
                </p>
                <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="tab-btn" onclick="openTab('tab-heatmap')" style="background: rgba(239,68,68,0.15); color: #ef4444; border-color: #ef4444;">Explorar Mapa de Calor en Vivo &rarr;</button>
                    <button class="tab-btn" onclick="openTab('tab-radar')" style="background: rgba(0,242,254,0.15); color: var(--cyan); border-color: var(--cyan);">Examinar Radar Evil Twin &rarr;</button>
                    <button class="tab-btn" onclick="openTab('tab-entropy')" style="background: rgba(139,92,246,0.15); color: var(--purple); border-color: var(--purple);">Auditar Entropia de Claves &rarr;</button>
                </div>
            </div>
        </div>

        <!-- TAB 2: MAPA DE CALOR ESPECTRAL -->
        <div id="tab-heatmap" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>🔥 Mapa de Calor Wi-Fi en Vivo (Sensor de Proximidad & RSSI Espectral)</h2>
                    <input type="text" id="filterHeatmapInput" class="search-bar" placeholder="Filtrar por SSID o BSSID..." onkeyup="filterHeatmapCards()">
                </div>
                <p style="color: var(--text-muted); font-size: 0.88rem; margin-bottom: 20px;">
                    Visualizacion termica de potencia de radiofrecuencia (RF) de todos los puntos de acceso detectados en las bandas 2.4 GHz y 5 GHz.
                    Permite identificar emisores fisicamente cercanos (&lt; 3 metros), posibles atacantes portatiles y saturacion de canales.
                </p>

                <div style="display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center;">
                    <button id="btnPulseSim" class="tab-btn" onclick="toggleHeatmapPulse()" style="background: rgba(239,68,68,0.15); color: #ef4444; border-color: #ef4444;">▶ Iniciar Pulso Termico en Vivo</button>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">Simula la fluctuacion de radiofrecuencia en tiempo real en el navegador</span>
                </div>

                <div class="heatmap-container">
{''.join(heatmap_cards)}
                </div>

                <div style="margin-top: 30px;">
                    <h3 style="color: var(--cyan); margin-bottom: 12px; font-size: 1.1rem;">Saturacion Termica por Canal (Carga Espectral RF)</h3>
                    <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-card); border-radius: 10px; padding: 18px;">
{''.join(spectrum_bars)}
                    </div>
                </div>

                <div class="educational-box" style="margin-top: 25px;">
                    <h3>Escala Termica y Diagnostico Forense de Proximidad</h3>
                    <ul>
                        <li><strong style="color: var(--heat-critical);">Zona Critica / Fuego (> 80% | > -50 dBm):</strong> Emisor a escasos metros o en el mismo habitaculo (&lt; 3m). Si es una red desconocida o clonada, indica presencia fisica inmediata de un atacante.</li>
                        <li><strong style="color: var(--heat-high);">Zona de Calor Alto (65% - 79% | -51 a -65 dBm):</strong> Cobertura optima y proximidad cercana (3 a 8 metros).</li>
                        <li><strong style="color: var(--heat-medium);">Zona Templada (45% - 64% | -66 a -75 dBm):</strong> Alcance normal de router domestico o empresarial a traves de 1 o 2 paredes (8 a 15 metros).</li>
                        <li><strong style="color: var(--heat-low);">Zona Tibia / Lejana (25% - 44% | -76 a -85 dBm):</strong> Senal atenuada por multiples obstaculos (15 a 25 metros).</li>
                        <li><strong style="color: var(--heat-cold);">Zona Fria (&lt; 25% | &lt; -85 dBm):</strong> Limite de recepcion radial (&gt; 25 metros).</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- TAB 3: RADAR EVIL TWIN -->
        <div id="tab-radar" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>📡 Radar de Caza de Ataques Evil Twin & Rogue AP en Vivo</h2>
                    <input type="text" id="filterRadarInput" class="search-bar" placeholder="Filtrar por SSID o BSSID..." onkeyup="filterRadarTable()">
                </div>
                <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 15px;">
                    Compara en tiempo real las tramas beacon de los puntos de acceso cercanos con los perfiles autorizados y guardados en tu sistema para detectar suplantaciones y degradaciones maliciosas.
                </p>
                <div class="table-responsive">
                    <table id="radarTable">
                        <thead>
                            <tr>
                                <th>Nombre de Red (SSID)</th>
                                <th>BSSID (Direccion MAC AP)</th>
                                <th>Autenticacion</th>
                                <th>Canal</th>
                                <th>Senal</th>
                                <th>Estado Radar</th>
                                <th>Diagnostico Forense</th>
                            </tr>
                        </thead>
                        <tbody>
{''.join(tbody_radar)}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="educational-box">
                <h3>Como opera un ataque Evil Twin (Gemelo Malvado)?</h3>
                <ul>
                    <li><strong>Emision de Probe Requests:</strong> Los dispositivos emiten constantemente peticiones broadcast con el nombre de sus redes conocidas.</li>
                    <li><strong>Clonacion Inmediata:</strong> Los atacantes con herramientas como <em>Wi-Fi Pineapple</em> capturan el SSID y levantan un AP falso con potencia superior para que tu equipo se asocie de forma preferente.</li>
                    <li><strong>Degradacion a Red Abierta:</strong> Si tu red original es WPA2, el atacante puede forzar un punto abierto para capturar trafico mediante un portal cautivo falso que simule una actualizacion de router o login corporativo.</li>
                </ul>
            </div>
        </div>

        <!-- TAB 3: CALCULADORA DE ENTROPIA & CRACKEO -->
        <div id="tab-entropy" class="tab-content">
            <!-- WIDGET INTERACTIVO -->
            <div class="simulator-box">
                <h3 style="color: var(--cyan); margin-bottom: 6px;">Simulador Interactivo de Entropia & Estimacion de Crackeo (Hashcat)</h3>
                <p style="color: var(--text-muted); font-size: 0.85rem;">Prueba cualquier contrasena o frase de paso en tiempo real para evaluar su resistencia ante ataques de fuerza bruta asistidos por hardware GPU:</p>
                
                <input type="text" id="liveEntropyInput" class="sim-input" placeholder="Escribe cualquier contrasena o frase de paso de prueba..." oninput="simulateEntropy(this.value)">

                <div class="entropy-meter-wrap">
                    <div id="liveMeterFill" class="entropy-meter-fill"></div>
                </div>

                <div class="sim-stats-grid">
                    <div class="sim-stat-card">
                        <div id="simLen" class="sim-stat-val">0</div>
                        <div class="sim-stat-lbl">Longitud Caracteres</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simPool" class="sim-stat-val">0</div>
                        <div class="sim-stat-lbl">Variedad (Pool)</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simBits" class="sim-stat-val">0.0 b</div>
                        <div class="sim-stat-lbl">Entropia Estimada</div>
                    </div>
                    <div class="sim-stat-card">
                        <div id="simClass" class="sim-stat-val" style="font-size: 1rem;">Vacio</div>
                        <div class="sim-stat-lbl">Nivel de Fortaleza</div>
                    </div>
                </div>

                <div class="crack-grid">
                    <div class="crack-card">
                        <div class="crack-hw">CPU Multi-Core</div>
                        <div class="crack-rate">30 kH/s</div>
                        <div id="simCpuTime" class="crack-time">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">NVIDIA RTX 3060</div>
                        <div class="crack-rate">350 kH/s</div>
                        <div id="sim3060Time" class="crack-time">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">NVIDIA RTX 4090</div>
                        <div class="crack-rate">2.4 MH/s</div>
                        <div id="sim4090Time" class="crack-time" style="color: var(--cyan);">&lt; 1 seg</div>
                    </div>
                    <div class="crack-card">
                        <div class="crack-hw">Cluster Cloud (8x 4090)</div>
                        <div class="crack-rate">19.2 MH/s</div>
                        <div id="simClusterTime" class="crack-time" style="color: var(--green);">&lt; 1 seg</div>
                    </div>
                </div>
            </div>

            <!-- TABLA DE CLAVES GUARDADAS -->
            <div class="section-box">
                <div class="section-header">
                    <h2>Auditoria de Entropia de Redes Almacenadas en este Equipo</h2>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>SSID</th>
                                <th>Longitud</th>
                                <th>Pool</th>
                                <th>Entropia</th>
                                <th>Patron Detectado</th>
                                <th>CPU (30k)</th>
                                <th>RTX 3060 (350k)</th>
                                <th>RTX 4090 (2.4M)</th>
                                <th>Cluster 8x GPU</th>
                            </tr>
                        </thead>
                        <tbody>
{''.join(tbody_entropy)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>



        <!-- TAB 5: INVENTARIO FORENSE -->
        <div id="tab-profiles" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>Inventario Forense de Perfiles Guardados (Cache DPAPI)</h2>
                    <input type="text" id="filterProfilesInput" class="search-bar" placeholder="Buscar por SSID, seguridad o riesgo..." onkeyup="filterProfilesTable()">
                </div>
                <div class="table-responsive">
                    <table id="profilesTable">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>SSID</th>
                                <th>Autenticacion</th>
                                <th>Cifrado</th>
                                <th>Conexion</th>
                                <th>Clave en Claro (DPAPI)</th>
                                <th>Riesgo</th>
                                <th>Diagnostico Forense</th>
                            </tr>
                        </thead>
                        <tbody>
{''.join(tbody_profiles)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 6: MANUAL & CHEATSHEET -->
        <div id="tab-hardening" class="tab-content">
            <div class="section-box">
                <div class="section-header">
                    <h2>Manual Didactico de Hardening & Cheatsheet Multiplataforma</h2>
                </div>

                <div style="text-align: center; margin: 15px 0;">
                    <img src="../assets/wifi_threat_matrix.jpg" alt="Matriz de Riesgo Inalambrico" style="max-width: 100%; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.7);" onerror="this.style.display='none'" />
                </div>

                <div class="educational-box">
                    <h3>Reglas de Oro de Seguridad Inalambrica</h3>
                    <ul>
                        <li><strong>Bloqueo Inmediato de Pantalla (Windows + L):</strong> En 10 segundos, un atacante con acceso fisico a tu ordenador desbloqueado puede ejecutar <code>netsh wlan show profile name="X" key=clear</code> y obtener tus contrasenas Wi-Fi personales y de la empresa.</li>
                        <li><strong>Eliminacion Periodica de Redes Antiguas:</strong> Borra perfiles de hoteles, aeropuertos y cafeterias ejecutando <code>netsh wlan delete profile name="NombreRed"</code> en consola como Administrador.</li>
                        <li><strong>Desactivar Conexion Automatica:</strong> En redes no corporativas, establece el modo de conexion en manual con <code>netsh wlan set profileparameter name="Nombre" connectionmode=manual</code> para evitar que tu PC emita Probe Requests en publico.</li>
                        <li><strong>Uso de Passphrases (>16 caracteres):</strong> La complejidad en WPA2 debe ser de longitud. Una frase de 4 palabras aleatorias ofrece mas de 75 bits de entropia y resiste ataques de supercomputadoras por siglos.</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generado de forma automatizada por <strong>WiFiSentry v1.2</strong> | Ecosistema DFIR Cru9 | <a href="https://github.com/Cru9" target="_blank">github.com/Cru9</a></p>
            <p style="margin-top: 5px; opacity: 0.6;">Fecha de auditoria forense: {fecha_str}</p>
        </div>

    </div>

    <script>
        function openTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(tb => tb.classList.remove('active'));
            const target = document.getElementById(tabId);
            if (target) target.classList.add('active');
            event.currentTarget.classList.add('active');
        }}

        function toggleKey(btn) {{
            const cell = btn.parentElement;
            const masked = cell.querySelector('.masked-key');
            const revealed = cell.querySelector('.revealed-key');
            if (masked.style.display === 'none') {{
                masked.style.display = 'inline';
                revealed.style.display = 'none';
                btn.textContent = '[Ver]';
            }} else {{
                masked.style.display = 'none';
                revealed.style.display = 'inline';
                btn.textContent = '[Ocultar]';
            }}
        }}

        function copyKey(btn) {{
            const text = btn.getAttribute('data-key');
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {{
                const orig = btn.textContent;
                btn.textContent = 'Copiado!';
                setTimeout(() => {{ btn.textContent = orig; }}, 1500);
            }});
        }}

        function filterProfilesTable() {{
            const input = document.getElementById('filterProfilesInput').value.toLowerCase();
            const rows = document.querySelectorAll('#profilesTable tbody tr');
            rows.forEach(row => {{
                row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none';
            }});
        }}

        let pulseInterval = null;
        function toggleHeatmapPulse() {{
            const btn = document.getElementById('btnPulseSim');
            if (pulseInterval) {{
                clearInterval(pulseInterval);
                pulseInterval = null;
                btn.textContent = '▶ Iniciar Pulso Termico en Vivo';
                btn.style.background = 'rgba(239,68,68,0.15)';
                btn.style.color = '#ef4444';
            }} else {{
                btn.textContent = '⏸ Detener Pulso en Vivo';
                btn.style.background = 'rgba(16,185,129,0.2)';
                btn.style.color = '#10b981';
                
                pulseInterval = setInterval(() => {{
                    document.querySelectorAll('.heat-card').forEach(card => {{
                        const baseSig = parseInt(card.getAttribute('data-signal')) || 50;
                        const delta = Math.floor(Math.random() * 9) - 4;
                        let curSig = Math.max(5, Math.min(100, baseSig + delta));
                        const rssi = Math.round((curSig / 2) - 100);
                        
                        const sigDisplay = card.querySelector('.heat-sig-display');
                        const rssiDisplay = card.querySelector('.heat-rssi-display');
                        const barFill = card.querySelector('.heat-bar-fill');
                        
                        if (sigDisplay) sigDisplay.textContent = curSig + '%';
                        if (rssiDisplay) rssiDisplay.textContent = rssi + ' dBm';
                        if (barFill) barFill.style.width = curSig + '%';
                    }});
                }}, 1600);
            }}
        }}

        function filterHeatmapCards() {{
            const q = document.getElementById('filterHeatmapInput').value.toLowerCase();
            document.querySelectorAll('.heat-card').forEach(card => {{
                const text = card.innerText.toLowerCase();
                card.style.display = text.includes(q) ? '' : 'none';
            }});
        }}

        function filterRadarTable() {{
            const input = document.getElementById('filterRadarInput').value.toLowerCase();
            const rows = document.querySelectorAll('#radarTable tbody tr');
            rows.forEach(row => {{
                row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none';
            }});
        }}

        function formatCrackTime(seconds) {{
            if (seconds < 1) return '< 1 seg';
            if (seconds < 60) return Math.round(seconds) + ' seg';
            if (seconds < 3600) return (seconds / 60).toFixed(1) + ' min';
            if (seconds < 86400) return (seconds / 3600).toFixed(1) + ' horas';
            if (seconds < 31536000) return (seconds / 86400).toFixed(1) + ' dias';
            const years = seconds / 31536000;
            if (years < 100) return years.toFixed(1) + ' anos';
            if (years < 1000) return Math.round(years) + ' anos';
            if (years < 1000000) return (years / 1000).toFixed(1) + 'k anos';
            return '+1 Millon de anos';
        }}

        function simulateEntropy(val) {{
            if (!val) {{
                document.getElementById('simLen').textContent = '0';
                document.getElementById('simPool').textContent = '0';
                document.getElementById('simBits').textContent = '0.0 b';
                document.getElementById('simClass').textContent = 'Vacio';
                document.getElementById('simClass').style.color = '#94a3b8';
                document.getElementById('liveMeterFill').style.width = '0%';
                document.getElementById('simCpuTime').textContent = '< 1 seg';
                document.getElementById('sim3060Time').textContent = '< 1 seg';
                document.getElementById('sim4090Time').textContent = '< 1 seg';
                document.getElementById('simClusterTime').textContent = '< 1 seg';
                return;
            }}

            const len = val.length;
            let pool = 0;
            if (/[a-z]/.test(val)) pool += 26;
            if (/[A-Z]/.test(val)) pool += 26;
            if (/[0-9]/.test(val)) pool += 10;
            if (/[^a-zA-Z0-9]/.test(val)) pool += 33;
            if (pool === 0) pool = 10;

            const bits = (len * (Math.log(pool) / Math.log(2))).toFixed(1);
            document.getElementById('simLen').textContent = len;
            document.getElementById('simPool').textContent = pool + ' chars';
            document.getElementById('simBits').textContent = bits + ' bits';

            const fill = document.getElementById('liveMeterFill');
            const classEl = document.getElementById('simClass');
            const pct = Math.min(Math.round((bits / 85) * 100), 100);
            fill.style.width = pct + '%';

            if (bits < 40) {{
                classEl.textContent = 'Critica / Muy Debil';
                classEl.style.color = 'var(--red)';
            }} else if (bits < 60) {{
                classEl.textContent = 'Moderada';
                classEl.style.color = 'var(--yellow)';
            }} else if (bits < 80) {{
                classEl.textContent = 'Robusta';
                classEl.style.color = 'var(--green)';
            }} else {{
                classEl.textContent = 'Nivel Militar / Solida';
                classEl.style.color = 'var(--cyan)';
            }}

            const safeExp = Math.min(len, 16);
            let combinations = Math.pow(pool, safeExp);
            if (len > 16) {{
                combinations = Math.pow(pool, 16) * Math.pow(10, Math.min(len - 16, 10));
            }}

            const secCpu = (combinations / 2) / 30000;
            const sec3060 = (combinations / 2) / 350000;
            const sec4090 = (combinations / 2) / 2400000;
            const secCluster = (combinations / 2) / 19200000;

            document.getElementById('simCpuTime').textContent = formatCrackTime(secCpu);
            document.getElementById('sim3060Time').textContent = formatCrackTime(sec3060);
            document.getElementById('sim4090Time').textContent = formatCrackTime(sec4090);
            document.getElementById('simClusterTime').textContent = formatCrackTime(secCluster);
        }}
    </script>
</body>
</html>
"""

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
    parser = argparse.ArgumentParser(description="WiFiSentry v1.2 | Suite de Auditoria WLAN DFIR")
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
