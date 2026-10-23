#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAudit-DFIR v3.0.0 - Terminal Demo Generator
Autor: Ezequiel Diaz (Cru9) | https://github.com/Cru9
Genera la animacion en GIF y PNG representativa del orquestador Suite-DFIR.
"""

import os
from PIL import Image, ImageDraw, ImageFont

def create_terminal_gif():
    width = 960
    height = 560
    font_size = 14
    
    font_path = r"C:\Windows\Fonts\consola.ttf"
    if not os.path.exists(font_path):
        font_path = "consola.ttf"
        
    font = ImageFont.truetype(font_path, font_size)
    font_bold = ImageFont.truetype(r"C:\Windows\Fonts\consolab.ttf", font_size)
    font_title = ImageFont.truetype(font_path, 12)

    bg_color = (11, 15, 25)          # #0b0f19
    header_color = (19, 27, 46)      # #131b2e
    border_color = (30, 41, 59)      # #1e293b
    text_color = (203, 213, 225)     # #cbd5e1
    dim_color = (100, 116, 139)      # #64748b
    cyan_color = (56, 189, 248)      # #38bdf8
    green_color = (74, 222, 128)     # #4ade80
    red_color = (248, 113, 113)      # #f87171
    amber_color = (251, 191, 36)     # #fbbf24
    purple_color = (192, 132, 252)   # #c084fc

    base = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(base)

    # Window header
    draw.rectangle([(0, 0), (width, 36)], fill=header_color)
    draw.line([(0, 36), (width, 36)], fill=border_color, width=1)

    # Window controls
    draw.ellipse([(14, 11), (26, 23)], fill=(239, 68, 68))
    draw.ellipse([(34, 11), (46, 23)], fill=(245, 158, 11))
    draw.ellipse([(54, 11), (66, 23)], fill=(16, 185, 129))

    title = "Cru9 :: WinAudit-DFIR Suite v3.0.0 — [Incident Response & Forensic Console]"
    draw.text((width // 2 - 240, 10), title, font=font_title, fill=dim_color)

    steps = [
        # Step 0: Prompt
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "_"))
        ],
        # Step 1: Command typed
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "python Suite-DFIR.py"))
        ],
        # Step 2: Main Menu
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "python Suite-DFIR.py")),
            ((cyan_color, "+------------------------------------------------------------------------------------+"),),
            ((cyan_color, "|  WinAudit-DFIR Master Suite v3.0.0 "), (dim_color, "| Pure Console Engine (ISO/IEC 27037:2012)     |")),
            ((cyan_color, "+------------------------------------------------------------------------------------+"),),
            ((text_color, "  [1] Detección de Intrusos (Host Logs)     [6] UsbSentry (Almacenamiento & BadUSB)  "),),
            ((text_color, "  [2] WiFiSentry (RF & Evil Twin Hunter)    [7] ExecSentry (Prefetch, UserAssist, BAM)"),),
            ((text_color, "  [3] SocketSentry (Red & C2 Hunter)        [8] BrowserSentry (Web & Descargas)      "),),
            ((text_color, "  [4] DnsSentry (Caché DNS & Hosts)         [9] MemSentry (RAM & LSASS Guard)        "),),
            ((text_color, "  [5] StartupSentry (Persistencia/ASEP)                                              "),),
            ((cyan_color, "+------------------------------------------------------------------------------------+"),),
            ((amber_color, "  Cru9@WinAudit-DFIR [PYTHON-CORE] >> "), (cyan_color, "7"))
        ],
        # Step 3: ExecSentry Triage Running
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "python Suite-DFIR.py")),
            ((cyan_color, "======================================================================================"),),
            ((cyan_color, "  [+] ExecSentry v3.0.0 "), (dim_color, "| Evidencia Forense de Ejecución en Windows")),
            ((cyan_color, "======================================================================================"),),
            ((green_color, "  [+] Runtime: Python 3.12 (Standard Library - 0-pip) | Privilegios: Administrador"),),
            ((cyan_color, "  [*] Analizando artefactos: Prefetch (.pf), UserAssist ROT13, BAM/DAM y Shimcache..."),),
            ((dim_color, "      -> 184 entradas Prefetch parseadas | 42 claves UserAssist descifradas"),),
            ((amber_color, "      -> Correlacionando SID S-1-5-21-... con marcas de tiempo en registro BAM"),)
        ],
        # Step 4: Threat Detected
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "python Suite-DFIR.py")),
            ((cyan_color, "======================================================================================"),),
            ((cyan_color, "  [+] ExecSentry v3.0.0 "), (dim_color, "| Evidencia Forense de Ejecución en Windows")),
            ((cyan_color, "======================================================================================"),),
            ((cyan_color, "  [*] Analizando artefactos: Prefetch (.pf), UserAssist ROT13, BAM/DAM y Shimcache..."),),
            ((red_color, "  [!] ALERTA CRÍTICA [Score: 95/100] — Evidencia de Herramienta Ofensiva / Cred-Dumper:"),),
            ((red_color, "      Binario: mimikatz.exe | Ejecuciones: 2 | Última: 2026-10-23 03:14:22 UTC"),),
            ((amber_color, "      Ruta en Prefetch: C:\\Users\\Public\\Downloads\\mimikatz.exe-7B2F1A.pf"),),
            ((amber_color, "      Fuente: Windows BAM (Background Activity Moderator) | Usuario: Administrator"),),
            ((red_color, "      Estado en Disco: ELIMINADO (Intento de evasión / Anti-Forensics confirmado)"),)
        ],
        # Step 5: Custody & Report preservation
        [
            ((dim_color, "PS C:\\Forensics\\WinAudit-DFIR> "), (cyan_color, "python Suite-DFIR.py")),
            ((cyan_color, "======================================================================================"),),
            ((cyan_color, "  [+] ExecSentry v3.0.0 "), (dim_color, "| Evidencia Forense de Ejecución en Windows")),
            ((cyan_color, "======================================================================================"),),
            ((red_color, "  [!] ALERTA CRÍTICA: mimikatz.exe ejecutado desde C:\\Users\\Public (Binario eliminado)"),),
            ((green_color, "  [+] Custodia ISO/IEC 27037:2012: Preservación de evidencias en modo inmutable"),),
            ((green_color, "  [+] Evidencia JSON: ExecSentry/Reportes/ExecSentry_Report_20261023.json"),),
            ((green_color, "  [+] Hash SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),),
            ((green_color, "  [+] Evidencia CSV:  ExecSentry/Reportes/ExecSentry_Report_20261023.csv"),),
            ((cyan_color, "--------------------------------------------------------------------------------------"),),
            ((purple_color, "  [+] Telemetría Global: 9 Módulos Operativos | 0 Dependencias Externas"),),
            ((dim_color, "Cru9@WinAudit-DFIR [PYTHON-CORE] >> "), (cyan_color, "_"))
        ]
    ]

    durations = [800, 1000, 2200, 2500, 3500, 5000]

    frames = []
    for step_lines in steps:
        frame = base.copy()
        fdraw = ImageDraw.Draw(frame)
        y = 50
        line_height = 23
        for line in step_lines:
            x = 24
            for color, text in line:
                use_font = font_bold if (color in (red_color, cyan_color, amber_color, purple_color)) else font
                fdraw.text((x, y), text, font=use_font, fill=color)
                bbox = fdraw.textbbox((x, y), text, font=use_font)
                x = bbox[2]
            y += line_height
        frames.append(frame)

    output_dir = os.path.dirname(os.path.abspath(__file__))
    gif_path = os.path.join(output_dir, "terminal_demo.gif")
    png_path = os.path.join(output_dir, "terminal_demo.png")
    
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True
    )
    frames[-1].save(png_path)
    print(f"[OK] GIF generado en: {gif_path} ({os.path.getsize(gif_path)} bytes)")
    print(f"[OK] PNG generado en: {png_path} ({os.path.getsize(png_path)} bytes)")

if __name__ == "__main__":
    create_terminal_gif()
