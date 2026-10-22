import os
from PIL import Image, ImageDraw, ImageFont

def create_terminal_gif():
    width = 960
    height = 540
    font_path = r"C:\Windows\Fonts\consola.ttf"
    font_size = 14
    font = ImageFont.truetype(font_path, font_size)
    font_bold = ImageFont.truetype(r"C:\Windows\Fonts\consolab.ttf", font_size)
    font_title = ImageFont.truetype(font_path, 12)

    # Color definitions
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

    # Pre-render window template
    base = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(base)

    # Window header
    draw.rectangle([(0, 0), (width, 36)], fill=header_color)
    draw.line([(0, 36), (width, 36)], fill=border_color, width=1)

    # Control buttons (macOS/Linux style)
    draw.ellipse([(14, 11), (26, 23)], fill=(239, 68, 68))    # Close
    draw.ellipse([(34, 11), (46, 23)], fill=(245, 158, 11))   # Minimize
    draw.ellipse([(54, 11), (66, 23)], fill=(16, 185, 129))   # Maximize

    # Title text
    title = "Cru9 :: WinAudit-DFIR Suite v1.2.1 — [Live Incident Response Console]"
    draw.text((width // 2 - 200, 10), title, font=font_title, fill=dim_color)

    frames = []

    # Text blocks for animation progression
    steps = [
        # Step 0: Blank prompt
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, "_"))
        ],
        # Step 1: Typing command
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, ".\\Suite-DFIR.bat"))
        ],
        # Step 2: Banner appears
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, ".\\Suite-DFIR.bat")),
            ((cyan_color, "=================================================================================="),),
            ((cyan_color, "  [+] WinAudit-DFIR Suite v1.2.1 "), (dim_color, "| Dual-Runtime Engine (Python 3 & PowerShell)")),
            ((cyan_color, "=================================================================================="),),
            ((text_color, "  [1] Detección de Intrusos (Host Forensics & Event Logs)"),),
            ((text_color, "  [2] WiFiSentry (RF Spectrum, Rogue AP & Evil Twin Hunter)"),),
            ((text_color, "  [3] SocketSentry (Live Sockets, C2 Beaconing & LOLBins)"),),
            ((cyan_color, "----------------------------------------------------------------------------------"),),
            ((amber_color, "  Selecciona una opcion [1, 2, 3]: "), (cyan_color, "3"))
        ],
        # Step 3: Module 3 launches
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, ".\\Suite-DFIR.bat")),
            ((cyan_color, "=================================================================================="),),
            ((cyan_color, "  [+] WinAudit-DFIR Suite v1.2 "), (dim_color, "| Dual-Runtime Engine (Python 3 & PowerShell)")),
            ((cyan_color, "=================================================================================="),),
            ((amber_color, "  Selecciona una opcion [1, 2, 3]: "), (cyan_color, "3")),
            ((text_color, ""),),
            ((green_color, "  [+] Runtime: Python 3.12 (Standard Library - 0 external pip dependencies)"),),
            ((purple_color, "  [+] Threat Intel: Abuse.ch Feodo Tracker (C2 Active) + LOLBAS Catalog (245+)"),),
            ((cyan_color, "  [*] [03:45:12] Escaneando sockets TCP/UDP activos y correlacionando WMI..."),),
            ((dim_color, "      -> Mapeados 47 sockets | 12 procesos evaluados contra base heuristica"),)
        ],
        # Step 4: Threat alert detected!
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, ".\\Suite-DFIR.bat")),
            ((cyan_color, "=================================================================================="),),
            ((cyan_color, "  [+] WinAudit-DFIR Suite v1.2.1 "), (dim_color, "| Dual-Runtime Engine (Python 3 & PowerShell)")),
            ((cyan_color, "=================================================================================="),),
            ((amber_color, "  Selecciona una opcion [1, 2, 3]: "), (cyan_color, "3")),
            ((green_color, "  [+] Runtime: Python 3.12 | Zero pip dependencies"),),
            ((cyan_color, "  [*] [03:45:12] Escaneando sockets TCP/UDP activos y correlacionando WMI..."),),
            ((dim_color, "      -> Mapeados 47 sockets | 12 procesos evaluados contra base heuristica"),),
            ((red_color, "  [!] ALERTA CRITICA [Score: 100/100] — Coincidencia C2 Feodo Tracker confirmada:"),),
            ((red_color, "      PID: 4912 | Proceso: powershell.exe (LOLBin) -> Destino: 178.62.3.223:443"),),
            ((amber_color, "      CommandLine: -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8..."),),
            ((amber_color, "      Frecuencia: Baliza C2 periodica (Beaconing detectado cada 15.2s +-0.3s)"),)
        ],
        # Step 5: Forensics & Active containment executed
        [
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, ".\\Suite-DFIR.bat")),
            ((cyan_color, "=================================================================================="),),
            ((cyan_color, "  [+] WinAudit-DFIR Suite v1.2.1 "), (dim_color, "| Dual-Runtime Engine (Python 3 & PowerShell)")),
            ((cyan_color, "=================================================================================="),),
            ((green_color, "  [+] Runtime: Python 3.12 | Zero pip dependencies"),),
            ((red_color, "  [!] ALERTA CRITICA [Score: 100/100] — Coincidencia C2 Feodo Tracker confirmada:"),),
            ((red_color, "      PID: 4912 | Proceso: powershell.exe (LOLBin) -> Destino: 178.62.3.223:443"),),
            ((amber_color, "      CommandLine: -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8..."),),
            ((green_color, "  [+] Preservacion Forense: MiniDump generado en /Reportes/powershell_4912.dmp"),),
            ((green_color, "  [+] Contencion Activa: Regla de bloqueo saliente creada en Windows Firewall"),),
            ((green_color, "  [+] Dashboard HTML: Reportes/SocketSentry_Dashboard_20261022.html [OK]"),),
            ((cyan_color, "----------------------------------------------------------------------------------"),),
            ((purple_color, "  [+] WiFiSentry Radar RF: 1 Rogue AP Detectado (Ataque Evil Twin en Canal 6)"),),
            ((dim_color, "      SSID: 'Red-Oficina' | BSSID: 98:03:8e:ff:51:cb (Clonado / Senal: 92%)"),),
            ((dim_color, "PS C:\\Incident-Response\\WinAudit-DFIR> "), (cyan_color, "_"))
        ]
    ]

    # Durations per step (in ms)
    durations = [800, 1000, 2000, 2200, 3200, 5000]

    for step_lines in steps:
        frame = base.copy()
        fdraw = ImageDraw.Draw(frame)
        y = 50
        line_height = 23
        for line in step_lines:
            x = 24
            for color, text in line:
                # Use bold font for alerts and banners
                use_font = font_bold if (color in (red_color, cyan_color, amber_color)) else font
                fdraw.text((x, y), text, font=use_font, fill=color)
                bbox = fdraw.textbbox((x, y), text, font=use_font)
                x = bbox[2]
            y += line_height
        frames.append(frame)

    output_path = os.path.join(os.path.dirname(__file__), "terminal_demo.gif")
    frames[0].save(
        output_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True
    )
    png_path = os.path.join(os.path.dirname(__file__), "terminal_demo.png")
    frames[-1].save(png_path)
    print(f"GIF generated successfully at: {output_path} ({os.path.getsize(output_path)} bytes)")
    print(f"PNG generated successfully at: {png_path} ({os.path.getsize(png_path)} bytes)")

if __name__ == "__main__":
    create_terminal_gif()
