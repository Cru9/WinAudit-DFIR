# 💾 Capítulo 8: UsbSentry (Forense de Almacenamiento & BadUSB)

**UsbSentry** es el módulo especializado en la reconstrucción forense del historial de dispositivos de almacenamiento extraíble (memorias USB, discos duros externos) y en la detección de hardware malicioso de inyección de pulsaciones (*BadUSB*, *Rubber Ducky*, *Bash Bunny*, *Flipper Zero*) en Windows.

---

## 🎯 ¿Por qué es Crítico el Forense de Dispositivos USB?

En investigaciones de incidentes de seguridad corporativa, los dispositivos USB intervienen frecuentemente en dos fases críticas de la cadena de ataque (*Cyber Kill Chain*):

1. **Acceso Inicial / Infección Física (`T1200`):** Ataques de ingeniería social (*USB Drop Attacks*) donde se dejan memorias infectadas en estacionamientos o recepciones, o dispositivos *BadUSB* que emulan teclados y ejecutan código malicioso en la terminal en cuestión de milisegundos.
2. **Exfiltración Física de Información (`T1052.001`):** Empleados desleales o atacantes con acceso físico que copian bases de datos, código fuente o propiedad intelectual hacia una memoria USB sin pasar por la red.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CAPACIDADES DE USBSENTRY                            │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. HISTORIAL USBSTOR          │ 2. CAZA DE BADUSB           │ 3. LETRAS     │
│ Vendor, Product, Rev y        │ Firmas de Rubber Ducky,     │ Mapeo con     │
│ Número de Serie de Hardware   │ Flipper Zero y emuladores   │ MountedDevices│
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

---

## 🔎 1. Artefactos Forenses Analizados

Windows registra cada dispositivo USB conectado en múltiples ramas del Registro y del sistema de archivos:

### A. Registro `HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR`
* Almacena cada dispositivo bajo la estructura:
  `Disk&Ven_<Fabricante>&Prod_<Modelo>&Rev_<Revisión>\<Número_de_Serie>`
* **Marca de Tiempo Forense (LastWriteTime):** Cada subclave de instancia almacena la fecha y hora exacta (estructura `FILETIME`) de la última modificación en el registro, que coincide con el evento de conexión o desconexión del dispositivo.

### B. Mapeo de Unidades `HKLM:\SYSTEM\MountedDevices`
* Los valores bajo `\DosDevices\` (ej. `\DosDevices\E:`, `\DosDevices\F:`) contienen cadenas Unicode con el identificador del dispositivo. UsbSentry correlaciona el número de serie para determinar **qué letra de unidad tuvo asignada históricamente la memoria USB** en el explorador de Windows.

### C. Detección en Vivo (`Win32_DiskDrive`)
* Consulta en tiempo real las unidades físicas montadas con interfaz USB para determinar si un dispositivo está **conectado en vivo en este preciso instante** (`LIVE`) y obtener su capacidad exacta en gigabytes.

---

## 🦆 2. Caza de Dispositivos BadUSB y Emuladores HID

Los dispositivos *BadUSB* (como el *Hak5 USB Rubber Ducky*, *Bash Bunny*, *Flipper Zero* o placas *Raspberry Pi Pico* / *Arduino Leonardo*) no se registran como memorias normales, sino como dispositivos de interfaz humana (teclados USB HID) para eludir los controles de bloqueo de puertos USB tradicionales.

UsbSentry inspecciona `HKLM:\SYSTEM\CurrentControlSet\Enum\USB` contrastando los descriptores con una base de firmas de hardware de intrusión física:

| Firma VID:PID | Dispositivo Identificado | Táctica MITRE ATT&CK | Nivel de Riesgo |
| :---: | :--- | :---: | :---: |
| **`0483:5740`** | Flipper Zero (Virtual COM / HID) | Hardware Additions (`T1200`) | 🔴 **CRÍTICO (Score: 95)** |
| **`1FC9:0003`** | Hak5 USB Rubber Ducky (NXP Chip) | Keystroke Injection (`T1200`) | 🔴 **CRÍTICO (Score: 100)** |
| **`F000:FFF0`** | Hak5 Bash Bunny Multi-Payload | Hardware Additions (`T1200`) | 🔴 **CRÍTICO (Score: 100)** |
| **`2341:8036`** | Arduino Leonardo (BadUSB Emulator) | Hardware Additions (`T1200`) | 🔴 **CRÍTICO (Score: 90)** |
| **`2E8A:0003`** | Raspberry Pi Pico (CircuitPython HID) | Keystroke Injection (`T1200`) | 🔴 **CRÍTICO (Score: 90)** |

---

## 🚦 3. Semáforo de Riesgo Heurístico

* 🟢 **CONFIABLE:** Memorias de fabricantes reconocidos con número de serie único válido.
* 🟡 **SOSPECHOSO:** Memorias sin número de serie de fábrica (caracteres `&0`, `&_&`), fabricantes genéricos o dispositivos conectados en las últimas 48 horas.
* 🔴 **CRÍTICO:** Coincidencia con firmas de BadUSB o dispositivos de inyección de teclado emulado.

---

## 💻 Modos de Uso

### 1. Lanzador Inteligente (.bat)
```cmd
cd UsbSentry
Ejecutar-UsbSentry.bat
```

### 2. Motor Python 3 (CLI Interactivo)
```powershell
python UsbSentry.py
```
Opciones:
* `[1]` Auditoría completa de dispositivos USB históricos y en vivo.
* `[2]` Filtrar solo dispositivos conectados actualmente (LIVE).
* `[3]` Filtrar solo dispositivos sospechosos / BadUSB Hunter.
* `[4]` Generación de Dashboard HTML Cyberpunk interactivo.
* `[5]` Exportación de evidencias a JSON y CSV.

### 3. Motor Nativo en PowerShell
```powershell
# Auditoría estándar en consola
powershell -ExecutionPolicy Bypass -File .\UsbSentry.ps1

# Filtrar únicamente sospechosos y BadUSB
powershell -ExecutionPolicy Bypass -File .\UsbSentry.ps1 -SoloSospechosos

# Exportación directa
powershell -ExecutionPolicy Bypass -File .\UsbSentry.ps1 -ExportarCSV "Reportes\usb.csv" -ExportarJSON "Reportes\usb.json"
```
