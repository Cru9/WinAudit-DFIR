# WinAudit-DFIR 🛡️📡
### Ecosistema Modular de Triage Forense y Detección de Amenazas en Windows
**Desarrollado por [Cru9](https://github.com/Cru9)**

[![GitHub release](https://img.shields.io/badge/Release-v2.0--Modular-blue.svg)](https://github.com/Cru9/WinAudit-DFIR)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg?logo=powershell)](https://github.com/Cru9/WinAudit-DFIR)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%2010%20%7C%2011%20%7C%20Server-0078D6.svg?logo=windows)](https://github.com/Cru9/WinAudit-DFIR)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Defensive-red.svg)](https://attack.mitre.org/)

---

## 🧭 Visión General del Proyecto

**WinAudit-DFIR** es un repositorio maestro y suite modular diseñada para analistas de **Blue Team**, especialistas en **DFIR** (Digital Forensics and Incident Response), auditores de seguridad y administradores de sistemas. 

El objetivo de este ecosistema es centralizar herramientas ligeras, de alta fidelidad y sin dependencias invasivas para diagnosticar, auditar y defender entornos Windows contra intrusiones tanto a nivel de sistema operativo como en el espectro de radiofrecuencia (Wi-Fi).

```
                            ┌─────────────────────────────────────────┐
                            │        WinAudit-DFIR Master Suite       │
                            │              (Cru9 / DFIR)              │
                            └────────────────────┬────────────────────┘
                                                 │
                    ┌────────────────────────────┴────────────────────────────┐
                    ▼                                                         ▼
    ┌───────────────────────────────┐                         ┌───────────────────────────────┐
    │   📁 Detección de Intrusos    │                         │        📁 WiFiSentry          │
    │   Triage Forense de Host      │                         │    Forense Inalámbrico        │
    ├───────────────────────────────┤                         ├───────────────────────────────┤
    │ • Eventos de Seguridad        │                         │ • Auditoría 802.11 / BSSID    │
    │ • Fuerza bruta RDP (4625)     │                         │ • Rogue AP / Evil Twin Hunter │
    │ • Anti-Forensics (1102)       │                         │ • Benchmark PBKDF2 (Hashcat)  │
    │ • Persistencia de Cuentas     │                         │ • Mapa de Calor RSSI en Vivo  │
    └───────────────────────────────┘                         └───────────────────────────────┘
```

---

## 🗂️ Módulos Integrados

### 1. 🛡️ [Detección de Intrusos](Detección%20de%20Intrusos/) — Triage Forense de Host y Persistencia
Especializado en la inspección automatizada y análisis forense del Visor de Eventos de Seguridad (`Security Log`) y Sistema (`System Log`) de Windows. Disponible en Python 3 (`IntruderDetector.py`) y PowerShell (`IntruderDetector.ps1`).
* **Inspección de Registros de Seguridad:** Detección de borrado intencional de logs (Anti-Forensics / Event ID 1102 y 104).
* **Vectores de Autenticación & Fuerza Bruta:** Rastreo de ataques de fuerza bruta y password spraying (Event ID 4625), clasificación de IPs atacantes y cuentas bloqueadas (4740).
* **Movimiento Lateral:** Detección de accesos RDP remotos interactivos (Event ID 4624 tipo 10) y sesiones SMB de red (tipo 3).
* **Persistencia y Elevación:** Identificación de creación anómala de usuarios o modificación de grupos de administradores (Event IDs 4720, 4732, 4728) mediante resolución robusta de SIDs (`S-1-5-32-544`).
* **Hunter de Comandos LOLBAS & Ransomware:** Detección de eliminación de copias de seguridad (`vssadmin delete shadows`), `certutil`, `powershell -enc` (Event ID 4688).
* **Radar SIEM en Tiempo Real:** Monitor continuo en vivo para alertar de intrusiones activas al instante.
* 🔗 *[Ver documentación detallada de Detección de Intrusos →](Detección%20de%20Intrusos/README.md)*

---

### 2. 📡 [WiFiSentry](WiFiSentry/) — Auditoría Forense Wi-Fi, Evil Twin Hunter & Mapa de Calor
Herramienta de nivel industrial para auditoría defensiva y análisis forense del espectro inalámbrico 802.11 en Windows.
* **Rogue AP Hunter (Evil Twin Radar):** Detección en tiempo real de suplantación de identidad Wi-Fi comparando BSSID (MAC), OUI de fabricantes, discrepancias de cifrado y anomalías de canal.
* **Calculadora de Entropía & Benchmark de Crackeo:** Estimación matemática de resistencia WPA2/WPA3 frente a ataques de diccionario y ataques masivos por GPU (clústeres Hashcat / RTX 4090).
* **Sensor de Proximidad & Heatmap Espectral:** Radar térmico en consola en vivo para rastrear fuentes emisoras mediante delta de señal ($\Delta \pm\%$), nivel RSSI estimado y saturación de canales.
* **Exportación Forense:** Generación de reportes ejecutivos en HTML interactivo (Glassmorphism cyberpunk) y volcados JSON/CSV estructurados.
* 🔗 *[Ver documentación detallada de WiFiSentry →](WiFiSentry/README.md)*

---

## 🎯 Cobertura con la Matriz MITRE ATT&CK®

| Módulo | Táctica MITRE | ID Técnica | Descripción / Detección |
| :--- | :--- | :--- | :--- |
| **Detección de Intrusos** | Defense Evasion | `T1070.001` | Clear Windows Event Logs (Vaciado de registro de auditoría 1102 / 104) |
| **Detección de Intrusos** | Credential Access | `T1110.001` | Password Guessing / Brute Force (Intentos de acceso fallidos 4625) |
| **Detección de Intrusos** | Lateral Movement | `T1021.001` | Remote Desktop Protocol (Sesiones interactivas RDP Tipo 10) |
| **Detección de Intrusos** | Persistence | `T1136.001` | Create Local Account (Creación de cuentas no autorizadas 4720) |
| **Detección de Intrusos** | Impact / Evasion | `T1490` | Inhibit System Recovery (Comandos vssadmin / wmic delete shadows 4688) |
| **Detección de Intrusos** | Persistence | `T1543.003` | Windows Service Creation (Nuevos servicios sospechosos 7045) |
| **WiFiSentry** | Discovery | `T1040` | Network Sniffing / Wi-Fi Reconnaissance |
| **WiFiSentry** | Credential Access | `T1110` | Brute Force (Estimación de crackeo de PSK WPA2/WPA3) |
| **WiFiSentry** | Initial Access | `T1557` | Adversary-in-the-Middle / Rogue AP (Ataques Evil Twin) |

---

## 🚀 Inicio Rápido

### Lanzador Maestro Unificado
Puedes ejecutar el lanzador central que te permitirá seleccionar qué herramienta inicializar con un solo clic:

```cmd
Suite-DFIR.bat
```

### Ejecución Independiente por Módulo

#### Para auditar eventos e intrusiones de Windows:
```cmd
cd "Detección de Intrusos"
.\Ejecutar-Deteccion.bat
```
*(O directamente mediante Python: `python "Detección de Intrusos\IntruderDetector.py"`)*

#### Para auditoría de redes inalámbricas:
```cmd
cd WiFiSentry
.\Ejecutar-WiFiSentry.bat
```
*(O directamente mediante Python: `python WiFiSentry\WiFiSentry.py`)*

---

## 📂 Estructura del Repositorio

```text
WinAudit-DFIR/
│
├── Suite-DFIR.bat                    # Lanzador interactivo centralizado
├── README.md                         # Documentación principal del ecosistema
├── LICENSE                           # Licencia MIT (Cru9)
├── .gitignore                        # Reglas de exclusión de git
│
├── 📁 Detección de Intrusos/         # MÓDULO 1: FORENSE DE HOST & EVENT LOGS
│   ├── IntruderDetector.py           # Core analítico en Python 3 (CLI + GUI Dashboard + SIEM)
│   ├── IntruderDetector.ps1          # Motor nativo avanzado en PowerShell 5.1+/7+
│   ├── Auditoria-Seguridad.ps1       # Script original retrocompatible
│   ├── Ejecutar-Deteccion.bat        # Lanzador inteligente multi-runtime con UAC
│   ├── Ejecutar-Auditoria.bat        # Script de compatibilidad
│   ├── Cerrar-Ventanas-Deteccion.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías de ciberseguridad
│   ├── Reportes/                     # Dashboard HTML y reportes de muestra
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de Detección de Intrusos
│
└── 📁 WiFiSentry/                    # MÓDULO 2: FORENSE INALÁMBRICO & SENSOR RF
    ├── WiFiSentry.py                 # Core analítico en Python (CLI + GUI Dashboard)
    ├── WiFiSentry.ps1                # Alternativa nativa en PowerShell 5.1+/7+
    ├── Ejecutar-WiFiSentry.bat       # Lanzador con selector automático de runtime
    ├── Cerrar-Ventanas-WiFiSentry.bat# Script de limpieza y detención de procesos
    ├── assets/                       # Banners e infografías de ciberseguridad
    ├── Reportes/                     # Dashboard HTML y reportes de muestra
    ├── SECURITY.md                   # Política de seguridad y divulgación
    ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
    └── README.md                     # Documentación completa de WiFiSentry
```

---

## 🛡️ Licencia y Reconocimientos

Este proyecto está distribuido bajo la licencia **MIT** - consulta el archivo [LICENSE](LICENSE) para más detalles.

**Autor:** [Cru9](https://github.com/Cru9)  
**Propósito:** Investigación en ciberseguridad, respuesta a incidentes (IR) y educación defensiva.
