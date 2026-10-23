# WinAudit-DFIR 🛡️📡
### Ecosistema Modular de Triage Forense y Detección de Amenazas en Windows
**Desarrollado por [Cru9](https://github.com/Cru9)**

[![GitHub release](https://img.shields.io/badge/Release-v3.0.0-blue.svg)](https://github.com/Cru9/WinAudit-DFIR/releases)
[![CI](https://github.com/Cru9/WinAudit-DFIR/actions/workflows/ci.yml/badge.svg)](https://github.com/Cru9/WinAudit-DFIR/actions/workflows/ci.yml)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg?logo=powershell)](https://github.com/Cru9/WinAudit-DFIR)
[![Python](https://img.shields.io/badge/Python-3.8%2B%20(0--pip)-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%2010%20%7C%2011%20%7C%20Server-0078D6.svg?logo=windows)](https://github.com/Cru9/WinAudit-DFIR)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Defensive%20Ecosystem-red.svg)](https://attack.mitre.org/)
[![Custodia ISO](https://img.shields.io/badge/Custodia-ISO%2FIEC%2027037%3A2012-purple.svg)](#-cadena-de-custodia-e-integridad-forense)

![WinAudit-DFIR Master Banner](assets/master_banner.jpg)

<div align="center">
  <img src="assets/terminal_demo.gif" alt="WinAudit-DFIR Live Terminal Demo" width="100%" style="border-radius: 8px; margin: 15px 0; box-shadow: 0 4px 20px rgba(0,0,0,0.4);" />
  <p><em>Demostración en vivo: Orquestador maestro Suite-DFIR v3.0.0 interactivo con telemetría pericial en consola pura.</em></p>
</div>

---

## 🧭 Visión General del Proyecto

**WinAudit-DFIR** es un ecosistema forense modular y suite de investigación defensiva diseñada para analistas de **Blue Team**, especialistas en **DFIR** (Digital Forensics and Incident Response), auditores de seguridad y administradores de infraestructura Windows.

El propósito central de la suite es proporcionar capacidades periciales profundas de **alta fidelidad y cero dependencias externas (`0-pip`)** en terminal de consola. Permite auditar estaciones de trabajo y servidores Windows aislados de la red (*air-gapped*) o en entornos de respuesta ante incidentes activos sin alterar la integridad del sistema operativo ni romper la cadena de custodia.

```
                                    ┌─────────────────────────────────────────┐
                                    │        WinAudit-DFIR Master Suite       │
                                    │              (Cru9 / DFIR)              │
                                    └────────────────────┬────────────────────┘
                                                         │
         ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
         ▼                   ▼                   ▼                   ▼                   ▼
┌───────────────────┐┌───────────────────┐┌───────────────────┐┌───────────────────┐┌───────────────────┐
│Detección Intrusos ││    WiFiSentry     ││   SocketSentry    ││     DnsSentry     ││   StartupSentry   │
│  Forense de Host  ││Forense Inalámbrico││ Threat Hunter Red ││Caché DNS & Hosts  ││Persistencia/Firmas│
├───────────────────┤├───────────────────┤├───────────────────┤├───────────────────┤├───────────────────┤
│• Security Events  ││• Auditoría 802.11 ││• Sockets TCP/UDP  ││• Caché DNS RAM    ││• Win32_StartupCmd │
│• Fuerza Bruta 4625││• Rogue AP / Evil  ││• Balizas C2 Hunter││• Entropía DGA     ││• Claves Registry  │
│• Evasión Log 1102 ││• PBKDF2 Benchmark ││• Abuse Feodo IOCs ││• Túneles C2       ││• Tareas Raíz no-MS│
│• Logons RDP / SMB ││• Sensor Proximidad││• Catálogo LOLBins ││• Hosts Poisoning  ││• Authenticode Sign│
│• Radar SIEM Vivo  ││• Heatmap Señal RF ││• Volcado MiniDump ││• DNS por Interfaz ││• Masquerading Hunt│
└───────────────────┘└───────────────────┘└───────────────────┘└───────────────────┘└───────────────────┘
         │                                                                               │
         └───────────────────┬───────────────────┬───────────────────┬───────────────────┘
                             ▼                   ▼                   ▼                   ▼
                    ┌───────────────────┐┌───────────────────┐┌───────────────────┐┌───────────────────┐
                    │     UsbSentry     ││    ExecSentry     ││   BrowserSentry   ││     MemSentry     │
                    │Almacenamiento/Bad ││Evidencia Ejecución││Navegadores/Descarg││Procesos/LSASS PPL │
                    ├───────────────────┤├───────────────────┤├───────────────────┤├───────────────────┤
                    │• Historial USBSTOR││• Prefetch (*.pf)  ││• SQLite Triage    ││• Árbol de Procesos│
                    │• MountedDevices E:││• UserAssist ROT13 ││• Chrome/Edge/Firef││• Linaje Padre-Hijo│
                    │• BadUSB / Ducky   ││• BAM/DAM por SID  ││• Historial Web C2 ││• RunAsPPL Auditor │
                    │• Seriales Hardware││• Shimcache/Amcache││• Descargas Riego  ││• Comsvcs/ProcDump │
                    │• SetupAPI Forensic││• Binarios Borrados││• Extensiones Addon││• Unquoted Paths   │
                    └───────────────────┘└───────────────────┘└───────────────────┘└───────────────────┘
```

---

## 🗂️ Módulos Integrados

### 1. 🛡️ [Detección de Intrusos](Detección%20de%20Intrusos/) — Triage Forense de Host, Event Logs & SIEM Radar
Especializado en la inspección automatizada y análisis forense del Visor de Eventos de Seguridad (`Security Log`) y Sistema (`System Log`) de Windows.
* **Inspección de Registros de Seguridad:** Detección de borrado intencional de logs (Anti-Forensics / Event ID 1102 y 104).
* **Vectores de Autenticación & Fuerza Bruta:** Rastreo de ataques de fuerza bruta y password spraying (Event ID 4625), clasificación de IPs atacantes y cuentas bloqueadas (4740).
* **Movimiento Lateral:** Detección de accesos RDP remotos interactivos (Event ID 4624 tipo 10) y sesiones SMB de red (tipo 3).
* **Persistencia y Elevación:** Identificación de creación anómala de usuarios o modificación de grupos de administradores (Event IDs 4720, 4732, 4728) mediante resolución robusta de SIDs (`S-1-5-32-544`).
* **Nuevos Servicios del Sistema:** Detección de nuevos servicios instalados en el sistema operativo (Event ID 7045 en System Log / tácticas APT, PsExec y ransomware).
* **Hunter de Comandos LOLBAS & Ransomware:** Detección de eliminación de copias de seguridad (`vssadmin delete shadows`), `certutil`, `powershell -enc` (Event ID 4688).
* **Radar SIEM en Tiempo Real:** Monitor continuo en vivo (*Live Tail*) para alertar de intrusiones activas al instante con avisos visuales y sonoros.
* 🔗 *[Ver documentación detallada de Detección de Intrusos →](Detección%20de%20Intrusos/README.md)*

---

### 2. 📡 [WiFiSentry](WiFiSentry/) — Auditoría Forense Wi-Fi, Evil Twin Hunter & Mapa de Calor
Herramienta de nivel industrial para auditoría defensiva y análisis forense del espectro inalámbrico 802.11 en Windows.
* **Rogue AP Hunter (Evil Twin Radar):** Detección en tiempo real de suplantación de identidad Wi-Fi comparando BSSID (MAC), OUI de fabricantes, discrepancias de cifrado y anomalías de canal.
* **Calculadora de Entropía & Benchmark de Crackeo:** Estimación matemática de resistencia WPA2/WPA3 frente a ataques de diccionario y ataques masivos por GPU (clústeres Hashcat / RTX 4090).
* **Sensor de Proximidad & Heatmap Espectral:** Radar térmico en consola en vivo para rastrear fuentes emisoras mediante delta de señal ($\Delta \pm\%$), nivel RSSI estimado y saturación de canales.
* **Preservación Forense:** Exportación estructurada de perfiles WLAN auditados en JSON y CSV con marcas temporales.
* 🔗 *[Ver documentación detallada de WiFiSentry →](WiFiSentry/README.md)*

---

### 3. 🌐 [SocketSentry](SocketSentry/) — Framework Forense de Red, LOLBins y C2 Threat Hunting
Framework especializado en la inspección profunda de sockets de red y detección de actividad Command & Control (C2) en tiempo real.
* **Correlación de Sockets en Memoria:** Mapeo de conexiones TCP/UDP activas hacia procesos propietarios, rutas en disco y líneas de comando completas.
* **Threat Intelligence Integrada:** Sincronización con Abuse.ch Feodo Tracker (IPs C2 activas) y catálogo de más de 245 binarios LOLBAS.
* **Detección de Balizas C2 (*Beaconing*):** Algoritmo de análisis de cadencia temporal para identificar llamadas periódicas hacia infraestructuras de ataque.
* **Respuesta y Preservación Forense:** Generación de volcados de memoria volátil (`MiniDump`) y contención activa mediante bloqueo saliente en Windows Defender Firewall.
* 🔗 *[Ver documentación detallada de SocketSentry →](SocketSentry/README.md)*

---

### 4. 🌐 [DnsSentry](DnsSentry/) — Forense de Caché DNS, DGA Hunter & Manipulación de Hosts
Especializado en la extracción forense de la memoria caché de resolución DNS del sistema operativo y detección de persistencia por resolución de nombres.
* **Extracción de Caché DNS en RAM:** Captura en vivo de todos los registros DNS resueltos por aplicaciones y procesos en segundo plano.
* **Detección de Algoritmos DGA:** Cálculo de entropía matemática de Shannon ($H \ge 3.75$) para identificar dominios aleatorios de botnets y ransomware.
* **Caza de Túneles C2 y Fast-Flux:** Detección de servicios dinámicos (`duckdns.org`, `ngrok-free.app`, `serveo.net`, `trycloudflare.com`) y TLDs de alto riesgo.
* **Auditoría del Archivo Hosts:** Verificación de integridad con hash SHA-256 de `C:\Windows\System32\drivers\etc\hosts` para descubrir sinkholing de antivirus o redirecciones locales fraudulentas.
* 🔗 *[Ver documentación detallada de DnsSentry →](DnsSentry/README.md)*

---

### 5. 🚀 [StartupSentry](StartupSentry/) — Hunter de Persistencia en Inicio, Tareas Programadas y Firmas Authenticode
Framework forense especializado en el triage de mecanismos de persistencia en el arranque de Windows.
* **Auditoría de Auto-Arranque:** Inspección exhaustiva de `Win32_StartupCommand`, carpetas de inicio de usuario/sistema y claves de registro en `HKLM`/`HKCU:Run` y `RunOnce`.
* **Tareas Programadas en Raíz (`\`):** Detección de tareas programadas no pertenecientes a Microsoft y análisis de gatillos con intervalos recurrentes de alta frecuencia (`<= 30 min`).
* **Validación Criptográfica Authenticode:** Verificación automatizada de firmas digitales (`Valid`, `NotSigned`, `HashMismatch`), emisores y certificados.
* **Heurística Anti-Evasión:** Identificación de binarios alojados en `AppData`, `Temp`, `Users\Public`, suplantación de procesos del sistema (*Masquerading*) y LOLBins.
* 🔗 *[Ver documentación detallada de StartupSentry →](StartupSentry/README.md)*

---

### 6. 💾 [UsbSentry](UsbSentry/) — Forense de Dispositivos USB, Exfiltración Física y BadUSB Hunter
Framework forense especializado en la reconstrucción histórica de almacenamiento extraíble y detección de hardware malicioso.
* **Historial USBSTOR & Seriales de Hardware:** Extracción de fabricante, modelo, revisión y número de serie único de cada dispositivo conectado históricamente.
* **Correlación de Letras de Unidad (MountedDevices):** Mapeo forense de particiones y letras (`E:`, `F:`) asignadas en el sistema.
* **Caza de Dispositivos BadUSB:** Detección de inyectores de teclado maliciosos emulados (Hak5 Rubber Ducky, Bash Bunny, Flipper Zero, emuladores Arduino/Pico HID).
* **Marcas Temporales Forenses:** Recuperación del último evento de conexión/desconexión mediante `LastWriteTime` de registro y SetupAPI.
* 🔗 *[Ver documentación detallada de UsbSentry →](UsbSentry/README.md)*

---

### 7. ⚡ [ExecSentry](ExecSentry/) — Evidencia Forense de Ejecución en Windows (Prefetch, UserAssist & BAM)
Framework forense diseñado para reconstruir la cronología pericial exacta de programas y comandos ejecutados en el sistema operativo.
* **Windows Prefetch (`.pf`):** Extracción de nombres de ejecutables, conteo de ejecuciones, marcas temporales históricas y hashes de volumen.
* **UserAssist (Claves de Registro ROT13):** Decodificación de ejecución interactiva de usuario y accesos directos en el Explorador de Windows.
* **Background Activity Moderator (BAM/DAM):** Análisis cronológico por SID de usuario para corroborar fechas exactas de lanzamiento.
* **Caza de Binarios Eliminados:** Detección de programas que fueron ejecutados por atacantes y posteriormente eliminados del disco para eludir el análisis.
* 🔗 *[Ver documentación detallada de ExecSentry →](ExecSentry/README.md)*

---

### 8. 🌐 [BrowserSentry](BrowserSentry/) — Forense de Navegadores Web, Descargas y Extensiones
Framework forense enfocado en el análisis pericial del vector de acceso inicial y navegación web en entornos Windows.
* **Extracción SQLite en Caliente:** Lectura forense en vivo de bases de datos SQLite en Google Chrome, Microsoft Edge, Brave Browser, Opera y Mozilla Firefox sin requerir cerrar el navegador.
* **Historial de Descargas:** Reconstrucción de la cadena de descarga: archivo obtenido, URL de origen, ruta de guardado en disco y marca temporal.
* **Detección de Payloads Peligrosos:** Alertas sobre descargas de ejecutables (`.exe`, `.scr`, `.bat`), contenedores de disco (`.iso`, `.vhd`) para eludir MOTW y documentos ofimáticos con macros.
* **Auditoría de Extensiones:** Inventario de complementos de navegador instalados, permisos manifiestos y extensiones cargadas en modo desarrollador.
* 🔗 *[Ver documentación detallada de BrowserSentry →](BrowserSentry/README.md)*

---

### 9. 🛡️ [MemSentry](MemSentry/) — Forense de Procesos en RAM, Inyección & LSASS Guard
Framework forense de bajo nivel enfocado en la memoria volátil de procesos, anomalías de linaje y protección de credenciales de seguridad.
* **Árbol de Procesos y Linaje Padre-Hijo:** Mapeo de jerarquía de ejecución para descubrir anomalías graves (ej. Microsoft Word o Excel generando `powershell.exe` o `cmd.exe`).
* **Process Masquerading Hunter:** Detección de binarios con nombres del sistema (`svchost.exe`, `csrss.exe`, `lsass.exe`) ejecutándose desde ubicaciones ilegítimas fuera de `System32`.
* **LSASS Guard (Auditoría Anti-Credential Dumping):** Verificación del estado de protección `RunAsPPL` (Protected Process Light) y mitigación de volcado con Mimikatz / ProcDump / Comsvcs.
* **Unquoted Service Paths:** Auditoría automatizada de servicios de Windows configurados con rutas sin entrecomillar para prevenir escalamiento local de privilegios.
* 🔗 *[Ver documentación detallada de MemSentry →](MemSentry/README.md)*

---

## 🎯 Cobertura con la Matriz MITRE ATT&CK®

| Módulo | Táctica MITRE | ID Técnica | Descripción / Detección Forense |
| :--- | :--- | :--- | :--- |
| **Detección de Intrusos** | Defense Evasion | `T1070.001` | Clear Windows Event Logs (Vaciado de registro de auditoría 1102 / 104) |
| **Detección de Intrusos** | Credential Access | `T1110.001` | Password Guessing / Brute Force (Intentos de acceso fallidos 4625) |
| **Detección de Intrusos** | Lateral Movement | `T1021.001` | Remote Desktop Protocol (Sesiones interactivas RDP Tipo 10) |
| **Detección de Intrusos** | Persistence | `T1136.001` | Create Local Account (Creación de cuentas no autorizadas 4720) |
| **Detección de Intrusos** | Impact / Evasion | `T1490` | Inhibit System Recovery (Comandos vssadmin / wmic delete shadows 4688) |
| **Detección de Intrusos** | Persistence | `T1543.003` | Windows Service Creation (Nuevos servicios sospechosos 7045) |
| **WiFiSentry** | Discovery | `T1040` | Network Sniffing / Wi-Fi Reconnaissance |
| **WiFiSentry** | Credential Access | `T1110` | Brute Force (Estimación matemática de crackeo PBKDF2 WPA2/WPA3) |
| **WiFiSentry** | Initial Access | `T1557` | Adversary-in-the-Middle / Rogue AP (Ataques Evil Twin) |
| **SocketSentry** | Command and Control | `T1071.001` | Application Layer Protocol (Canales C2 sobre HTTP/HTTPS y puertos no estándar) |
| **SocketSentry** | Defense Evasion | `T1218` | System Binary Proxy Execution (Abuso de LOLBins en red) |
| **SocketSentry** | Command and Control | `T1571` | Non-Standard Port (Puertos de malware comunes 4444, 50050, 1337) |
| **SocketSentry** | Ingress Tool Transfer | `T1105` | Ingress Tool Transfer (Cradles de descarga con Certutil / PowerShell) |
| **DnsSentry** | Command and Control | `T1071.004` | DNS Application Protocol (Túneles C2, DuckDNS, Ngrok y exfiltración) |
| **DnsSentry** | Defense Evasion | `T1562.001` | Impair Defenses (Sinkholing malicioso en archivo Hosts contra antivirus) |
| **DnsSentry** | Defense Evasion | `T1565.001` | Stored Data Manipulation (Manipulación de resolución local en Hosts) |
| **DnsSentry** | Command and Control | `T1572` | Protocol Tunneling (DGA con alta entropía de Shannon) |
| **StartupSentry** | Persistence | `T1547.001` | Registry Run Keys / Startup Folder (Win32_StartupCommand y Run keys) |
| **StartupSentry** | Persistence / Execution | `T1053.005` | Scheduled Tasks (Tareas raíz no-MS e intervalos recurrentes <= 30 min) |
| **StartupSentry** | Defense Evasion | `T1553.002` | Subvert Trust Controls: Code Signing (Binarios NotSigned / HashMismatch) |
| **StartupSentry** | Defense Evasion | `T1036.005` | Masquerading: Match Legitimate Name (Binarios de sistema fuera de System32) |
| **UsbSentry** | Exfiltration | `T1052.001` | Exfiltration Over Physical Medium (Fuga de datos y exfiltración por USB) |
| **UsbSentry** | Initial Access / Execution | `T1200` | Hardware Additions (BadUSB / Rubber Ducky / Inyección de pulsaciones) |
| **UsbSentry** | Lateral Movement | `T1091` | Replication Through Removable Media (Propagación por memorias USB) |
| **UsbSentry** | Collection | `T1025` | Data from Removable Media (Acceso a particiones y archivos extraíbles) |
| **ExecSentry** | Execution | `T1204.002` | User Execution: Malicious File (Reconstrucción en UserAssist ROT13) |
| **ExecSentry** | Execution | `T1059` | Command and Scripting Interpreter (Evidencias Prefetch y BAM de cmd/ps1) |
| **ExecSentry** | Defense Evasion | `T1070.004` | Indicator Removal: File Deletion (Identificación de binarios borrados) |
| **ExecSentry** | Defense Evasion | `T1036.007` | Masquerading: Double Extension (Archivos con dobles extensiones falsificadas) |
| **BrowserSentry** | Initial Access | `T1566.002` | Phishing: Spearphishing Link (Rastreo de URLs visitadas y descargas) |
| **BrowserSentry** | Persistence | `T1176` | Browser Extensions (Extensiones no oficiales o en modo desarrollador) |
| **BrowserSentry** | Defense Evasion | `T1553.005` | Mark-of-the-Web Bypass (Descargas ISO/VHD para evadir SmartScreen) |
| **MemSentry** | Credential Access | `T1003.001` | LSASS Memory Dumping (Auditoría de RunAsPPL y comandos de volcado) |
| **MemSentry** | Defense Evasion | `T1055` | Process Injection (Padres anómalos y linaje sospechoso) |
| **MemSentry** | Privilege Escalation | `T1574.009` | Unquoted Service Paths (Servicios de Windows vulnerables a secuestro) |

---

## ⚖️ Cadena de Custodia e Integridad Forense

Siguiendo las directrices internacionales del estándar **ISO/IEC 27037:2012** (*Directrices para la identificación, recolección, adquisición y preservación de evidencia digital*) y las recomendaciones del **NIST SP 800-86**:

1. **Inmutabilidad y Criptografía:** Cada ejecución genera un informe pericial en formato estructurado (JSON y CSV) que incluye el hash criptográfico **SHA-256** del propio archivo y de los artefactos auditados.
2. **Preservación No Invasiva:** Las herramientas operan en modo de solo lectura sobre registros, memorias y archivos del sistema, minimizando la huella forense en el host auditado.
3. **Metadatos Temporales:** Todos los hallazgos registran marcas de tiempo estandarizadas en formato ISO 8601 con indicación del huso horario local.

---

## 🚀 Inicio Rápido

### Lanzador Maestro Unificado (Recomendado)
Puedes iniciar la consola interactiva centralizada que te permitirá seleccionar qué herramienta ejecutar o realizar diagnósticos globales con un solo clic:

```cmd
# Lanzador inteligente Batch (detecta Python / PowerShell y solicita UAC de forma limpia):
Suite-DFIR.bat

# O directamente mediante el orquestador Python puro (0-pip):
python Suite-DFIR.py
```

### Opciones de Línea de Comandos (CLI / Headless)
```powershell
# Ejecutar diagnóstico de salud de módulos y privilegios
python Suite-DFIR.py --health

# Visualizar resúmenes ejecutivos en consola sin interfaz gráfica
python Suite-DFIR.py --summaries

# Lanzar directamente un módulo específico (ej. ExecSentry)
python Suite-DFIR.py --module 7
```

### Ejecución Independiente por Módulo

#### 1. Detección de Intrusos (Host & Logs):
```cmd
cd "Detección de Intrusos"
.\Ejecutar-Deteccion.bat
```
*(O vía Python: `python "Detección de Intrusos\IntruderDetector.py"`)*

#### 2. WiFiSentry (Wireless 802.11):
```cmd
cd WiFiSentry
.\Ejecutar-WiFiSentry.bat
```
*(O vía Python: `python WiFiSentry\WiFiSentry.py`)*

#### 3. SocketSentry (Red & C2 Threat Hunting):
```cmd
cd SocketSentry
.\Ejecutar-SocketSentry.bat
```
*(O vía Python: `python SocketSentry\SocketSentry.py`)*

#### 4. DnsSentry (Caché DNS & Hosts):
```cmd
cd DnsSentry
.\Ejecutar-DnsSentry.bat
```
*(O vía Python: `python DnsSentry\DnsSentry.py`)*

#### 5. StartupSentry (Persistencia en Arranque):
```cmd
cd StartupSentry
.\Ejecutar-StartupSentry.bat
```
*(O vía Python: `python StartupSentry\StartupSentry.py`)*

#### 6. UsbSentry (Almacenamiento USB & BadUSB):
```cmd
cd UsbSentry
.\Ejecutar-UsbSentry.bat
```
*(O vía Python: `python UsbSentry\UsbSentry.py`)*

#### 7. ExecSentry (Evidencia de Ejecución):
```cmd
cd ExecSentry
.\Ejecutar-ExecSentry.bat
```
*(O vía Python: `python ExecSentry\ExecSentry.py`)*

#### 8. BrowserSentry (Navegadores & Descargas):
```cmd
cd BrowserSentry
.\Ejecutar-BrowserSentry.bat
```
*(O vía Python: `python BrowserSentry\BrowserSentry.py`)*

#### 9. MemSentry (RAM, Procesos & LSASS Guard):
```cmd
cd MemSentry
.\Ejecutar-MemSentry.bat
```
*(O vía Python: `python MemSentry\MemSentry.py`)*

---

## 📂 Estructura del Repositorio

```text
WinAudit-DFIR/
│
├── .github/                          # Automatización CI/CD y plantillas comunitarias
│   ├── workflows/ci.yml              # Pipeline de integración continua (Python & PowerShell)
│   ├── workflows/release-asset.yml   # Empaquetado automatizado de ZIPs para Releases
│   ├── ISSUE_TEMPLATE/               # Plantillas para bugs, features y aportes de IOCs
│   └── pull_request_template.md      # Plantilla estandarizada de Pull Requests
├── docs/                             # Documentación y manuales completos
│   └── wiki/                         # Suite completa de 12 capítulos sincronizada con GitHub Wiki
├── Suite-DFIR.bat                    # Lanzador interactivo centralizado en Batch
├── Suite-DFIR.py                     # Orquestador maestro forense en Python puro (0-pip)
├── README.md                         # Documentación principal del ecosistema
├── CONTRIBUTING.md                   # Normas de contribución y arquitectura
├── SECURITY.md                       # Política de divulgación responsable de vulnerabilidades
├── LICENSE                           # Licencia MIT (Cru9)
├── .gitignore                        # Reglas de exclusión de evidencias y temporales
├── 📁 assets/                        # Banners maestros y animación interactiva en GIF
│   ├── master_banner.jpg
│   ├── terminal_demo.gif
│   └── terminal_demo.png
│
├── 📁 Detección de Intrusos/         # MÓDULO 1: FORENSE DE HOST & EVENT LOGS
│   ├── IntruderDetector.py           # Core analítico en Python 3 (CLI ANSI + SIEM Radar)
│   ├── IntruderDetector.ps1          # Motor nativo avanzado en PowerShell 5.1+/7+
│   ├── Auditoria-Seguridad.ps1       # Script original retrocompatible
│   ├── Ejecutar-Deteccion.bat        # Lanzador inteligente multi-runtime con UAC
│   ├── Ejecutar-Auditoria.bat        # Script de compatibilidad
│   ├── Cerrar-Ventanas-Deteccion.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías de ciberseguridad
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de Detección de Intrusos
│
├── 📁 WiFiSentry/                    # MÓDULO 2: FORENSE INALÁMBRICO & SENSOR RF
│   ├── WiFiSentry.py                 # Core analítico en Python (CLI + Rogue AP + PBKDF2)
│   ├── WiFiSentry.ps1                # Alternativa nativa en PowerShell 5.1+/7+
│   ├── Ejecutar-WiFiSentry.bat       # Lanzador con selector automático de runtime
│   ├── Cerrar-Ventanas-WiFiSentry.bat# Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías de ciberseguridad
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de WiFiSentry
│
├── 📁 SocketSentry/                  # MÓDULO 3: THREAT HUNTING DE RED & C2
│   ├── SocketSentry.py               # Core analítico en Python 3 (CLI + Feodo C2 + Beaconing)
│   ├── SocketSentry.ps1              # Motor nativo avanzado en PowerShell 5.1+/7+
│   ├── Auditar-Conexiones.ps1        # Motor original forense y respuesta activa
│   ├── Ejecutar-SocketSentry.bat     # Lanzador inteligente multi-runtime con UAC
│   ├── Ejecutar-Auditoria-Red.bat    # Script de compatibilidad retrocompatible
│   ├── Cerrar-Ventanas-SocketSentry.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías de ciberseguridad
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de SocketSentry
│
├── 📁 DnsSentry/                     # MÓDULO 4: CACHÉ DNS & ARCHIVO HOSTS
│   ├── DnsSentry.py                  # Core analítico en Python 3 (CLI + DGA Shannon + Triage)
│   ├── DnsSentry.ps1                 # Motor nativo forense en PowerShell 5.1+/7+
│   ├── Ejecutar-DnsSentry.bat        # Lanzador inteligente multi-runtime con UAC
│   ├── Cerrar-Ventanas-DnsSentry.bat # Script de detención de procesos
│   ├── assets/                       # Banners e infografías HUD de red y DNS
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de DnsSentry
│
├── 📁 StartupSentry/                 # MÓDULO 5: PERSISTENCIA EN ARRANQUE & TAREAS
│   ├── StartupSentry.py              # Core analítico en Python 3 (CLI ANSI + ASEP Hunter)
│   ├── StartupSentry.ps1             # Motor forense nativo en PowerShell (Authenticode)
│   ├── Ejecutar-StartupSentry.bat    # Lanzador inteligente multi-runtime con UAC
│   ├── Cerrar-Ventanas-StartupSentry.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías HUD de ciberseguridad
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de StartupSentry
│
├── 📁 UsbSentry/                     # MÓDULO 6: ALMACENAMIENTO USB & BADUSB
│   ├── UsbSentry.py                  # Core analítico en Python 3 (CLI ANSI + USBSTOR)
│   ├── UsbSentry.ps1                 # Motor forense nativo en PowerShell 5.1+/7+
│   ├── Ejecutar-UsbSentry.bat        # Lanzador inteligente multi-runtime con UAC
│   ├── Cerrar-Ventanas-UsbSentry.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías HUD de almacenamiento
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de UsbSentry
│
├── 📁 ExecSentry/                    # MÓDULO 7: EVIDENCIA FORENSE DE EJECUCIÓN
│   ├── ExecSentry.py                 # Core analítico en Python 3 (Prefetch, UserAssist, BAM)
│   ├── ExecSentry.ps1                # Motor forense nativo en PowerShell 5.1+/7+
│   ├── Ejecutar-ExecSentry.bat       # Lanzador inteligente multi-runtime con UAC
│   ├── Cerrar-Ventanas-ExecSentry.bat# Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías HUD de ejecución
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de ExecSentry
│
├── 📁 BrowserSentry/                 # MÓDULO 8: FORENSE DE NAVEGADORES WEB
│   ├── BrowserSentry.py              # Core analítico en Python 3 (SQLite multi-navegador)
│   ├── BrowserSentry.ps1             # Motor forense nativo en PowerShell 5.1+/7+
│   ├── Ejecutar-BrowserSentry.bat    # Lanzador inteligente multi-runtime con UAC
│   ├── Cerrar-Ventanas-BrowserSentry.bat # Script de limpieza y detención de procesos
│   ├── assets/                       # Banners e infografías HUD de navegación
│   ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
│   ├── LICENSE                       # Licencia MIT
│   ├── SECURITY.md                   # Política de seguridad y divulgación
│   ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
│   └── README.md                     # Documentación completa de BrowserSentry
│
└── 📁 MemSentry/                     # MÓDULO 9: PROCESOS EN RAM & LSASS GUARD
    ├── MemSentry.py                  # Core analítico en Python 3 (Árbol de procesos, LSASS)
    ├── MemSentry.ps1                 # Motor forense nativo en PowerShell 5.1+/7+
    ├── Ejecutar-MemSentry.bat        # Lanzador inteligente multi-runtime con UAC
    ├── Cerrar-Ventanas-MemSentry.bat # Script de limpieza y detención de procesos
    ├── assets/                       # Banners e infografías HUD de memoria y procesos
    ├── Reportes/                     # Directorio de evidencias forenses (.gitkeep)
    ├── LICENSE                       # Licencia MIT
    ├── SECURITY.md                   # Política de seguridad y divulgación
    ├── CONTRIBUTING.md               # Guía para desarrolladores y colaboradores
    └── README.md                     # Documentación completa de MemSentry
```

---

## ⭐ Apoya el Proyecto

Si **WinAudit-DFIR** te ha resultado útil en tus auditorías, laboratorios o respuesta ante incidentes:
* Regálanos una **estrella ⭐ en GitHub** para ayudar a que más analistas de seguridad conozcan la suite.
* Comparte el proyecto en tus redes profesionales, foros de ciberseguridad o comunidades de analistas DFIR.
* Revisa [`CONTRIBUTING.md`](./CONTRIBUTING.md) para enviar sugerencias o nuevas reglas de detección.

---

## 🛡️ Licencia y Reconocimientos

Este proyecto está distribuido bajo la licencia **MIT** - consulta el archivo [LICENSE](LICENSE) para más detalles.

**Autor:** [Cru9](https://github.com/Cru9)  
**Propósito:** Investigación en ciberseguridad defensiva, respuesta a incidentes (DFIR) y educación técnica.
