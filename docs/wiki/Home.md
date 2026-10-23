# 🛡️ Bienvenido a la Wiki Oficial de WinAudit-DFIR

Bienvenido a la documentación técnica oficial y manual de operaciones de **WinAudit-DFIR**, una suite integral de **Respuesta a Incidentes Forenses (DFIR)**, **Threat Hunting** y **Auditoría de Seguridad** desarrollada por **[Cru9](https://github.com/Cru9)** para sistemas operativos Microsoft Windows.

---

## 🧭 ¿Qué es WinAudit-DFIR?

**WinAudit-DFIR** ha sido concebida desde sus cimientos para resolver una necesidad crítica de los equipos de seguridad defensiva (*Blue Team*), analistas SOC y peritos informáticos forenses: **disponer de capacidades analíticas avanzadas sin comprometer la integridad del entorno auditado**.

Muchas herramientas forenses modernas requieren pesadas dependencias de terceros, compiladores de C++ o conexión a internet para instalar módulos vía `pip` o gestores de paquetes. En un incidente real, un analista suele enfrentarse a **equipos aislados de la red (*air-gapped*)**, terminales con políticas restrictivas de ejecución o sistemas altamente comprometidos donde introducir binarios externos no verificados destruye la cadena de custodia.

Para solucionar esto, **WinAudit-DFIR** se rige por tres pilares arquitectónicos innegociables:

1. **Cero Dependencias Externas (`0 pip`):** Todo el núcleo analítico en Python funciona exclusivamente con la **Biblioteca Estándar de Python 3.8+**.
2. **Arquitectura Dual-Runtime:** Cada módulo cuenta con su motor nativo en **PowerShell 5.1+ / 7+** y su motor analítico en **Python 3**, complementados con lanzadores `.bat` inteligentes con auto-elevación UAC sin bucles.
3. **Privacidad Absoluta y Localidad:** Ningún dato, telemetría o evidencia sale del equipo auditado a menos que el usuario lo solicite expresamente.

---

## 🏛️ Mapa de la Suite Forense

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

## 📑 Índice de Capítulos de la Wiki

Explora los manuales temáticos haciendo clic en los siguientes enlaces:

| Capítulo | Módulo / Tópico | Descripción Técnica |
| :---: | :--- | :--- |
| **01** | [[Arquitectura & Filosofía 0-Pip\|01-Arquitectura-y-Filosofia-Zero-Pip]] | Principios de diseño forense, dual-runtime, compatibilidad de codificación y preservación de memoria. |
| **02** | [[Detección de Intrusos (Host & Logs)\|02-Deteccion-de-Intrusos-Manual-Forense]] | Análisis del Visor de Eventos de Seguridad (`Security Log`), fuerza bruta, RDP, anti-forensics y radar SIEM en vivo. |
| **03** | [[WiFiSentry (Forense Inalámbrico)\|03-WiFiSentry-Manual-de-Operaciones]] | Inspección del espectro 802.11, detección de Evil Twins, cálculo de entropía de contraseñas y sensor de proximidad RF. |
| **04** | [[SocketSentry (Threat Hunting de Red)\|04-SocketSentry-Threat-Hunting-de-Red]] | Correlación de sockets activos, IOCs de Abuse.ch Feodo Tracker, detección de beaconing C2, LOLBins y volcados de memoria. |
| **05** | [[StartupSentry (Persistencia en Inicio)\|05-StartupSentry-Triage-de-Persistencia]] | Auditoría de auto-arranque, tareas programadas en raíz, suplantación de procesos (*masquerading*) y firmas Authenticode. |
| **06** | [[Metodología Forense & Cadena de Custodia\|06-Metodologia-Forense-y-Cadena-de-Custodia]] | Cumplimiento del estándar NIST SP 800-86, orden de volatilidad (RFC 3227) y generación de hashes SHA-256 de evidencias. |
| **07** | [[Preguntas Frecuentes & Solución de Problemas\|07-Preguntas-Frecuentes-y-Troubleshooting]] | Guía de resolución de permisos UAC, ExecutionPolicy de PowerShell, consolas cp1252/UTF-8 y falsos positivos. |
| **08** | [[UsbSentry (Almacenamiento USB & BadUSB)\|08-UsbSentry-Forense-de-Dispositivos-USB]] | Reconstrucción histórica de USBSTOR, MountedDevices, letras de unidad asignadas y detección de hardware BadUSB. |
| **09** | [[ExecSentry (Evidencia de Ejecución)\|09-ExecSentry-Evidencia-de-Ejecucion]] | Reconstrucción temporal de programas ejecutados, decodificación ROT13 en UserAssist, BAM/DAM y análisis de Prefetch. |
| **10** | [[BrowserSentry (Forense Web & Descargas)\|10-BrowserSentry-Forense-de-Navegadores-y-Descargas]] | Auditoría SQLite multi-navegador (Chrome, Edge, Brave, Firefox), detección de descargas peligrosas y extensiones. |
| **11** | [[MemSentry (Procesos en RAM & LSASS Guard)\|11-MemSentry-Forense-de-Procesos-y-LSASS-Guard]] | Auditoría de procesos activos en vivo, árbol de linaje padre-hijo, blindaje RunAsPPL de LSASS y Unquoted Service Paths. |
| **12** | [[DnsSentry (Caché DNS & Hosts)\|12-DnsSentry-Cache-DNS-y-Hosts-Poisoning]] | Inspección de memoria caché DNS, detección de DGA por entropía, Fast-Flux, túneles C2 y sinkholes en archivo Hosts. |

---

## 🚀 Inicio Rápido

Para ejecutar la suite completa en cualquier máquina Windows (10, 11 o Server):

```cmd
git clone https://github.com/Cru9/WinAudit-DFIR.git
cd WinAudit-DFIR
Suite-DFIR.bat
```

> [!TIP]
> Puedes ejecutar `Suite-DFIR.bat` directamente haciendo doble clic desde el Explorador de Archivos de Windows. El script solicitará permisos de Administrador de manera limpia y presentará el centro de control interactivo.
