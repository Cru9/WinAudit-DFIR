# WinAudit-DFIR 🛡️
### Herramienta Ligera de Detección de Intrusos y Triage Forense para Windows

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg?logo=powershell)](https://github.com/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%2010%20%7C%2011%20%7C%20Server-0078D6.svg?logo=windows)](https://github.com/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Defensive-red.svg)](https://attack.mitre.org/)

**WinAudit-DFIR** es un script en PowerShell diseñado para realizar una auditoría forense rápida y automatizada sobre el Registro de Eventos de Seguridad (`Security Log`) de Windows. Permite a analistas de Blue Team, administradores de sistemas y entusiastas de ciberseguridad responder a la pregunta: ***¿Alguien ha intentado o logrado entrar a este equipo?***

---

## 📌 Tabla de Contenidos
- [Características Principales](#-características-principales)
- [Mapeo con MITRE ATT&CK](#-mapeo-con-mitre-attck)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Requisitos](#-requisitos)
- [Instalación y Uso](#-instalación-y-uso)
  - [Opción 1: Lanzador Rápido (.bat)](#opción-1-lanzador-rápido-bat)
  - [Opción 2: Consola de PowerShell](#opción-2-consola-de-powershell)
- [Interpretación de Resultados](#-interpretación-de-resultados)
- [Mejores Prácticas y Limitaciones](#-mejores-prácticas-y-limitaciones)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)

---

## 🚀 Características Principales

- **100% Nativo sin dependencias externas:** Utiliza exclusivamente herramientas y APIs del sistema (`Get-WinEvent`).
- **Resiliente y agnóstico al idioma:** Resuelve el grupo de administradores mediante SID (`S-1-5-32-544`), funcionando indistintamente en Windows en español, inglés, francés, etc.
- **Parsing XML de Eventos:** Extrae propiedades (`IpAddress`, `TargetUserName`, `LogonType`) directamente de la estructura XML de cada evento, evitando discrepancias de índices entre distintas compilaciones de Windows.
- **Detección de Anti-Forensics:** Identifica si un atacante intentó vaciar los registros de auditoría para encubrir su rastro.
- **Salida visual clara:** Formato estructurado en tablas con código de colores según el nivel de severidad.

---

## 🎯 Mapeo con MITRE ATT&CK

| Fase | Event ID | Técnica / Táctica | Código MITRE | Qué Detecta |
|---|---|---|---|---|
| **Evasión** | `1102` | *Indicator Removal: Clear Windows Event Logs* | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Vaciado manual del log de seguridad (`wevtutil cl`). |
| **Acceso Inicial** | `4625` | *Brute Force / Password Spraying* | [T1110](https://attack.mitre.org/techniques/T1110/) | Intentos fallidos agrupados por IP y cuenta objetivo. |
| **Movimiento Lateral** | `4624` (Tipo 10) | *Remote Services: Remote Desktop Protocol* | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Conexiones interactivas remotas (RDP) exitosas. |
| **Movimiento Lateral** | `4624` (Tipo 3) | *Remote Services: SMB/Windows Admin Shares* | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Accesos a recursos compartidos de red desde otros equipos. |
| **Persistencia** | `4720` | *Create Account: Local Account* | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Creación de nuevas cuentas de usuario en el sistema. |
| **Escalada de Privilegios** | `4732` / `4728` | *Account Manipulation: Group Membership* | [T1098](https://attack.mitre.org/techniques/T1098/) | Inclusión de cuentas en grupos locales privilegiados. |

---

## 📂 Estructura del Proyecto

```text
├── Auditoria-Seguridad.ps1   # Script principal con la lógica de auditoría
├── Ejecutar-Auditoria.bat    # Lanzador directo con soporte UTF-8 y pausa de terminal
├── README.md                 # Documentación completa del proyecto
├── LICENSE                   # Licencia MIT
└── .gitignore                # Reglas de exclusión para control de versiones
```

---

## 📋 Requisitos

* **Sistema Operativo:** Windows 10, Windows 11 o Windows Server 2016+.
* **PowerShell:** Versión 5.1 o superior (PowerShell 7 admitido).
* **Privilegios:** Requiere **permisos de Administrador** para leer el canal `Security` del Visor de Eventos.

---

## 💻 Instalación y Uso

### Clonar el repositorio
```bash
git clone https://github.com/Cru9/WinAudit-DFIR.git
cd WinAudit-DFIR
```

### Opción 1: Lanzador Rápido (.bat)
1. Haz clic derecho sobre `Ejecutar-Auditoria.bat`.
2. Selecciona **"Ejecutar como administrador"**.
3. La auditoría se ejecutará y mantendrá la ventana abierta para que puedas revisar cómodamente los hallazgos.

### Opción 2: Consola de PowerShell
Abre una terminal de PowerShell con privilegios elevados (**Ejecutar como Administrador**) y ejecuta:

```powershell
# Ejecución estándar (audita los últimos 7 días)
powershell -ExecutionPolicy Bypass -File .\Auditoria-Seguridad.ps1

# Auditoría personalizada (ejemplo: últimos 30 días, máximo 100 eventos)
powershell -ExecutionPolicy Bypass -File .\Auditoria-Seguridad.ps1 -DiasAtras 30 -MaxEventos 100
```

#### Parámetros Disponibles:
* `-DiasAtras [int]`: Ventana de tiempo a inspeccionar hacia el pasado (por defecto: `7`).
* `-MaxEventos [int]`: Límite máximo de eventos exitosos a desplegar en tabla (por defecto: `50`).

---

## 🔍 Interpretación de Resultados

* **`[OK]` en Verde:** No se registraron anomalías en esa categoría durante la ventana de tiempo evaluada.
* **`[!]` o `[ALERTA]` en Amarillo:** 
  * Intentos fallidos aislados desde la IP `127.0.0.1` o IPs locales (`192.168.x.x`) suelen deberse a errores de tipeo del usuario o servicios internos.
  * Inicios de sesión de red tipo 3 son habituales si compartes impresoras o carpetas en tu red local.
* **`[ALERTA CRÍTICA]` en Rojo:**
  * **Borrado de registros (1102):** Acción sumamente sospechosa que suele indicar encubrimiento deliberado.
  * **Sesiones RDP (Tipo 10) desde IPs públicas desconocidas:** Posible compromiso de credenciales.
  * **Usuarios creados (`4720`) desconocidos:** Evidencia clara de tácticas de persistencia.

---

## ⚠️ Mejores Prácticas y Limitaciones

1. **Tamaño del Registro de Eventos:**
   En instalaciones estándar de Windows cliente, el tamaño máximo de `Security.evtx` es de 20 MB. Bajo un ataque de fuerza bruta masivo, los eventos antiguos pueden sobrescribirse rápidamente. Si administras entornos corporativos, configura el tamaño a mínimo 100-500 MB o centraliza los logs en un SIEM (Splunk, Elastic, Sentinel).
2. **Políticas de Auditoría Avanzadas:**
   Para asegurar que todos los eventos `4625`, `4720` y `4732` se generen, verifica que las directivas de auditoría de Windows estén activadas en `secpol.msc` (*Configuración de seguridad -> Directivas locales -> Directiva de auditoría*).
3. **Escritorio Remoto (RDP):**
   Nunca expongas el puerto `3389` directamente a Internet. Utiliza siempre una VPN con autenticación de dos factores (2FA).

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si deseas añadir nuevas reglas de detección (por ejemplo: eventos Sysmon, PowerShell script block logging `4104` o servicios nuevos `7045`):
1. Haz un Fork del proyecto.
2. Crea una rama para tu feature (`git checkout -b feature/NuevaDeteccion`).
3. Realiza tus cambios y haz commit (`git commit -m 'Añade detección de nuevo servicio'`).
4. Sube la rama (`git push origin feature/NuevaDeteccion`).
5. Abre un Pull Request.

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---
*Desarrollado para la comunidad de Ciberseguridad y Blue Team.*
