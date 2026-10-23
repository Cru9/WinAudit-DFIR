# 🛡️ Capítulo 2: Detección de Intrusos (Host & Event Logs)

El módulo **IntruderDetector** (`Detección de Intrusos`) es el especialista forense de host y análisis de eventos de seguridad de la suite **WinAudit-DFIR**. Su objetivo primordial es reconstruir la línea de tiempo de cualquier intento de vulneración en una máquina Windows analizando el registro de eventos de Seguridad (`Security Log`) y Sistema (`System Log`).

---

## 🔍 Catálogo Forense de Event IDs Analizados

El motor inspecciona y correlaciona de forma automatizada los identificadores de eventos críticos definidos por Microsoft:

| Event ID | Canal / Registro | Táctica MITRE ATT&CK | Descripción Técnica Forense |
| :---: | :---: | :---: | :--- |
| **`1102`** | Security | Anti-Forensics (`T1070.001`) | **Vaciado del registro de auditoría de seguridad.** Indica un intento deliberado por parte de un intruso o malware de eliminar evidencias de su actividad. |
| **`104`** | System | Anti-Forensics (`T1070.001`) | **Vaciado del registro de eventos del sistema.** Alerta cuando se eliminan logs de servicios y drivers. |
| **`4625`** | Security | Credential Access (`T1110.001`) | **Intento fallido de inicio de sesión.** Utilizado para identificar ataques de fuerza bruta, ataques de diccionario o *password spraying*. |
| **`4740`** | Security | Impact / Account Lockout | **Cuenta de usuario bloqueada.** Consecuencia directa de exceder el umbral de intentos fallidos de autenticación. |
| **`4624`** | Security | Lateral Movement (`T1021.001`) | **Inicio de sesión exitoso.** El módulo filtra específicamente sesiones remotas: **Tipo 10 (RDP / Escritorio Remoto)** y **Tipo 3 (Acceso por Red / SMB)**. |
| **`4720`** | Security | Persistence (`T1136.001`) | **Creación de cuenta de usuario local.** Detecta puertas traseras (*backdoors*) creadas por atacantes. |
| **`4732` / `4728`** | Security | Privilege Escalation (`T1098`) | **Adición de un usuario a un grupo de seguridad privilegiado.** Rastrea si un usuario estándar fue promovido al grupo Administradores. |
| **`7045`** | System | Persistence (`T1543.003`) | **Nuevo servicio instalado en el sistema.** Técnica común de propagación de ransomware, actores APT y herramientas como PsExec. |
| **`4688`** | Security | Execution / LOLBAS (`T1490`) | **Creación de proceso con línea de comandos.** Detecta destrucción de copias de seguridad (`vssadmin delete shadows`), descargas con `certutil` o PowerShell ofuscado. |

---

## 👥 Auditoría Agnóstica de Administradores Locales (SID Universal)

Un error habitual en herramientas de seguridad es buscar literalmente el grupo `"Administradores"` en PowerShell o CMD. Si el sistema operativo fue instalado en inglés, el grupo se llama `"Administrators"`; en francés, `"Administrateurs"`.

Para evitar falsos negativos en entornos multinacionales, **IntruderDetector** utiliza el **Identificador de Seguridad (SID) Universal de Windows**:

$$\text{SID: } \mathbf{S\text{-}1\text{-}5\text{-}32\text{-}544}$$

Este identificador es inmutable en cualquier edición o idioma de Windows NT, garantizando que el análisis de cuentas privilegiadas sea 100% certero.

---

## 💻 Modos de Uso y Comandos

### 1. Vía Lanzador Batch (Modo Automático Recomendado)
Doble clic en:
```cmd
Ejecutar-Deteccion.bat
```
El script eleva privilegios mediante UAC y detecta si Python 3 está disponible.

### 2. Motor Python 3 (CLI Interactivo y Automatizado)
Desde una consola con privilegios de Administrador:

```cmd
cd "Detección de Intrusos"

# Menú interactivo completo
python IntruderDetector.py

# Modo desatendido / headless: Auditoría de los últimos 7 días con reportes
python IntruderDetector.py --scan --days 7 --json --csv --html

# Iniciar Radar de Intrusiones en Vivo (SIEM Live Tail)
python IntruderDetector.py --live
```

### 3. Motor Nativo en PowerShell
Ideal para servidores donde no está permitido instalar software adicional:

```powershell
cd "Detección de Intrusos"

# Ejecución estándar con ventana de tiempo de 7 días
.\IntruderDetector.ps1 -DiasAtras 7

# Análisis extendido de 30 días con límite de 1000 eventos
.\IntruderDetector.ps1 -DiasAtras 30 -MaxEventos 1000
```

---

## 📡 Radar SIEM en Tiempo Real (Live Tail Monitoring)

Al activar la opción de **Radar en Tiempo Real** (`--live` o selección interactiva `[6]`), el módulo se suscribe al flujo de eventos del núcleo de Windows mediante una cola de escucha asíncrona:

* Cada vez que un atacante intenta autenticarse por RDP, falla una contraseña o se ejecuta un comando malicioso, la pantalla emite una alerta cromática instantánea con el detalle de la IP de origen, usuario afectado y código de error.
* En consolas compatibles, se reproduce una señal sonora (*beep* de advertencia) para alertar al analista durante guardias SOC o pruebas de penetración activas.

---

## 📊 Salidas y Evidencias Forenses

Todos los resultados se almacenan con sellos de tiempo ISO en la carpeta `Reportes/`:
1. **`IntruderDetector_Dashboard_*.html`:** Dashboard Cyberpunk Glassmorphism con KPIs de severidad, gráficas de autenticación y buscador interactivo.
2. **`IntruderDetector_Audit_*.json`:** Estructura de datos completa lista para ser importada por ElasticSearch, Splunk o el motor maestro de Cru9.
3. **`IntruderDetector_Reporte_*.csv`:** Tabla de eventos formateada para análisis masivo en hojas de cálculo.
