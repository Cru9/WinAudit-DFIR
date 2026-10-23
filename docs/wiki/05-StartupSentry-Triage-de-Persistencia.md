# 🚀 Capítulo 5: StartupSentry (Triage de Persistencia & Firmas)

**StartupSentry** es el módulo especializado en la detección, auditoría y neutralización de mecanismos de persistencia en el arranque de Windows, tareas programadas furtivas y validación criptográfica de firmas digitales **Authenticode**.

---

## 🎯 ¿Por qué es Crítico el Triage de Persistencia?

Cuando un adversario logra acceso a un endpoint, su primer objetivo tras la ejecución es **garantizar su supervivencia a reinicios del sistema operativo y cierres de sesión** (Táctica MITRE ATT&CK: **Persistence**).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VECTORES DE PERSISTENCIA DFIR                        │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. AUTO-ARRANQUE & REGISTRO   │ 2. TAREAS PROGRAMADAS RAÍZ  │ 3. FIRMAS     │
│ Win32_StartupCommand, Run keys│ Tareas en raíz (\) no-MS    │ Authenticode: │
│ y carpetas Startup con .LNK   │ y cadencias recurrentes     │ HashMismatch  │
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

---

## 🔎 1. Vectores de Persistencia Auditados

StartupSentry examina de forma exhaustiva cuatro vectores fundamentales:

### A. Clase CIM / WMI `Win32_StartupCommand`
* Recupera las aplicaciones registradas por el sistema operativo para iniciar automáticamente con el inicio de sesión de cualquier usuario.

### B. Claves Directas del Registro de Windows
Inspecciona directamente las ramas de registro más abusadas por actores de amenazas:
* `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

### C. Carpetas de Inicio (*Startup Folders*) y Resolución de `.LNK`
* `C:\Users\<Usuario>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
* `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
* **Resolución Forense de Accesos Directos:** Si en estas carpetas existe un archivo `.lnk`, el módulo no se limita a leer el nombre del archivo, sino que mediante el objeto COM `WScript.Shell` resuelve el **ejecutable de destino real**, sus argumentos ocultos y su ubicación en disco.

### D. Tareas Programadas en Raíz (`\`)
Windows contiene miles de tareas programadas legítimas bajo la rama `\Microsoft\Windows\...`. Muchos analistas omiten auditar tareas por el ruido excesivo.
StartupSentry aplica un filtro inteligente:
1. Inspecciona únicamente las tareas ubicadas en la **raíz del sistema (`\`)**.
2. Excluye fabricantes conocidos como Microsoft.
3. Examina los gatillos (*triggers*) de repetición: alerta de inmediato si una tarea está configurada para ejecutarse en intervalos periódicos de alta frecuencia ($\le 30$ minutos, ej. `PT5M`, `PT10M`, `PT15M`), una técnica clásica de balizas C2 y troyanos para reactivarse continuamente.

---

## 🔏 2. Validación Criptográfica de Firmas Authenticode

Para cada binario descubierto en el auto-arranque o en tareas programadas, StartupSentry ejecuta una validación de firma digital mediante la API de seguridad de Windows:

| Estado de Firma | Nivel de Riesgo | Significado Forense |
| :---: | :---: | :--- |
| **`Valid`** | 🟢 Confiable | El binario fue firmado por una entidad certificadora de confianza (Microsoft, Google, etc.) y su hash coincide exactamente con el certificado. |
| **`NotSigned`** | 🟡 Sospechoso | El ejecutable carece de firma digital. Si reside en rutas protegidas (`Program Files`) puede ser software legítimo antiguo; si reside en carpetas de usuario (`AppData`, `Temp`), requiere inspección inmediata. |
| **`HashMismatch`** | 🔴 **CRÍTICO** | **El binario fue modificado tras ser firmado digitalmente.** Este es el indicador definitivo de inyección de código malicioso, manipulación binaria o troyanización (*tampering*). |

---

## 🎭 3. Heurística Anti-Evasión (*Masquerading*)

El motor heurístico de StartupSentry evalúa patrones de camuflaje frecuentes:

1. **Suplantación de Identidad (*Masquerading* / `T1036.005`):**
   * Si un proceso se llama `svchost.exe`, `explorer.exe`, `lsass.exe` o `csrss.exe`, pero su ruta **NO** es `C:\Windows\System32` ni `C:\Windows\SysWOW64`, el sistema emite una alerta crítica instantánea.
2. **Rutas Anómalas:**
   * Binarios configurados para iniciar con el sistema que residen en `AppData\Local`, `AppData\Roaming`, `Temp`, `Users\Public` o `C:\ProgramData`.
3. **Líneas de Comandos Ofuscadas (LOLBins):**
   * Uso de cadenas codificadas en Base64 (`powershell -enc`), scripts VBScript/JScript invocados con `wscript` o llamadas a `mshta`.

---

## 💻 Modos de Uso

### 1. Lanzador Inteligente (.bat)
```cmd
cd StartupSentry
Ejecutar-StartupSentry.bat
```

### 2. Motor Python 3 (CLI Interactivo)
```powershell
python StartupSentry.py
```
Opciones:
* `[1]` Auditoría completa de auto-arranque y tareas programadas.
* `[2]` Filtrado exclusivo de elementos sospechosos y no firmados.
* `[3]` Auditoría profunda de tareas programadas en raíz (`\`).
* `[4]` Generación de Dashboard HTML Cyberpunk interactivo.
* `[5]` Exportar evidencias estructuradas a JSON y CSV.

### 3. Motor Nativo en PowerShell
```powershell
# Ejecución completa
powershell -ExecutionPolicy Bypass -File .\StartupSentry.ps1

# Filtrar únicamente sospechosos
powershell -ExecutionPolicy Bypass -File .\StartupSentry.ps1 -SoloSospechosos

# Exportación directa a CSV y JSON
powershell -ExecutionPolicy Bypass -File .\StartupSentry.ps1 -ExportarCSV "Reportes\persistencia.csv"
powershell -ExecutionPolicy Bypass -File .\StartupSentry.ps1 -ExportarJSON "Reportes\persistencia.json"
```
