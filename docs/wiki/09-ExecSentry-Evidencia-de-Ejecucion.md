# ⚡ Capítulo 9: ExecSentry (Evidencia Forense de Ejecución)

**ExecSentry** es el módulo especializado en la reconstrucción cronológica y análisis forense de programas, comandos y binarios ejecutados en un equipo Windows. Rastrea y correlaciona artefactos clave del sistema operativo: **Windows Prefetch** (`.pf`), claves **UserAssist** ofuscadas en **ROT13**, y el subsistema de moderación de actividad **BAM/DAM** en el registro por SID de usuario.

---

## 🎯 ¿Por qué es Crítica la Evidencia de Ejecución en DFIR?

En la mayoría de los incidentes de intrusión y ransomware, los atacantes intentan destruir evidencia borrando sus herramientas y scripts de carpetas como `%TEMP%`, `AppData` o `C:\Users\Public` tras haberlos corrido.

Sin embargo, el kernel y subsistemas de Windows conservan **marcas permanentes de ejecución**:
1. **Prueba Incontrovertible de Ejecución (`T1204`):** Permite demostrar ante un tribunal o en un informe pericial que el malware **sí se ejecutó**, cuándo ocurrió la primera y última ejecución, y cuántas veces.
2. **Identificación de Herramientas Ofensivas (`T1059`):** Rastreo de frameworks de post-explotación (`Mimikatz`, `Rubeus`, `Procdump`, `Chisel`, `Ngrok`).
3. **Detección de LOLBins:** Identificación de utilidades legítimas de Windows invocadas para fines hostiles (`certutil`, `bitsadmin`, `powershell -enc`, `vssadmin`).

---

## 🔎 1. Artefactos Forenses Analizados

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CAPACIDADES DE EXECSENTRY                           │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. WINDOWS PREFETCH           │ 2. USERASSIST (ROT13)       │ 3. BAM / DAM  │
│ Archivos *.pf en C:\Windows   │ Ejecuciones GUI interactivas│ Moderador de  │
│ Hash, nombre y timestamps     │ Conteo y último timestamp   │ actividad HKLM│
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

### A. Windows Prefetch (`C:\Windows\Prefetch\*.pf`)
* Diseñado para optimizar la carga de aplicaciones en memoria RAM.
* Cada archivo tiene el formato `NOMBRE.EXE-<HASH>.pf`.
* La fecha de modificación del archivo `.pf` (`LastWriteTime`) corresponde a la última vez que el binario fue ejecutado en el sistema operativo.

### B. UserAssist (`HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`)
* Clave de registro que registra aplicaciones ejecutadas desde la interfaz de usuario de Windows (Explorer, Menú Inicio, Accesos directos).
* **Ofuscación ROT13:** Los nombres de los ejecutables están codificados en ROT13 (e.g., `U:\Cebtenz Svyrf\...` -> `H:\Program Files\...`).
* **Bloque de Datos Binario (72 bytes):**
  * Bytes 4-7: Conteo total de ejecuciones (DWORD).
  * Bytes 60-67: Estructura `FILETIME` de la última ejecución en formato UTC.

### C. BAM / DAM (Background Activity Moderator)
* Ubicado en `HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<UserSID>`.
* Asocia directamente el identificador de seguridad del usuario (**SID**) con la ruta absoluta del binario ejecutado.
* Los primeros 8 bytes del valor binario contienen el timestamp `FILETIME` exacto de inicio del proceso.

---

## 🚦 2. Semáforo de Riesgo Heurístico

* 🟢 **CLEAN (Riesgo Normal):** Aplicaciones comerciales estándar ejecutadas desde `C:\Program Files` o `C:\Windows\System32`.
* 🟡 **MEDIUM / HIGH (Sospechoso):** Binarios ejecutados desde rutas temporales (`%TEMP%`, `Downloads`, `Public`) o ejecutables LOLBins nativos (`certutil.exe`, `vssadmin.exe`, `powershell.exe`).
* 🔴 **CRITICAL (Amenaza Detectada):** Coincidencia con firmas de herramientas de intrusión (`mimikatz`, `rubeus`, `procdump`, `cobaltstrike`) o técnicas de evasión de doble extensión (`factura.pdf.exe`).

---

## 💻 3. Uso y Reportes Forenses

```powershell
# Modo interactivo CLI con menú
python ExecSentry.py

# Modo silencioso (Headless) con exportación automática a HTML, JSON y CSV
python ExecSentry.py --all

# Motor nativo en PowerShell
powershell -ExecutionPolicy Bypass -File .\ExecSentry.ps1 -SoloTriage
```
