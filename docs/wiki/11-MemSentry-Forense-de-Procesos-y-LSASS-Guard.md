# 🛡️ Capítulo 11: MemSentry (Forense de Procesos & LSASS Guard)

**MemSentry** es el módulo especializado en la inspección forense de la memoria RAM activa, detección de anomalías en el árbol de procesos, análisis de suplantación de identidad (*Process Masquerading*), auditoría de protección del almacén de credenciales **LSASS** y escaneo de vulnerabilidades por rutas de servicio sin entrecomillar (*Unquoted Service Paths*).

---

## 🎯 ¿Por qué es Crítico el Forense de Procesos en RAM?

1. **Ataques Residentes en Memoria (*Fileless Malware*):** Amenazas que operan inyectando código en procesos legítimos sin guardar archivos en el disco duro.
2. **Robo Masivo de Credenciales (`T1003.001`):** Herramientas como Mimikatz o ProcDump que acceden al espacio de memoria del proceso `lsass.exe` para extraer hashes NTLM, tickets Kerberos y credenciales de dominio.
3. **Persistencia y Evasión por Masquerading (`T1036.005`):** Troyanos que se nombran `svchost.exe` o `taskhostw.exe` pero se ejecutan desde carpetas de usuario o son hijos de procesos anómalos.

---

## 🔎 1. Capacidades Forenses Analizadas

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CAPACIDADES DE MEMSENTRY                           │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. ÁRBOL DE PROCESOS EN RAM   │ 2. LSASS GUARD              │ 3. UNQUOTED   │
│ Linaje Padre-Hijo, detección  │ RunAsPPL, Credential Guard  │ Rutas con     │
│ de macros y comandos encoded  │ y credenciales WDigest      │ espacios T1574│
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

### A. Auditoría de Protección de LSASS
* **RunAsPPL (Protected Process Light):** Verifica si el registro `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` está activo (valor `1` o `2`). Esto impide que procesos sin firma de Microsoft abran manejadores con permisos `PROCESS_VM_READ` contra LSASS.
* **WDigest Caching:** Comprueba si `UseLogonCredential` está en `0` para evitar que Windows almacene contraseñas en texto claro en memoria.

### B. Linaje Padre-Hijo y Masquerading
* Verifica que los procesos críticos del sistema sean hijos exclusivamente de sus padres legítimos:
  * `svchost.exe` -> Hijo de `services.exe`
  * `services.exe` -> Hijo de `wininit.exe`
  * `lsass.exe` -> Hijo de `wininit.exe`
* Alerta crítica si binarios de consola (`cmd.exe`, `powershell.exe`) son engendrados por aplicaciones ofimáticas (Word, Excel, PowerPoint, Adobe Acrobat) o servidores web (`w3wp.exe`).

### C. Scanner de Rutas sin Comillas (*Unquoted Service Paths*)
* Rastrea claves de servicios en `HKLM:\SYSTEM\CurrentControlSet\Services` con rutas que contienen espacios y carecen de comillas delimitadoras (vulnerabilidad clásica de escalada de privilegios locales).

---

## 💻 2. Uso y Reportes Forenses

```powershell
# Modo interactivo CLI con menú
python MemSentry.py

# Modo silencioso (Headless) con exportación automática a HTML, JSON y CSV
python MemSentry.py --all

# Motor nativo en PowerShell
powershell -ExecutionPolicy Bypass -File .\MemSentry.ps1 -SoloTriage
```
