# ❓ Capítulo 7: Preguntas Frecuentes y Solución de Problemas (FAQ)

Este capítulo reúne las soluciones a los problemas técnicos más comunes reportados al desplegar y ejecutar **WinAudit-DFIR** en diferentes versiones de Windows.

---

## 🚨 1. Errores de Permisos y Elevación UAC

### ❌ Problema:
> *"ERROR DE PRIVILEGIOS: Este script necesita leer el registro de Seguridad (Security Log)."*  
> *"Acceso denegado al inspeccionar sockets de red."*

### 💡 Causa y Solución:
En Windows, el registro de auditoría de seguridad (`Security Log`) y la correlación completa de sockets de red hacia líneas de comando están protegidos por el subsistema de seguridad y no son accesibles para usuarios estándar:
1. **Solución Automática:** Ejecuta siempre los archivos lanzadores **`.bat`** (`Suite-DFIR.bat`, `Ejecutar-Deteccion.bat`, etc.). Estos scripts implementan auto-elevación y solicitarán automáticamente la aprobación en la ventana UAC de Windows.
2. **Solución Manual:** Si ejecutas directamente desde PowerShell o CMD, haz clic derecho sobre el acceso directo de la terminal y selecciona **"Ejecutar como administrador"**.

---

## 📜 2. Políticas de Ejecución de PowerShell (ExecutionPolicy)

### ❌ Problema:
> *"File cannot be loaded because running scripts is disabled on this system"* (`PSSecurityException`).

### 💡 Causa y Solución:
Windows desactiva por defecto la ejecución de scripts `.ps1` externos como medida preventiva:
* Para ejecutar cualquiera de los scripts sin alterar la política global del sistema operativo, utiliza siempre el parámetro `-ExecutionPolicy Bypass`:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\StartupSentry.ps1
  ```
* Todos los archivos `.bat` de la suite ya incluyen este flag de forma predeterminada.

---

## 🔤 3. Caracteres Rotos en Consola (Mojibake)

### ❌ Problema:
> Los cuadros ASCII, tildes o iconos se muestran como `├`, `â€`, `` o símbolos corruptos.

### 💡 Causa y Solución:
Las versiones clásicas de la consola de Windows (`cmd.exe` y Windows PowerShell 5.1) utilizan páginas de códigos heredadas (como Windows-1252 o CP-437).
1. En consolas de CMD, ejecuta antes:
   ```cmd
   chcp 65001
   ```
2. Si utilizas Windows 10 u 11, se recomienda encarecidamente utilizar **Windows Terminal** en lugar de `conhost.exe` para disfrutar de renderizado acelerado por GPU y soporte completo de UTF-8 y colores HSL.
3. Todos los scripts `.ps1` de la suite se encuentran codificados con **UTF-8 con BOM (`utf-8-sig`)**, lo que garantiza que PowerShell 5.1 no confunda la tabla de caracteres.

---

## 🐍 4. Python no Detectado en el Sistema

### ❌ Problema:
> *"Python no se reconoce como un comando interno o externo, programa o archivo por lotes ejecutable."*

### 💡 Causa y Solución:
La suite está diseñada con **arquitectura dual-runtime**:
* Si Python no está instalado o no fue agregado al `PATH` de Windows durante su instalación, los lanzadores `.bat` **detectan esta condición automáticamente y conmutan al motor nativo en PowerShell**.
* Si deseas utilizar la interfaz de Python y generar dashboards interactivos:
  1. Descarga Python 3 desde [python.org](https://www.python.org/).
  2. **¡Paso Fundamental!** En la primera pantalla del instalador, marca la casilla:  
     ☑️ **"Add python.exe to PATH"**.

---

## ⚠️ 5. Manejo de Falsos Positivos

### ❌ Problema:
> *"Un software propio de mi empresa o un agente de respaldo aparece marcado como Sospechoso o Crítico."*

### 💡 Causa y Solución:
* **Firma Digital Faltante:** Si una aplicación interna fue compilada internamente sin un certificado digital Authenticode reconocido por una Autoridad Certificadora (CA pública), StartupSentry y SocketSentry la clasificarán como `NotSigned` con riesgo preventivo medio.
* **Ruta de Ejecución:** Si la herramienta se ejecuta desde `AppData\Local\Temp` o `C:\Users\Public`, el motor heurístico elevará su puntuación por considerarse un patrón habitual de malware.
* **Cómo Excluirlo:** Puedes reportar un falso positivo legítimo mediante nuestra plantilla comunitaria en GitHub:
  🔗 [Reporte de Falso Positivo / IOC](https://github.com/Cru9/WinAudit-DFIR/issues/new?template=ioc_submission.yml).

---

## 🏢 6. ¿Es Seguro Ejecutar WinAudit-DFIR en Producción?

### 💡 Respuesta Técnica:
**Sí, con total seguridad.**
* WinAudit-DFIR **no instala controladores de kernel (*drivers*)**, no inyecta DLLs en procesos ajenos y no altera claves del sistema operativo.
* Todas las consultas forenses se realizan mediante APIs públicas y documentadas de Windows (Win32 API, WMI/CIM, Event Log API y NetAPI32).
* El consumo de memoria y CPU es mínimo ($\le 25 \text{ MB}$ de RAM durante escaneos completos).

---

## 💡 7. ¿Cómo Aportar Nuevas Reglas o IOCs?

Si eres analista de inteligencia de amenazas y descubres una nueva IP de comando y control (C2), un puerto malicioso o un nuevo LOLBin abusable:
1. Abre un Issue usando la plantilla de Threat Intel:
   🔗 [Aportar IOC / Regla Defensiva](https://github.com/Cru9/WinAudit-DFIR/issues/new?template=ioc_submission.yml).
2. O edita el archivo [`SocketSentry/db_conexiones.json`](../SocketSentry/db_conexiones.json) y envía un Pull Request contra la rama `main`.
