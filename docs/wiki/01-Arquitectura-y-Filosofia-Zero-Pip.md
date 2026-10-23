# 🏛️ Capítulo 1: Arquitectura y Filosofía Zero-Pip

Este capítulo profundiza en los principios de ingeniería de software defensivo y estándares forenses que sustentan el diseño de **WinAudit-DFIR**.

---

## 🎯 Los Tres Pilares de WinAudit-DFIR

El diseño de la suite responde a las condiciones extremas a las que se enfrenta un respondedor de incidentes en el mundo real:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FILOSOFÍA DE ARQUITECTURA DFIR                        │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. CERO DEPENDENCIAS (0 PIP)  │ 2. DUAL-RUNTIME RESILIENTE  │ 3. PRIVACIDAD │
│ Biblioteca estándar de Python │ Python 3.8+ y PowerShell    │ 100% Local    │
│ Sin necesidad de compilar C++ │ Conmutación transparente    │ Cero fugas    │
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

### 1. Cero Dependencias Obligatorias (`0 pip`)
En incidentes cibernéticos críticos (ataques de Ransomware, intrusiones APT o servidores en zonas desmilitarizadas DMZ), las máquinas suelen estar aisladas de la red para evitar movimiento lateral o exfiltración.
* Instalar paquetes mediante `pip install` es **imposible** sin conexión a internet y **desaconsejable** en informática forense, ya que altera las claves de registro del sistema y sobrescribe archivos en disco.
* Cada línea de código en Python dentro de **WinAudit-DFIR** utiliza únicamente módulos nativos:
  `subprocess`, `json`, `csv`, `ctypes`, `socket`, `re`, `datetime`, `platform`, `html`, `math`, `pathlib`.

### 2. Dual-Runtime (Python 3 + PowerShell 5.1 / 7+)
Windows carece históricamente de un intérprete de Python preinstalado por defecto.
* Si el equipo analizado cuenta con Python 3 en el `PATH`, los scripts `.bat` inician la interfaz enriquecida de Python con generación de dashboards interactivos.
* Si Python no está instalado, el lanzador conmuta inmediatamente y sin errores hacia el motor nativo en **PowerShell**.
* Dado que PowerShell viene incorporado en todas las versiones modernas de Windows (Windows 10, 11, Server 2016, 2019, 2022, 2025), el analista **nunca se queda sin capacidad de respuesta**.

### 3. Principio de Mínima Huella Forense (*Zero-Touch Footprint*)
* La suite no crea servicios persistentes, no modifica claves del registro de Windows (salvo en acciones explícitas de contención como el bloqueo en Firewall de SocketSentry) y no requiere instalación formal en `Program Files`.
* Todas las evidencias, logs y reportes se encapsulan exclusivamente en la subcarpeta local [`Reportes/`](Reportes/).

---

## ⚙️ Mecanismos de Elevación de Privilegios UAC sin Bucles

Muchos scripts de administración en Windows fallan al solicitar permisos de Administrador debido a llamadas recursivas infinitas o apertura descontrolada de ventanas en consola.

Los lanzadores inteligentes `.bat` de WinAudit-DFIR implementan un protocolo de **protección anti-bucle**:

```cmd
:: 1. PROTECCION ANTI-BUCLE: Si ya fue invocado con el parametro -elevated, no volver a elevar
if "%~1"=="-elevated" goto :CheckRuntime

:: 2. Comprobar si ya tenemos privilegios de Administrador
net session >nul 2>&1
if %errorLevel% equ 0 goto :CheckRuntime

:: 3. Intentar elevacion UNA SOLA VEZ
echo [i] Solicitando permisos de Administrador...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '-elevated' -Verb RunAs } catch { exit 1 }" >nul 2>&1

:: Si se elevo con exito, cerrar esta ventana original para no duplicar
if %errorLevel% equ 0 exit /b
```

### Explicación del Flujo:
1. Al ejecutarse, comprueba privilegios mediante el comando nativo `net session`.
2. Si no es administrador, solicita elevación mediante el verbo `RunAs` de PowerShell pasando el argumento bandera `-elevated`.
3. Inmediatamente después de lanzar la nueva consola con privilegios elevados, la ventana original se cierra (`exit /b`), evitando duplicidad en pantalla.
4. Si el usuario hace clic en "No" en el control de cuentas de usuario (UAC), el script detecta la denegación y continúa en modo estándar sin crashear.

---

## 🔤 Estándares de Codificación de Caracteres en Windows

Uno de los problemas más frecuentes en la administración de sistemas Windows en español son los caracteres especiales corruptos (*mojibake* como `├`, `─`, `└`, tildes y símbolos de advertencia):

1. **Scripts de PowerShell (`.ps1`):**
   * Windows PowerShell 5.1 interpreta por defecto los archivos UTF-8 sin marca de orden de bytes como codificación ANSI/Windows-1252 local.
   * **Regla de la Suite:** Todos los scripts `.ps1` que contienen caracteres especiales se guardan estrictamente con codificación **UTF-8 con BOM (`utf-8-sig`)**.
2. **Scripts por Lotes (`.bat`):**
   * El intérprete `cmd.exe` de Windows puede desincronizar los saltos de línea si se usa UTF-8 con BOM.
   * **Regla de la Suite:** Todos los archivos `.bat` se codifican en **UTF-8 sin BOM con saltos de línea CRLF** y ejecutan `chcp 65001 >nul` en su primera línea para forzar salida Unicode en terminal.

---

## 📊 Arquitectura de los Dashboards HTML Autónomos

Los reportes HTML generados por los módulos (Cyberpunk Glassmorphism) no son páginas web comunes:
* **Autonomía Total (Cero CDNs):** No cargan fuentes de Google Fonts, ni scripts de Bootstrap o Tailwind vía CDN externo. Si el equipo no tiene conexión a internet, la página se visualiza con el 100% de su diseño, colores y funciones intactos.
* **Estilos Embebidos:** El CSS moderno (variables HSL, filtros de desenfoque `backdrop-filter: blur`, animaciones CSS3) y los iconos vectoriales SVG están integrados en el propio archivo HTML.
* **Interactividad Vanilla JS:** Filtros de búsqueda en tiempo real, ordenamiento de columnas y cambio de vistas ejecutivas sin librerías externas (jQuery, React, etc.).
