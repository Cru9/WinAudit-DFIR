# 🌐 Capítulo 10: BrowserSentry (Forense de Navegadores & Descargas)

**BrowserSentry** es el módulo especializado en la inspección profunda de la actividad de navegación web en endpoints Windows, con soporte multi-navegador en vivo (**Google Chrome, Microsoft Edge, Brave Browser y Mozilla Firefox**). Permite recuperar historiales de descargas, cadenas de URLs de redirección, búsquedas de explotación y extensiones instaladas.

---

## 🎯 ¿Por qué es Crítico el Forense de Navegadores Web?

Más del 85% de las brechas de seguridad iniciales ocurren a través del navegador:
1. **Acceso Inicial por Phishing (`T1566.002`):** Enlaces maliciosos que entregan páginas de suplantación de identidad o payloads armados.
2. **Descarga de Malicious Payloads (`T1204.001`):** Archivos descargados desde almacenamiento temporal (`anonfiles`, `discord cdn`, `gofile`) o túneles inversos (`duckdns`, `ngrok`).
3. **Evasión Mark-of-the-Web (MOTW Bypass `T1553.005`):** Descarga de imágenes de disco (`.iso`, `.vhd`, `.img`) que, al ser montadas en Windows, omiten el flag de zona de Internet de SmartScreen.
4. **Persistencia mediante Extensiones (`T1176`):** Extensiones no oficiales o sideloaded que secuestran sesiones web o roban cookies y credenciales.

---

## 🔎 1. Arquitectura y Bases de Datos SQLite

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CAPACIDADES DE BROWSERSENTRY                         │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. HISTORIAL DE DESCARGAS     │ 2. VISITAS Y BÚSQUEDAS      │ 3. EXTENSIONES│
│ Tabla 'downloads' y URL       │ Tabla 'urls' (Chrome/Edge)  │ Inspección de │
│ chains con tamaño y estado    │ Caza de términos de hacking │ manifest.json │
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

### Manejo Forense de Archivos Bloqueados
Cuando los navegadores web están en ejecución, las bases de datos SQLite (`History`, `places.sqlite`) son bloqueadas por el proceso del navegador mediante bloqueos exclusivos del sistema operativo.  
**BrowserSentry** implementa una técnica de clonado forense en memoria temporal (`%TEMP%`), copiando la base de datos principal y sus archivos de registro Write-Ahead Log (`-wal`) antes de consultar los datos, permitiendo auditar navegadores activos sin cerrarle las pestañas al usuario.

---

## 🚦 2. Semáforo de Riesgo Heurístico

* 🟢 **CLEAN (Riesgo Normal):** Descargas habituales de documentos (`.pdf`, `.png`, `.jpg`, `.txt`) desde dominios corporativos reconocidos.
* 🟡 **MEDIUM (Sospechoso):** Archivos comprimidos (`.zip`, `.rar`, `.7z`) o documentos con macros (`.docm`, `.xlsm`). Búsquedas web sobre herramientas de intrusión.
* 🔴 **CRITICAL (Amenaza Inminente):** Descarga de archivos ejecutables (`.exe`, `.scr`, `.bat`, `.ps1`), imágenes de disco (`.iso`, `.vhd`), o descargas originadas desde túneles dinámicos (`duckdns.org`, `ngrok-free.app`, `serveo.net`, `trycloudflare.com`).

---

## 💻 3. Uso y Reportes Forenses

```powershell
# Modo interactivo CLI con menú
python BrowserSentry.py

# Modo silencioso (Headless) con exportación automática a HTML, JSON y CSV
python BrowserSentry.py --all

# Motor nativo en PowerShell
powershell -ExecutionPolicy Bypass -File .\BrowserSentry.ps1 -SoloTriage
```
