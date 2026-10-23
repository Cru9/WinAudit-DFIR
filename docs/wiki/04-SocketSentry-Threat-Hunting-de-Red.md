# 🌐 Capítulo 4: SocketSentry (Threat Hunting de Red & C2)

**SocketSentry** es el módulo especializado en el análisis forense de la pila de red en tiempo real, detección de canales de Comando y Control (C2), caza de balizas (*Beaconing*) y abuso de binarios legítimos (*Living Off The Land / LOLBAS*) en Windows.

---

## 🎯 Capacidades Forenses Principales

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CAPACIDADES DE SOCKETSENTRY                         │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. CORRELACIÓN TOTAL          │ 2. THREAT INTEL INTEGRADA   │ 3. RESPUESTA  │
│ Socket TCP/UDP -> PID ->      │ Feodo Tracker + Catálogo de │ MiniDump de   │
│ Binario -> Firma -> CmdLine   │ 245+ LOLBins + Puertos APT  │ memoria y FW  │
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

---

## 🔍 1. Correlación Profunda de Sockets en Memoria

Los comandos tradicionales como `netstat -ano` solo muestran IPs y PIDs numéricos, obligando al analista a buscar manualmente en el Administrador de Tareas a qué programa pertenece cada conexión.

**SocketSentry** correlaciona de forma atómica y en tiempo real:
1. **Identidad del Proceso:** Resuelve el PID al nombre del ejecutable, ruta absoluta en disco y argumentos completos de la línea de comandos (*CommandLine*).
2. **Validación Authenticode:** Comprueba si el ejecutable que mantiene la conexión abierta cuenta con una firma digital válida emitida por un fabricante legítimo.
3. **Geolocalización y DNS Inverso (rDNS):** Determina el nombre de dominio asociado (PTR) y el país de destino de la dirección IP remota.

---

## 🛡️ 2. Fuentes de Inteligencia de Amenazas (Threat Intel)

SocketSentry incorpora una base de datos local enriquecida ([`db_conexiones.json`](../SocketSentry/db_conexiones.json)) que no requiere conexión a internet:

### A. Abuse.ch Feodo Tracker
* Lista curada de servidores C2 activos utilizados por familias de malware financiero, troyanos bancarios y cargadores de ransomware como **Qakbot, Dridex, Emotet y Trickbot**.
* Si una conexión saliente coincide con un registro de Feodo Tracker, se asigna automáticamente una puntuación de riesgo de **100/100 (Severidad Crítica)**.

### B. Catálogo LOLBAS (*Living Off The Land Binaries and Scripts*)
* Contiene firmas y patrones de uso de más de **245 binarios legítimos de Windows** (`certutil.exe`, `powershell.exe`, `mshta.exe`, `bitsadmin.exe`, `curl.exe`, `rundll32.exe`, `regsvr32.exe`) que los atacantes abusan para descargar payloads o evadir antivirus (`T1218`).
* Detecta si un LOLBin está estableciendo conexiones salientes hacia internet no esperadas.

### C. Matriz de Puertos Sospechosos
* Monitoreo activo de puertos habitualmente asociados con herramientas de explotación:
  `4444` (Metasploit Default), `50050` (Cobalt Strike Team Server), `1337`, `6667` (IRC Botnets), `31337` (Back Orifice), `8080`, `9001` (Tor Directory), etc.

---

## ⏱️ 3. Algoritmo de Detección de Balizas C2 (*Beaconing*)

Muchos implantes maliciosos modernos (Cobalt Strike, Havoc, Mythic, Sliver) se comunican periódicamente con su servidor C2 para solicitar nuevas instrucciones (*check-in*).

SocketSentry implementa un algoritmo de análisis de cadencia temporal:
1. Muestrea las conexiones salientes hacia un mismo destino durante una ventana de observación.
2. Calcula los intervalos de tiempo entre paquetes ($\Delta t$).
3. Evalúa la media ($\mu$) y la desviación estándar ($\sigma$) para determinar el **Coeficiente de Variación ($CV$)**:

$$CV = \frac{\sigma}{\mu}$$

* Si $CV \approx 0$ (o dentro del rango de fluctuación programada de *jitter*), la conexión se clasifica como una **baliza programática automatizada**, diferenciándola del tráfico de navegación web humana interactiva.

---

## ⚡ 4. Contención Activa y Preservación Forense

Frente a una amenaza crítica confirmada, SocketSentry permite actuar directamente desde la consola:

### Generación de MiniDump de Memoria (`MiniDumpWriteDump`)
* Antes de cerrar un proceso malicioso, el analista puede ordenar un volcado de memoria volátil (`.dmp`) del proceso sospechoso.
* Esto preserva cadenas en memoria, configuraciones C2, claves de cifrado y artefactos inyectados para posterior análisis forense con herramientas como Volatility o IDA Pro.

### Bloqueo Inmediato en Firewall de Windows
* Permite crear una regla de bloqueo saliente automática en Windows Defender Firewall para aislar el proceso o la IP remota sin derribar la conectividad del resto del equipo:
  ```cmd
  netsh advfirewall firewall add rule name="SocketSentry_Block_Threat" dir=out action=block remoteip=X.X.X.X
  ```

---

## 💻 Modos de Uso

### 1. Lanzador Inteligente (.bat)
```cmd
cd SocketSentry
Ejecutar-SocketSentry.bat
```

### 2. Motor Python 3 (CLI Interactivo)
```powershell
python SocketSentry.py
```
Opciones:
* `[1]` Auditoría completa de conexiones activas en memoria.
* `[2]` Análisis en tiempo real de balizas C2 (*Beacon Hunter*).
* `[3]` Filtrado exclusivo de conexiones sospechosas y alertas críticas.
* `[4]` Generación de Dashboard HTML Cyberpunk interactivo.
* `[5]` Exportación de evidencias a JSON y CSV.

### 3. Motor Nativo en PowerShell
```powershell
powershell -ExecutionPolicy Bypass -File .\Auditar-Conexiones.ps1
```
