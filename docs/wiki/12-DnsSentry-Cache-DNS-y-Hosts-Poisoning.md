# 🌐 Capítulo 13: DnsSentry (Forense de Caché DNS & Manipulación de Hosts)

**DnsSentry** es el módulo especializado en la inspección forense de la memoria caché del cliente DNS en vivo, detección de técnicas de comunicación Command and Control (C2) sobre el protocolo DNS, identificación de dominios generados algorítmicamente (DGA), Fast-Flux y auditoría de integridad del archivo de resolución local `hosts` de Windows.

---

## 🎯 ¿Por qué es Crítico el Forense de DNS y Hosts?

1. **Evasión de Antivirus por Sinkholing (`T1562.001`):** Malware como troyanos o ransomware alteran el archivo `C:\Windows\System32\drivers\etc\hosts` redirigiendo dominios de telemetría de Windows Defender, actualizaciones de seguridad o VirusTotal hacia `127.0.0.1` o `0.0.0.0` para cegar las defensas.
2. **Ataques de Pharming / DNS Spoofing (`T1566`):** Redirección forzada de dominios bancarios, portales corporativos o servicios de correo hacia direcciones IP controladas por atacantes.
3. **Canales C2 y Exfiltración de Datos sobre DNS (`T1071.004`):** El protocolo DNS rara vez es bloqueado en cortafuegos corporativos. Los atacantes abusan de proveedores Dynamic DNS (DuckDNS, Ngrok, Cloudflare Tunnels) o fragmentan datos confidenciales en subdominios codificados en Base64/Hex.
4. **Algoritmos DGA (Domain Generation Algorithms):** Malware como Emotet, LockBit o Cobalt Strike que consultan decenas de nombres de dominio pseudo-aleatorios con alta entropía matemática antes de establecer contacto.

---

## 🔬 1. Capacidades Forenses Analizadas

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CAPACIDADES DE DNSSENTRY                           │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. INTEGRIDAD DE HOSTS        │ 2. CACHÉ DNS EN VIVO        │ 3. HEURÍSTICA │
│ Hash SHA-256, detección de    │ Get-DnsClientCache, TTL,    │ Entropía DGA, │
│ sinkholes y pharming T1562    │ registros A/AAAA/CNAME      │ túneles C2 TLD│
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

### A. Auditoría del Archivo Hosts
* **Ruta de Inspección:** `C:\Windows\System32\drivers\etc\hosts`
* **Sellado Hash:** Cálculo de huella SHA-256 para verificación de cadena de custodia.
* **Alertas Forenses:**
  * 🔴 **CRITICAL (Sinkhole Antivirus):** Mapeo de dominios de seguridad (`*.microsoft.com`, `windowsupdate.com`, `virustotal.com`) hacia IPs de loopback.
  * 🔴 **CRITICAL (Pharming):** Mapeo de dominios de autenticación (Google, Microsoft, Banca) hacia servidores no autorizados.
  * 🟡 **MEDIUM (Modificación Local):** Entradas personalizadas activas fuera de la plantilla predeterminada de Microsoft.

### B. Análisis de Caché DNS y Entropía DGA
* Extrae el historial de consultas resueltas recientemente en el endpoint.
* **Cálculo de Entropía de Shannon:** Evalúa la aleatoriedad de los nombres de dominio. Un índice $H \ge 3.75$ en etiquetas mayores a 12 caracteres alerta sobre generación algorítmica DGA.
* **Detector de Túneles:** Alerta si la primera etiqueta del dominio excede 42 caracteres (típico de cadenas Base64/Hex exfiltradas en queries DNS) o si la profundidad de subdominios supera 5 niveles.
* **Detección de Dynamic DNS:** Identificación de conexiones hacia proveedores frecuentemente abusados por malware (`duckdns.org`, `ngrok.io`, `trycloudflare.com`, etc.).

---

## 💻 2. Modos de Ejecución

```powershell
# Modo interactivo CLI con resumen pericial
python DnsSentry.py

# Modo silencioso (Headless) con exportación automática a HTML, JSON y CSV
python DnsSentry.py --all

# Motor nativo en PowerShell 5.1/7+
powershell -ExecutionPolicy Bypass -File .\DnsSentry.ps1
```

---

## 📄 3. Reportes Periciales Generados

En la carpeta `DnsSentry/Reportes/`:
* `DnsSentry_Dashboard_<TIMESTAMP>.html`: Dashboard interactivo Cyberpunk con buscador en vivo de dominios y tabla de integridad de Hosts.
* `DnsSentry_Report_<TIMESTAMP>.json`: Base estructurada con metadatos del perito, servidores DNS por interfaz y clasificación de riesgo.
* `DnsSentry_Cache_<TIMESTAMP>.csv`: Lista tabulada de consultas DNS para análisis pericial en hojas de cálculo.
