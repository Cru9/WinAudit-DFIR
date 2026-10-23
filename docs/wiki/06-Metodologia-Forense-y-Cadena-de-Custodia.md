# ⚖️ Capítulo 6: Metodología Forense y Cadena de Custodia

Este capítulo establece las directrices metodológicas, normativas internacionales y principios de preservación digital que rigen las operaciones con la suite **WinAudit-DFIR**.

---

## 📜 Estándares Internacionales de Referencia

La arquitectura de WinAudit-DFIR ha sido alineada con las principales guías forenses internacionales:
1. **NIST Special Publication 800-86:** *Guide to Integrating Forensic Techniques into Incident Response*.
2. **RFC 3227:** *Guidelines for Evidence Collection and Archiving*.
3. **ISO/IEC 27037:** *Directrices para la identificación, recolección, adquisición y preservación de evidencia digital*.

---

## ⏱️ 1. El Orden de Volatilidad (RFC 3227)

El principio fundamental de la recolección de evidencias digitales establece que **los datos más efímeros deben recolectarse antes de que se pierdan por reinicio o sobreescritura**:

```
VOLATILIDAD ALTA  ▲  1. Memoria RAM y conexiones de red activas ──► SocketSentry
                  │  2. Procesos en ejecución y live tail SIEM  ──► IntruderDetector (--live)
                  │  3. Espectro RF y señales inalámbricas      ──► WiFiSentry (Proximity)
                  │  4. Configuración en disco y persistencia   ──► StartupSentry
VOLATILIDAD BAJA  ▼  5. Registros de eventos archivados (.evtx) ──► IntruderDetector
```

### Secuencia de Ejecución Recomendada en un Incidente Activo:
1. **Fase 1 (Red y Sockets en Vivo):** Ejecutar [`SocketSentry`](../SocketSentry/) para capturar conexiones C2 activas, puertos abiertos y generar volcados `MiniDump` de procesos sospechosos antes de que el atacante cierre la sesión.
2. **Fase 2 (Espectro Wi-Fi):** Si el equipo es portátil o está en una red inalámbrica, ejecutar [`WiFiSentry`](../WiFiSentry/) para descartar puntos de acceso gemelos (*Evil Twin*) o saturación de señal.
3. **Fase 3 (Mecanismos de Persistencia):** Ejecutar [`StartupSentry`](../StartupSentry/) para identificar programas de auto-arranque, tareas programadas en la raíz y binarios con firmas alteradas (`HashMismatch`).
4. **Fase 4 (Línea de Tiempo en Event Logs):** Ejecutar [`Detección de Intrusos`](../Detección%20de%20Intrusos/) para correlacionar eventos históricos de autenticación (4625), accesos RDP (4624) y borrado de logs (1102).

---

## 🔒 2. Cadena de Custodia Criptográfica (SHA-256)

En un peritaje judicial o auditoría formal de cumplimiento (SOC 2, ISO 27001, PCI-DSS), una evidencia digital carece de validez legal si no se puede demostrar que **no fue alterada tras su recolección**.

Todos los reportes generados por WinAudit-DFIR (`.json`, `.csv`, `.html`) deben ser protegidos mediante un resumen criptográfico:

### Cálculo de Hash SHA-256 en PowerShell:
```powershell
Get-FileHash -Path "Reportes\*.json" -Algorithm SHA256 | Format-Table -AutoSize
```

### Cálculo de Hash SHA-256 en Python:
```python
import hashlib
from pathlib import Path

def calcular_hash_evidencia(ruta_archivo):
    sha256 = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()
```

### Documentación de la Cadena de Custodia:
Para cada extracción de evidencias, el analista debe registrar en su acta pericial:
* **Fecha y Hora UTC (ISO 8601):** Marca temporal exacta de inicio y fin del escaneo.
* **Identidad del Host:** Nombre NetBIOS (`COMPUTERNAME`), Dominio/Grupo de trabajo, dirección MAC y número de serie del BIOS.
* **Identidad del Perito / Analista:** Nombre, rol y firma digital del operador.
* **Hash SHA-256 de los Reportes:** Para garantizar la inmutabilidad de los datos.

---

## 🛡️ 3. Principio de No Invasión y Respeto a la Evidencia

* **Solo Lectura por Defecto:** Ningún módulo de WinAudit-DFIR escribe en el registro de Windows, ni modifica la configuración del sistema durante los análisis diagnósticos.
* **Acciones de Respuesta con Confirmación:** Las funciones defensivas activas (como el aislamiento de procesos mediante Windows Firewall en SocketSentry) requieren confirmación explícita del operador antes de alterar las reglas de red.
* **Aislamiento en Disco:** Todos los reportes se guardan localmente en la carpeta `Reportes/` del módulo en ejecución, sin dispersar archivos temporales por el sistema operativo.
