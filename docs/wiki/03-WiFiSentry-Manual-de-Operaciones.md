# 📡 Capítulo 3: WiFiSentry (Forense Inalámbrico & RF)

**WiFiSentry** es el módulo especializado en el análisis forense del espectro electromagnético 802.11 (Wi-Fi), auditoría de higiene de credenciales inalámbricas y caza de puntos de acceso no autorizados (*Rogue AP / Evil Twin*) en Windows.

---

## 🎯 Capacidades Forenses Principales

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CAPACIDADES DE WIFISENTRY                           │
├───────────────────────────────┬─────────────────────────────┬───────────────┤
│ 1. EVIL TWIN HUNTER           │ 2. BENCHMARK PBKDF2 & GPU   │ 3. SENSOR RF  │
│ BSSID, OUI y discrepancia de  │ Cálculo matemático de       │ Radar delta de│
│ cifrado en puntos de acceso   │ tiempo de crackeo de PSK    │ señal y dBm   │
└───────────────────────────────┴─────────────────────────────┴───────────────┘
```

---

## 🛰️ 1. Rogue AP Hunter (Radar de Evil Twin)

Uno de los ataques más peligrosos en entornos corporativos o públicos es el **Punto de Acceso Gemelo Malicioso (*Evil Twin*)**: un atacante despliega una antena Wi-Fi emitiendo el mismo nombre de red (SSID) que la red legítima, pero con mayor potencia de señal o desautenticando a los clientes legítimos para interceptar su tráfico mediante un ataque Adversary-in-the-Middle (AitM / `T1557`).

**WiFiSentry** analiza cuatro vectores simultáneos para identificar gemelos maliciosos:
1. **Colisión de SSID con diferente BSSID:** Identifica si existen múltiples direcciones MAC transmitiendo el mismo nombre de red.
2. **Discrepancia de Fabricante (OUI Check):** Si los puntos de acceso legítimos de una empresa son *Cisco Systems* o *Aruba Networks*, pero aparece una red con el mismo nombre cuyo OUI corresponde a *Raspberry Pi Foundation* o *Espressif Systems*, el sistema genera una alerta crítica de severidad máxima.
3. **Discrepancia de Cifrado:** Si la red legítima utiliza autenticación corporativa WPA2-Enterprise (802.1X) y el clon emite WPA2-Personal (PSK) o red abierta con portal cautivo.
4. **Anomalías de Canal:** Puntos de acceso gemelos transmitiendo en canales no convencionales o saturados deliberadamente.

---

## 🧮 2. Calculadora de Entropía y Benchmark de Crackeo PBKDF2

En redes WPA2-Personal, la clave de paso (Pre-Shared Key / PSK) se deriva mediante el algoritmo **PBKDF2** utilizando 4096 iteraciones de HMAC-SHA1 junto con el SSID como *salt*.

WiFiSentry evalúa la robustez criptográfica de cada perfil inalámbrico almacenado en el equipo mediante:

### Fórmula de Entropía de Shannon:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

A partir del espacio de claves posible ($N^L$, donde $N$ es el conjunto de caracteres y $L$ la longitud), el módulo calcula el tiempo estimado necesario para queclústeres de cómputo dedicados vulneren la contraseña mediante ataques de diccionario y fuerza bruta masiva:

| Escenario de Ataque | Tasa de Hash Estimada | Tipo de Infraestructura |
| :--- | :--- | :--- |
| **CPU Estándar (Laptop)** | $\approx 2.5 \times 10^3 \text{ H/s}$ | Procesador convencional de oficina |
| **GPU Moderna (NVIDIA RTX 4090)** | $\approx 2.5 \times 10^6 \text{ H/s}$ | Tarjeta gráfica de alto rendimiento |
| **Clúster Dedicado de Crackeo (8x RTX 4090)** | $\approx 2.0 \times 10^7 \text{ H/s}$ | Granja de cómputo para auditoría forense |

El reporte clasifica cada red con un código cromático:
* 🟢 **Robusta:** Entropía $\ge 60$ bits (requiere décadas de cómputo GPU).
* 🟡 **Moderada:** Entropía entre 45 y 59 bits (vulnerable a diccionarios combinatorios).
* 🔴 **Crítica:** Entropía $< 45$ bits o palabras comunes de diccionario (crackeable en minutos/horas).

---

## 📶 3. Sensor de Proximidad RF y Heatmap Espectral

Al ejecutar la opción de **Sensor de Proximidad en Vivo**, WiFiSentry entra en un bucle de refresco rápido sobre el adaptador de red inalámbrica:

* **Estimación de Potencia RSSI en dBm:** Realiza la conversión matemática del porcentaje de calidad de señal de Windows a decibelios-milivatio:
  $$\text{RSSI (dBm)} \approx \left(\frac{\text{Calidad}}{2}\right) - 100$$
* **Delta de Variación ($\Delta \pm\%$):** Calcula la variación en tiempo real respecto al último muestreo, permitiendo al analista caminar con el equipo para triangular físicamente la posición del emisor no autorizado.
* **Mapa Térmico de Canales:** Muestra barras de saturación de frecuencia en las bandas de 2.4 GHz y 5 GHz para detectar interferencias intencionales (*RF Jamming*).

---

## 💻 Modos de Ejecución

### 1. Ejecución con Lanzador Inteligente (.bat)
```cmd
cd WiFiSentry
Ejecutar-WiFiSentry.bat
```

### 2. Motor Python 3 (CLI Interactivo)
```powershell
python WiFiSentry.py
```
Opciones del menú:
* `[1]` Auditoría completa de perfiles inalámbricos almacenados y claves.
* `[2]` Escaneo en vivo de redes cercanas y Evil Twin Hunter.
* `[3]` Sensor de Proximidad RF en tiempo real.
* `[4]` Generación de Dashboard HTML Cyberpunk interactivo.
* `[5]` Exportar perfiles a JSON/CSV.

### 3. Motor Nativo en PowerShell
```powershell
powershell -ExecutionPolicy Bypass -File .\WiFiSentry.ps1
```
