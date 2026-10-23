# 🤝 Guía de Contribución — WinAudit-DFIR Suite

¡Gracias por tu interés en colaborar con **WinAudit-DFIR**! Esta suite fue creada por **[Cru9](https://github.com/Cru9)** con el objetivo de ofrecer herramientas forenses, transparentes y de alto rendimiento para analistas de seguridad, respondedores de incidentes (DFIR) y administradores de sistemas Windows.

---

## 🧭 Filosofía de Arquitectura del Proyecto

Para que cualquier contribución sea admitida dentro del repositorio, debe respetar estos **3 pilares innegociables**:

1. **Cero Dependencias Externas Obligatorias (`0 pip`):**
   * Todo script en Python debe funcionar exclusivamente con la **Biblioteca Estándar de Python 3.8+** (`subprocess`, `json`, `ctypes`, `urllib`, `re`, `socket`, `math`, etc.).
   * Esto garantiza que un analista pueda ejecutar las herramientas en entornos aislados o comprometidos sin conexión a internet y sin necesidad de compilar paquetes C++.
2. **Dual-Runtime y Resiliencia en Windows:**
   * Cada capacidad clave debe tener su implementación en **Python 3** y su contraparte nativa en **PowerShell 5.1+ / 7+**.
   * Debe incluirse un lanzador `.bat` con elevación UAC limpia que detecte automáticamente el runtime disponible.
3. **Privacidad y Seguridad Defensiva:**
   * Ningún dato del sistema auditado debe salir de la máquina local salvo que el usuario ejecute explícitamente una acción de reporte externo.
   * Todos los reportes deben soportar modos de anonimización para proteger identidades corporativas o personales.

---

## 🛠️ Flujo de Desarrollo

1. **Haz un Fork** del repositorio a tu cuenta personal:
   ```bash
   git clone https://github.com/TU-USUARIO/WinAudit-DFIR.git
   cd WinAudit-DFIR
   ```
2. **Crea una Rama Temática** para tu funcionalidad o corrección:
   ```bash
   git checkout -b feature/nuevo-detector-usb
   ```
3. **Valida la Sintaxis Localmente:**
   ```powershell
   # Validar sintaxis en Python
   python -m py_compile WiFiSentry/WiFiSentry.py
   python -m py_compile SocketSentry/SocketSentry.py
   python -m py_compile "Detección de Intrusos/IntruderDetector.py"
   python -m py_compile StartupSentry/StartupSentry.py
   python -m py_compile UsbSentry/UsbSentry.py

   # Validar JSON
   Get-Content SocketSentry/db_conexiones.json -Raw | ConvertFrom-Json | Out-Null
   ```
4. **Haz Commit con Mensajes Claros (Convención Semántica):**
   * `feat(SocketSentry): agregar soporte para detección de proxies inversos`
   * `fix(WiFiSentry): corregir cálculo de dBm en adaptadores MediaTek`
   * `docs(README): actualizar diagrama de arquitectura`
5. **Abre un Pull Request** contra la rama `main` de `Cru9/WinAudit-DFIR`.

---

## 📜 Licencia de las Contribuciones

Al contribuir código al proyecto, aceptas que tus contribuciones se distribuyan bajo los términos de la **Licencia MIT**.
