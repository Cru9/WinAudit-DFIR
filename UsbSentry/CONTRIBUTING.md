# Guía de Contribución a UsbSentry

¡Gracias por tu interés en colaborar con **UsbSentry**! Este módulo está enfocado en la investigación forense de almacenamiento extraíble en Windows (DFIR) y detección de hardware malicioso.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nueva-firma-badusb
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero librerías externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo de codificación UTF-8 con BOM en archivos `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile UsbSentry.py
   powershell -ExecutionPolicy Bypass -File .\UsbSentry.ps1
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Nuevas firmas VID/PID de dispositivos BadUSB o hardware hacking.
- Correlación con eventos de desconexión en `Microsoft-Windows-DriverFrameworks-UserMode/Operational`.
- Extracción de volumen serial y GUIDs en ramas complejas de `MountedDevices`.
