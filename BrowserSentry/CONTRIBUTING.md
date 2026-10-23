# Guía de Contribución a BrowserSentry

¡Gracias por tu interés en colaborar con **BrowserSentry**! Este módulo está enfocado en la investigación forense de navegadores web en Windows (DFIR), rastreo de historiales SQLite de descargas, extensiones y vectores de acceso inicial.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nuevo-navegador-soportado
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero dependencias externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo de codificación UTF-8 en archivos `.py` y `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile BrowserSentry.py
   powershell -ExecutionPolicy Bypass -File .\BrowserSentry.ps1 -SoloTriage
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Soporte para navegadores adicionales (Vivaldi, Arc, Tor Browser).
- Extracción segura de perfiles adicionales o múltiples cuentas de usuario.
- Detección de extensiones maliciosas basada en permisos manifiestos (`manifest.json`).
