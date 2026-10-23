# Guía de Contribución a StartupSentry

¡Gracias por tu interés en colaborar con **StartupSentry**! Este módulo está enfocado en la investigación forense de persistencia en Windows (DFIR) y validación criptográfica Authenticode.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nuevo-detector-persistencia
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero librerías externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo robusto de firmas Authenticode y codificación UTF-8 con BOM en archivos `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile StartupSentry.py
   powershell -ExecutionPolicy Bypass -File .\StartupSentry.ps1 -SoloSospechosos
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Nuevas claves de registro de persistencia (AppInit_DLLs, Image File Execution Options, Winlogon).
- Detección de persistencia por WMI Event Subscriptions (`__EventFilter`, `__EventConsumer`).
- Mejoras en el cálculo de Threat Score heurístico.
