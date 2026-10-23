# Guía de Contribución a MemSentry

¡Gracias por tu interés en colaborar con **MemSentry**! Este módulo está enfocado en la auditoría forense de procesos en memoria RAM, verificación de linaje de ejecución, blindaje de LSASS (RunAsPPL) y detección de debilidades de elevación de privilegios en Windows.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nueva-heuristica-masquerading
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero dependencias externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo de codificación UTF-8 en archivos `.py` y `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile MemSentry.py
   powershell -ExecutionPolicy Bypass -File .\MemSentry.ps1 -SoloTriage
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Nuevas reglas de linaje padre-hijo anómalo para detectar inyección de procesos.
- Expansión del catálogo de procesos del sistema para detección de Process Masquerading.
- Auditoría adicional de configuraciones de seguridad en subsistemas LSA y Credential Guard.
