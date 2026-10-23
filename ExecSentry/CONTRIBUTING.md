# Guía de Contribución a ExecSentry

¡Gracias por tu interés en colaborar con **ExecSentry**! Este módulo está enfocado en la reconstrucción forense de evidencia de ejecución en Windows (DFIR) mediante artefactos como Prefetch (.pf), UserAssist (ROT13) y BAM/DAM.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nuevo-parser-prefetch
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero dependencias externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo de codificación UTF-8 en archivos `.py` y `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile ExecSentry.py
   powershell -ExecutionPolicy Bypass -File .\ExecSentry.ps1 -SoloTriage
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Soporte para descompresión LZXPRESS en Windows 10/11 Prefetch con Python puro.
- Nuevos decodificadores de artefactos de ejecución forense (Shimcache, Amcache, SRUM).
- Reglas heurísticas avanzadas para detección de binarios renombrados o de doble extensión.
