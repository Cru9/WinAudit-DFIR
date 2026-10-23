# Guía de Contribución a DnsSentry

¡Gracias por tu interés en colaborar con **DnsSentry**! Este módulo está enfocado en la investigación forense de la memoria caché DNS, algoritmos DGA, túneles C2 e integridad del archivo Hosts en Windows.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio principal [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR).
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nuevo-detector-dga
   ```
3. **Realiza tus cambios** manteniendo los estándares innegociables:
   - Cero dependencias externas de terceros en Python (`0 pip` - exclusivamente Biblioteca Estándar).
   - Compatibilidad dual en PowerShell 5.1+ y 7+.
   - Manejo de codificación UTF-8 en archivos `.py` y `.ps1`.
4. **Valida la sintaxis localmente:**
   ```powershell
   python -m py_compile DnsSentry.py
   powershell -ExecutionPolicy Bypass -File .\DnsSentry.ps1 -SoloTriage
   ```
5. **Envía un Pull Request** explicando claramente los beneficios técnicos de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Nuevas heurísticas para detección de dominios DGA y cálculo de entropía de Shannon.
- Firmas adicionales de proveedores de túneles dinámicos (Cloudflare, Ngrok, etc.).
- Verificación de políticas DoH (DNS over HTTPS) y DoT en navegadores y sistema.
