# Guía de Contribución a WiFiSentry

¡Gracias por tu interés en colaborar con **WiFiSentry**! Esta herramienta está orientada a la educación en ciberseguridad, respuesta a incidentes (DFIR) y concientización sobre seguridad inalámbrica.

---

## 🛠️ ¿Cómo contribuir?

1. **Haz un Fork** del repositorio.
2. **Crea una rama descriptiva** para tu mejora:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. **Realiza tus cambios** manteniendo la compatibilidad:
   - Los scripts de PowerShell (`WiFiSentry.ps1`) deben ser compatibles tanto con Windows PowerShell 5.1 como con PowerShell 7+.
   - El script de Python (`WiFiSentry.py`) debe ejecutarse con la biblioteca estándar sin requerir dependencias de `pip` obligatorias.
4. **Verifica la ejecución:**
   - Asegúrate de que los comandos no generen excepciones en consolas con codificación cp1252 o UTF-8.
   - Prueba las opciones interactivas y la generación de reportes HTML.
5. **Envía un Pull Request** explicando claramente los beneficios de tu cambio.

---

## 💡 Ideas de mejoras bienvenidas:
- Soporte para exportación a formatos estructurados (JSON, CSV).
- Detección de perfiles empresariales con autenticación 802.1X y certificados EAP-TLS.
- Soporte extendido para NetworkManager y iwd en distribuciones Linux.
- Nuevos módulos didácticos sobre ataques KRACK, Dragonblood o WPS Pixie Dust.

---

## 📜 Código de Conducta
Mantén siempre una comunicación respetuosa, constructiva y enfocada en el aprendizaje mutuo.
