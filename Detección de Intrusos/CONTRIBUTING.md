# Guía de Contribución a IntruderDetector

¡Gracias por tu interés en colaborar con **IntruderDetector** y el ecosistema **WinAudit-DFIR** de [Cru9](https://github.com/Cru9)!

---

## 🚀 Cómo Contribuir

1. **Fork del Repositorio:** Haz un fork del repositorio principal `Cru9/WinAudit-DFIR`.
2. **Crear una Rama:** Crea una rama descriptiva para tu función o corrección:
   ```bash
   git checkout -b feature/nuevo-detector-evento
   ```
3. **Estándares de Código:**
   - **Python:** Compatible con Python 3.8+ sin dependencias externas obligatorias (`pip`). Utilizar librerías estándar siempre que sea posible.
   - **PowerShell:** Compatible con Windows PowerShell 5.1 y PowerShell 7+.
   - **Mapeo MITRE:** Si agregas una nueva regla de detección de eventos, documenta su técnica y táctica MITRE ATT&CK correspondiente.
4. **Pull Request:** Envía tu Pull Request con una descripción detallada de las pruebas realizadas.
