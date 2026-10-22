# Guía de Contribución a SocketSentry 🤝

¡Gracias por tu interés en colaborar con **SocketSentry**! Las contribuciones de la comunidad permiten mantener las heurísticas de detección actualizadas frente a las técnicas emergentes de ciberataques.

---

## 🛠️ ¿Cómo puedes contribuir?

1. **Reportar Falsos Positivos:** Ayúdanos a ajustar la matriz de scoring para que herramientas y servicios legítimos no generen alertas innecesarias.
2. **Proponer Nuevas Reglas:** Sugerir puertos de C2 emergentes, binarios abusables de LOLBAS o patrones de CommandLine ofuscados en `db_conexiones.json`.
3. **Mejorar el Código:** Optimizar el rendimiento de las consultas CIM/WMI, el parser forense o el generador de reportes HTML.
4. **Documentación:** Traducir, corregir o agregar explicaciones didácticas para usuarios que están aprendiendo DFIR.

---

## 🚀 Flujo de Trabajo para Desarrolladores

### 1. Clonar el Repositorio
```bash
git clone https://github.com/Cru9/SocketSentry.git
cd SocketSentry
```

### 2. Crear una Rama para tu Mejora
```bash
git checkout -b feature/nueva-regla-c2
# o bien
git checkout -b fix/falso-positivo-driver
```

### 3. Probar los Cambios Localmente
Antes de proponer cambios en el script o la base de datos, ejecuta la suite de simulación para validar que el motor de evaluación funcione correctamente:

```powershell
# Probar la auditoría con inyección de procesos simulados:
.\Auditar-Conexiones.ps1 -SimularSospechoso -SoloSospechosas

# Comprobar la sincronización con feeds de Threat Intel:
.\Auditar-Conexiones.ps1 -ActualizarFeeds
```

### 4. Validar Calidad de Código (Linter)
El repositorio utiliza **PSScriptAnalyzer** en los flujos de GitHub Actions. Puedes comprobar que tu código cumple los estándares de PowerShell ejecutando:

```powershell
Invoke-ScriptAnalyzer -Path .\Auditar-Conexiones.ps1
```

---

## 📝 Estándares y Políticas Obligatorias

* **Privacidad Total (Cero Datos Personales):**
  * NUNCA envíes *commits* que incluyan rutas locales personales (ej. `C:\Users\tu_nombre\..`), nombres de tu equipo (*hostname*) o direcciones IP internas de tu empresa.
  * Los reportes generados (`Reporte-Conexiones.html`, volcados `.dmp`, etc.) están explícitamente ignorados en `.gitignore`.
* **Compatibilidad:**
  * El código debe mantenerse 100% compatible tanto con **Windows PowerShell 5.1** como con **PowerShell 7+**.
  * Evita dependencias de módulos de terceros para permitir su ejecución inmediata en entornos limpios de respuesta a incidentes.

---

## 📬 Enviar un Pull Request (PR)

1. Haz *commit* de tus cambios con mensajes descriptivos:
   ```bash
   git commit -m "feat(db): agregar detección de puerto C2 para Sliver (TCP 8888)"
   ```
2. Sube tus cambios a tu *fork*:
   ```bash
   git push origin feature/nueva-regla-c2
   ```
3. Abre un **Pull Request** detallando el motivo del cambio y cómo fue probado.
