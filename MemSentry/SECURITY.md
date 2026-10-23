# Política de Seguridad de MemSentry

## 🎯 Enfoque Defensivo y Forense

**MemSentry** ha sido concebido como un framework estrictamente **defensivo, de auditoría forense autorizada y de respuesta a incidentes (Blue Team / DFIR)**.

El objetivo de inspeccionar la memoria de procesos y la configuración de LSASS es blindar la infraestructura contra ataques de volcado de credenciales (Credential Dumping / Mimikatz), detectar procesos suplantados y corregir vulnerabilidades locales como Unquoted Service Paths.

---

## ⚠️ Uso Responsable

- **Sistemas Autorizados:** Esta herramienta debe ser ejecutada únicamente en sistemas de tu propiedad o en aquellos donde cuentes con autorización expresa y por escrito de sus legítimos propietarios.
- **Protección de Datos:** Las evidencias generadas pueden exponer nombres de procesos, líneas de comando activas y parámetros en memoria. Mantén los resultados bajo estricta confidencialidad profesional.

---

## 🔒 Reporte Responsable de Vulnerabilidades

Si descubres alguna vulnerabilidad o fallo en este módulo, te solicitamos seguir las mejores prácticas de divulgación responsable a través del canal central de seguridad del proyecto en [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR/security/advisories/new).
