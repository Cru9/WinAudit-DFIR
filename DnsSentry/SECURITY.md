# Política de Seguridad de DnsSentry

## 🎯 Enfoque Defensivo y Forense

**DnsSentry** ha sido concebido como un framework estrictamente **defensivo, de auditoría forense autorizada y de respuesta a incidentes (Blue Team / DFIR)**.

El objetivo de inspeccionar la caché DNS y el archivo `hosts` es descubrir vectores de comunicación C2, exfiltración encubierta por subdominios, algoritmos de generación de dominios (DGA) y técnicas de evasión o sinkholing que intenten bloquear herramientas de seguridad o redirigir el tráfico del sistema.

---

## ⚠️ Uso Responsable

- **Sistemas Autorizados:** Esta herramienta debe ser ejecutada únicamente en sistemas de tu propiedad o en aquellos donde cuentes con autorización expresa y por escrito de sus legítimos propietarios.
- **Protección de Datos:** Las evidencias generadas pueden listar dominios visitados y consultas DNS de usuarios del sistema auditado. Almacena y procesa los reportes bajo estricta confidencialidad.

---

## 🔒 Reporte Responsable de Vulnerabilidades

Si descubres alguna vulnerabilidad o vector de evasión en este módulo, te solicitamos seguir las mejores prácticas de divulgación responsable a través del canal central de seguridad del proyecto en [Cru9/WinAudit-DFIR](https://github.com/Cru9/WinAudit-DFIR/security/advisories/new).
