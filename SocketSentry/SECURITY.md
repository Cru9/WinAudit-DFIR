# Política de Seguridad y Descargo de Responsabilidad

## ⚖️ Descargo de Responsabilidad Ética (Disclaimer)

**SocketSentry** es una herramienta de código abierto desarrollada exclusivamente con fines defensivos, educativos, de auditoría autorizada y respuesta ante incidentes (DFIR).

* Este software debe utilizarse únicamente en sistemas y redes donde cuentes con la debida **autorización expresa** del propietario o administrador.
* Los autores y colaboradores no se hacen responsables del uso indebido, negligente o no autorizado de esta herramienta, ni de cualquier consecuencia derivada de la aplicación de medidas de contención (como el bloqueo de direcciones IP en el Firewall de Windows).

---

## 🔒 Versiones Compatibles

Actualmente se brinda soporte y mantenimiento para las siguientes versiones de entorno:

| Entorno / Shell | Versión | Estado de Soporte |
| :--- | :--- | :--- |
| Windows PowerShell | 5.1 (Nativo en Windows 10/11/Server) | ✅ Compatible |
| PowerShell Core | 7.x+ (Multiplataforma) | ✅ Compatible |
| Sistema Operativo | Windows 10, Windows 11, Windows Server 2016+ | ✅ Compatible |

---

## 📢 Reporte de Vulnerabilidades o Fallos de Seguridad

Si descubres una posible vulnerabilidad de seguridad en el código de **SocketSentry** (por ejemplo, una posibilidad de inyección en comandos CIM/WMI o elevación no controlada):

1. **NO** abras un Issue público en GitHub.
2. Abre un **Security Advisory Privado** a través de la pestaña **Security > Advisories** en el repositorio de GitHub.
3. Proporciona los detalles técnicos del hallazgo, un escenario de reproducción (*PoC*) y la versión de PowerShell/Windows donde ocurre.
4. Se revisará y responderá a la brevedad para coordinar la publicación de un parche de seguridad de forma responsable.

---

## 🟢 Reporte de Falsos Positivos

Si un software legítimo (por ejemplo, un antivirus corporativo, driver o herramienta de desarrollo) recibe una puntuación alta de sospecha:
* Consulta la guía en [`CONTRIBUTING.md`](./CONTRIBUTING.md) o abre un Issue utilizando la plantilla de **Reporte de Falso Positivo**.
* La comunidad evalúa continuamente las exclusiones para mantener la base de datos lo más precisa y libre de ruido posible.
