import os

from core.basetool import BaseTool
from core.models import Finding, Severity


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠️  THC-SSL-DOS — HERRAMIENTA EXPERIMENTAL — USO BAJO TU RESPONSABILIDAD  ║
╚══════════════════════════════════════════════════════════════════════╝

¿Qué hace?
  THC-SSL-DOS es una herramienta de Denegación de Servicio (DoS) contra
  servicios SSL/TLS. Envía peticiones de renegociación SSL masivamente
  para agotar los recursos de CPU del servidor objetivo.

Riesgos y advertencias:
  1. ILEGAL sin autorización — Usarlo contra un objetivo que no te
     pertenece o sin permiso escrito expreso viola leyes de delitos
     informáticos en la mayoría de países (posibles penas de cárcel).

  2. Daño colateral real — Puede tumbar el servidor objetivo,
     afectando a todos los usuarios y servicios que dependen de él.

  3. No es un escáner — No detecta vulnerabilidades, las EXPLOTA
     activamente. No es una herramienta de auditoría pasiva.

  4. Requiere root — Necesita privilegios de administrador para
     funcionar (raw sockets).

  5. Invasivo — No hay forma de ejecutarlo de forma "ligera" o
     "no intrusiva". Su único propósito es saturar.

Recomendación:
  NO uses esta herramienta a menos que:
  - El objetivo sea de tu propiedad.
  - Tengas autorización por escrito para hacer pruebas de estrés.
  - Estés en un entorno controlado (laboratorio, CTF propio).

Por defecto, Vulnet la trae DESHABILITADA. Debes activarla explícitamente.
"""


class THCSSLDOSTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "thc-ssl-dos"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    @classmethod
    def show_disclaimer(cls) -> bool:
        from core.console import console
        console.print(DISCLAIMER, style="bold red")
        result = console.input(
            "\n[bold red]Escribe 'ACEPTO' para continuar (cualquier otra cosa cancela): [/]"
        ).strip()
        return result == "ACEPTO"

    def build_command(self) -> list[str]:
        try:
            if os.geteuid() != 0:
                return []
        except AttributeError:
            return []
        return [
            "thc-ssl-dos",
            self.config.target_domain,
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        if not stdout.strip():
            return []
        return [
            Finding(
                title="THC-SSL-DOS ejecutado",
                severity=Severity.INFO,
                description="Prueba de estrés SSL completada. Revisar disponibilidad del servidor objetivo.",
                remediation="No aplica — herramienta experimental de estrés, no un hallazgo de seguridad.",
                tool=self.name,
            )
        ]
