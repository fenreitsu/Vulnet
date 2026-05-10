from core.basetool import BaseTool
from core.models import Finding, Severity


class HydraTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "hydra"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        if not self.config.wordlist:
            return []
        return [
            "hydra", "-l", "root", "-P", self.config.wordlist,
            "ssh://" + self.config.target_ip,
            "-t", "1", "-s", "22",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        if "password:" in stdout.lower() or "login:" in stdout.lower():
            findings.append(
                Finding(
                    title="Credencial SSH encontrada",
                    severity=Severity.CRITICAL,
                    description="Hydra encontró una contraseña válida para SSH.",
                    remediation="Cambiar la contraseña inmediatamente. Usar autenticación por clave.",
                    tool=self.name,
                )
            )
        return findings
