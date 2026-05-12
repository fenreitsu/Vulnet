from core.basetool import BaseTool
from core.models import Finding, Severity


class SSLyzeTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "sslyze"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        return ["sslyze", self.config.target_domain]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        if "VULNERABLE" in stdout:
            findings.append(
                Finding(
                    title="SSL/TLS Vulnerable",
                    severity=Severity.HIGH,
                    description="Se encontraron configuraciones SSL/TLS débiles o vulnerables.",
                    remediation="Hardenizar la configuración SSL/TLS (deshabilitar protocolos antiguos, usar TLS 1.2+).",
                    tool=self.name,
                )
            )
        if "EXPIRED" in stdout:
            findings.append(
                Finding(
                    title="Certificado Expirado",
                    severity=Severity.MEDIUM,
                    description="El certificado SSL ha expirado.",
                    remediation="Renovar el certificado SSL.",
                    tool=self.name,
                )
            )
        return findings
