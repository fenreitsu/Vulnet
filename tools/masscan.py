from core.basetool import BaseTool
from core.models import Finding, Severity


class MasscanTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "masscan"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return [
            "masscan", self.config.target_ip,
            "-p80,443,22,8080,8443",
            "--rate=1000",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "open" in line.lower() and "port" in line.lower():
                findings.append(
                    Finding(
                        title=f"Puerto detectado (Masscan)",
                        severity=Severity.INFO,
                        description=line.strip()[:150],
                        remediation="Verificar si el puerto debe estar accesible.",
                        tool=self.name,
                    )
                )
        return findings
