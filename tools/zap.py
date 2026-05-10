from core.basetool import BaseTool
from core.models import Finding, Severity


class ZAPTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "zap-cli"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        return [
            "zap-cli", "quick-scan",
            "--self-contained",
            "--start-options", "-daemon",
            self._get_web_target(),
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            lower = line.lower()
            if "alert" in lower and ("high" in lower or "medium" in lower):
                findings.append(
                    Finding(
                        title="Alerta OWASP ZAP",
                        severity=Severity.HIGH,
                        description=line.strip()[:200],
                        remediation="Revisar el reporte detallado de ZAP.",
                        tool=self.name,
                    )
                )
        return findings
