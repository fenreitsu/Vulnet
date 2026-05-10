from core.basetool import BaseTool
from core.models import Finding, Severity


class DNSenumTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "dnsenum"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return ["dnsenum", self.config.target_domain]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            lower = line.lower()
            if "host" in lower and "found" in lower:
                findings.append(
                    Finding(
                        title="Host encontrado (DNSenum)",
                        severity=Severity.INFO,
                        description=line.strip()[:200],
                        remediation="Registrar para análisis de superficie.",
                        tool=self.name,
                    )
                )
        return findings
