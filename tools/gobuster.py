from core.basetool import BaseTool
from core.models import Finding, Severity


class GobusterTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "gobuster"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        if not self.config.wordlist:
            return []
        return [
            "gobuster", "dir", "-u", self._get_web_target(),
            "-w", self.config.wordlist,
            "--no-error", "-z",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "Status:" in line and ("200" in line or "301" in line or "403" in line):
                findings.append(
                    Finding(
                        title="Ruta encontrada (Gobuster)",
                        severity=Severity.MEDIUM,
                        description=line.strip()[:200],
                        remediation="Revisar si el recurso debe ser público.",
                        tool=self.name,
                    )
                )
        return findings
