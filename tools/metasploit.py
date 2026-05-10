from core.basetool import BaseTool
from core.models import Finding, Severity


class MetasploitTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "msfconsole"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        self.resource_file = self.create_temp_file(".rc")
        with open(self.resource_file, "w") as f:
            f.write(
                f"use auxiliary/scanner/portscan/tcp\n"
                f"set RHOSTS {self.config.target_ip}\n"
                f"set PORTS 80,443,22\n"
                f"run\n"
                f"exit\n"
            )
        return ["msfconsole", "-q", "-r", self.resource_file]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "TCP OPEN" in line:
                findings.append(
                    Finding(
                        title=f"Puerto abierto (Metasploit)",
                        severity=Severity.INFO,
                        description=line.strip()[:150],
                        remediation="Verificar necesidad del puerto.",
                        tool=self.name,
                    )
                )
        return findings
