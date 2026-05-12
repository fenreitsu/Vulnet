from core.basetool import BaseTool
from core.models import Finding, Severity, ScanConfig


class NmapTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "nmap"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        cmd = ["nmap", self.config.target_ip, "-oN", "-", "--open", "-v"]
        if self.config.mode.value == "complejo":
            cmd[1:1] = ["-p-", "-sV", "-sC", "-O", "-T4"]
        elif self.config.mode.value == "simple":
            cmd[1:1] = ["-sV", "--version-light", "-F"]
        else:
            cmd[1:1] = ["-sV", "-sC", "-T4"]
        return cmd

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                svc_name = parts[2] if len(parts) > 2 else "?"
                findings.append(
                    Finding(
                        title=f"Puerto {port} abierto",
                        severity=Severity.MEDIUM,
                        description=f"Servicio detectado: {svc_name}",
                        remediation="Revisar si este puerto debe estar expuesto.",
                        tool=self.name,
                    )
                )
        return findings
