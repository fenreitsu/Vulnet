import xml.etree.ElementTree as ET

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
        cmd = ["nmap", self.config.target_ip, "-oX", "-", "--open", "-v"]
        if self.config.mode.value == "complejo":
            cmd[1:1] = ["-p-", "-sV", "-sC", "-O", "-T4"]
        elif self.config.mode.value == "simple":
            cmd[1:1] = ["-sV", "--version-light", "-F"]
        else:
            cmd[1:1] = ["-sV", "-sC", "-T4"]
        return cmd

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        try:
            start = stdout.find("<?xml")
            if start != -1:
                root = ET.fromstring(stdout[start:])
                for port in root.findall(".//port"):
                    pid = port.get("portid")
                    svc = port.find("service")
                    svc_name = svc.get("name", "?") if svc is not None else "?"
                    findings.append(
                        Finding(
                            title=f"Puerto {pid} abierto",
                            severity=Severity.MEDIUM,
                            description=f"Servicio detectado: {svc_name}",
                            remediation="Revisar si este puerto debe estar expuesto.",
                            tool=self.name,
                        )
                    )
        except Exception:
            pass
        return findings
