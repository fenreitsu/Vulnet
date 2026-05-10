from core.basetool import BaseTool
from core.models import Finding, Severity


class TsharkTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "tshark"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        self.pcap_file = self.create_temp_file(".pcap")
        return [
            "tshark", "-i", "any",
            "-f", f"host {self.config.target_ip}",
            "-a", "duration:20",
            "-w", self.pcap_file,
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "packet" in line.lower() and ("captured" in line.lower()):
                findings.append(
                    Finding(
                        title="Captura de tráfico completada",
                        severity=Severity.INFO,
                        description=line.strip()[:200],
                        remediation="Analizar el archivo PCAP con Wireshark.",
                        tool=self.name,
                    )
                )
        if not findings:
            findings.append(
                Finding(
                    title="Captura de red (20s)",
                    severity=Severity.INFO,
                    description=f"Tráfico capturado hacia {self.config.target_ip}. Archivo: {getattr(self, 'pcap_file', 'N/A')}",
                    remediation="Abrir el PCAP en Wireshark para análisis detallado.",
                    tool=self.name,
                )
            )
        return findings
