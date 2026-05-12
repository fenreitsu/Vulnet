from datetime import datetime
from pathlib import Path

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
        pcap_dir = Path(self.config.output_dir) / "tshark_captures"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        safe_target = self.config.target_domain.replace(".", "_")
        self.pcap_file = str(
            pcap_dir / f"{safe_target}_{datetime.now():%Y%m%d_%H%M%S}.pcap"
        )
        return [
            "tshark", "-i", "any",
            "-f", f"host {self.config.target_ip}",
            "-a", "duration:20",
            "-w", self.pcap_file,
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            if "packet" in line.lower() and "captured" in line.lower():
                findings.append(
                    Finding(
                        title="Captura de tráfico completada",
                        severity=Severity.INFO,
                        description=line.strip()[:200],
                        remediation=f"Analizar el PCAP en: {self.pcap_file}",
                        tool=self.name,
                    )
                )
        if not findings:
            findings.append(
                Finding(
                    title="Captura de red (20s)",
                    severity=Severity.INFO,
                    description=f"Tráfico capturado hacia {self.config.target_ip}. Archivo: {self.pcap_file}",
                    remediation=f"Abrir el PCAP en Wireshark: {self.pcap_file}",
                    tool=self.name,
                )
            )
        return findings

    def cleanup(self):
        pass
