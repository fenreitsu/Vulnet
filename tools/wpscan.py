import json
import os

from core.basetool import BaseTool
from core.models import Finding, Severity


class WPScanTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "wpscan"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        self.output_file = self.create_temp_file(".json")
        cmd = [
            "wpscan", "--url", self._get_web_target(),
            "--format", "json", "-o", self.output_file,
        ]
        if self.config.mode.value == "complejo":
            cmd.extend(["--enumerate", "vp,vt,u"])
        elif self.config.mode.value == "simple":
            cmd.extend(["--enumerate", "vp"])
        else:
            cmd.extend(["--enumerate", "vp,vt"])
        return cmd

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        if hasattr(self, "output_file") and os.path.exists(self.output_file):
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for plugin_name in data.get("plugins", {}):
                    findings.append(
                        Finding(
                            title=f"Plugin WordPress: {plugin_name}",
                            severity=Severity.MEDIUM,
                            description=f"Plugin detectado en el objetivo.",
                            remediation="Mantener actualizado.",
                            tool=self.name,
                        )
                    )
                for vuln in data.get("vulnerabilities", []):
                    findings.append(
                        Finding(
                            title=f"Vuln WP: {vuln.get('title', 'Desconocida')}",
                            severity=Severity.HIGH,
                            description=vuln.get("description", "")[:200],
                            remediation="Aplicar parche de seguridad.",
                            tool=self.name,
                        )
                    )
            except Exception:
                pass
        return findings
