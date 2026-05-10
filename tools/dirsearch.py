import json
import os

from core.basetool import BaseTool
from core.models import Finding, Severity


class DirsearchTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "dirsearch"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        self.output_file = self.create_temp_file(".json")
        return [
            "dirsearch", "-u", self._get_web_target(),
            "--format=json", "-o", self.output_file,
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        if hasattr(self, "output_file") and os.path.exists(self.output_file):
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    if r.get("status") in (200, 301, 302, 403):
                        findings.append(
                            Finding(
                                title=f"Directorio: {r['path']}",
                                severity=Severity.MEDIUM,
                                description=f"Estado HTTP: {r['status']} — Accesible",
                                remediation="Revisar si debe estar expuesto.",
                                tool=self.name,
                            )
                        )
            except Exception:
                pass
        return findings
