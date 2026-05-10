from core.basetool import BaseTool
from core.models import Finding, Severity


class WapitiTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "wapiti"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return [
            "wapiti", "-u", self._get_web_target(),
            "-o", self.create_temp_file(),
            "-f", "html",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        vuln_keywords = ["vulnerable", "found", "xss", "sql", "csrf", "file inclusion"]
        for line in stdout.splitlines():
            lower = line.lower()
            for kw in vuln_keywords:
                if kw in lower:
                    findings.append(
                        Finding(
                            title=f"Posible vulnerabilidad: {kw.upper()}",
                            severity=Severity.HIGH,
                            description=line.strip()[:200],
                            remediation="Revisar el reporte HTML generado por Wapiti.",
                            tool=self.name,
                        )
                    )
                    break
        return findings
