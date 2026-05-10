from core.basetool import BaseTool
from core.models import Finding, Severity


class SkipfishTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "skipfish"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        self.output_dir = self.create_temp_dir(suffix="")
        return [
            "skipfish", "-o", self.output_dir,
            self._get_web_target(),
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        for line in stdout.splitlines():
            lower = line.lower()
            if "issue" in lower and ("high" in lower or "medium" in lower):
                findings.append(
                    Finding(
                        title="Issue detectado por Skipfish",
                        severity=Severity.HIGH,
                        description=line.strip()[:200],
                        remediation="Revisar el reporte HTML en el directorio de salida.",
                        tool=self.name,
                    )
                )
        return findings
