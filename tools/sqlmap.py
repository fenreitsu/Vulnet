from core.basetool import BaseTool
from core.models import Finding, Severity


class SQLmapTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "sqlmap"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        cmd = ["sqlmap", "-u", self._get_web_target(), "--batch", "--banner"]
        if self.config.mode.value == "complejo":
            cmd.extend(["--level", "3", "--risk", "2"])
        elif self.config.mode.value == "simple":
            cmd.extend(["--level", "1"])
        else:
            cmd.extend(["--level", "2"])
        return cmd

    def parse_results(self, stdout: str) -> list[Finding]:
        if "vulnerable" in stdout.lower():
            return [
                Finding(
                    title="SQLi Detectada",
                    severity=Severity.CRITICAL,
                    description="SQLmap encontró una inyección SQL potencial.",
                    remediation="Sanitizar y parametrizar todas las consultas SQL.",
                    tool=self.name,
                )
            ]
        return []
