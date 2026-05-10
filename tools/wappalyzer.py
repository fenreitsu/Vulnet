from core.basetool import BaseTool
from core.models import Finding, Severity


class WappalyzerTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "wappalyzer"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        return ["wappalyzer", self._get_web_target()]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        if lines:
            techs = []
            for line in lines:
                techs.append(line)
            findings.append(
                Finding(
                    title=f"Tecnologías detectadas: {len(techs)}",
                    severity=Severity.INFO,
                    description="\n".join(techs[:15]),
                    remediation="Conocer las tecnologías ayuda a evaluar vectores de ataque.",
                    tool=self.name,
                )
            )
        return findings
