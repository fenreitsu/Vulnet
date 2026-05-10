from core.basetool import BaseTool
from core.models import Finding, Severity


class GooglerTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "googler"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return [
            "googler", "-n", "20",
            f"site:{self.config.target_domain} inurl:login",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        results = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("googler")]
        if results:
            findings.append(
                Finding(
                    title=f"Google Dorks: {len(results)} resultados",
                    severity=Severity.INFO,
                    description="\n".join(results[:10]),
                    remediation="Revisar los resultados de OSINT encontrados.",
                    tool=self.name,
                )
            )
        return findings
