from core.basetool import BaseTool
from core.models import Finding, Severity


class FierceTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "fierce"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return ["fierce", "-dns", self.config.target_domain]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        subdomains = [l for l in lines if "." in l and not l.startswith("fierce")][:10]
        if subdomains:
            findings.append(
                Finding(
                    title=f"Subdominios (Fierce): {len(subdomains)}",
                    severity=Severity.INFO,
                    description="\n".join(subdomains),
                    remediation="Revisar subdominios para ampliar superficie de ataque.",
                    tool=self.name,
                )
            )
        return findings
