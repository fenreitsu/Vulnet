from core.basetool import BaseTool
from core.models import Finding, Severity


class AmassTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "amass"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Windows", "Linux"]

    def build_command(self) -> list[str]:
        return ["amass", "enum", "-d", self.config.target_domain, "-passive"]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        lines = [l for l in stdout.splitlines() if l.strip()]
        if lines:
            subdomains = [l.strip() for l in lines if "." in l and "%" not in l][:10]
            if subdomains:
                findings.append(
                    Finding(
                        title=f"Subdominios: {len(subdomains)} encontrados",
                        severity=Severity.INFO,
                        description="\n".join(subdomains),
                        remediation="Revisar superficie de ataque.",
                        tool=self.name,
                    )
                )
        return findings
