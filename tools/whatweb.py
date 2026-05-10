from core.basetool import BaseTool
from core.models import Finding, Severity


class WhatWebTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "whatweb"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return ["whatweb", self._get_web_target()]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        line = stdout.strip()
        if line:
            findings.append(
                Finding(
                    title="Fingerprint web (WhatWeb)",
                    severity=Severity.INFO,
                    description=line[:300],
                    remediation="Usar esta información para enfocar el escaneo.",
                    tool=self.name,
                )
            )
        return findings
