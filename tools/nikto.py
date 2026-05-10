from core.basetool import BaseTool
from core.models import Finding, Severity


class NiktoTool(BaseTool):
    @classmethod
    def get_executable(cls) -> str:
        return "nikto"

    @classmethod
    def supported_os(cls) -> list[str]:
        return ["Linux"]

    def build_command(self) -> list[str]:
        return [
            "nikto", "-h", self._get_web_target(),
            "-Format", "xml", "-o", "-",
        ]

    def parse_results(self, stdout: str) -> list[Finding]:
        findings = []
        try:
            if "<?xml" in stdout:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(stdout[stdout.find("<?xml"):])
                for item in root.findall(".//item"):
                    desc = item.findtext("description", "")[:150]
                    findings.append(
                        Finding(
                            title="Vulnerabilidad web detectada",
                            severity=Severity.HIGH,
                            description=desc,
                            remediation="Revisar y corregir la vulnerabilidad reportada.",
                            tool=self.name,
                        )
                    )
        except Exception:
            pass
        return findings
