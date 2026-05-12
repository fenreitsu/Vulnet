from enum import Enum
from dataclasses import dataclass, field


class Severity(Enum):
    CRITICAL = "CRÍTICO"
    HIGH = "ALTO"
    MEDIUM = "MEDIO"
    LOW = "BAJO"
    INFO = "INFO"
    CLEAN = "LIMPIO"


class Mode(Enum):
    SIMPLE = "simple"
    NORMAL = "normal"
    COMPLEX = "complejo"
    CUSTOM = "personalizado"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    remediation: str
    tool: str
    raw_output: str = ""


@dataclass
class ScanConfig:
    target_ip: str
    target_domain: str
    mode: Mode
    wordlist: str
    timeout: int
    selected_tools: list[str] = field(default_factory=list)
    output_formats: list[str] = field(default_factory=lambda: ["csv", "json"])
    parallel: bool = False
    output_dir: str = "./reports"
    raw_outputs: dict[str, str] = field(default_factory=dict)
