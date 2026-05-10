import platform

from tools.nmap import NmapTool
from tools.nikto import NiktoTool
from tools.sqlmap import SQLmapTool
from tools.dirsearch import DirsearchTool
from tools.wpscan import WPScanTool
from tools.sslyze import SSLyzeTool
from tools.masscan import MasscanTool
from tools.gobuster import GobusterTool
from tools.amass import AmassTool
from tools.hydra import HydraTool
from tools.metasploit import MetasploitTool
from tools.wapiti import WapitiTool
from tools.zap import ZAPTool
from tools.wappalyzer import WappalyzerTool
from tools.whatweb import WhatWebTool
from tools.googler import GooglerTool
from tools.skipfish import SkipfishTool
from tools.tshark import TsharkTool
from tools.fierce import FierceTool
from tools.dnsenum import DNSenumTool
from tools.thc_ssl_dos import THCSSLDOSTool

TOOL_REGISTRY = {
    "Nmap": NmapTool,
    "Nikto": NiktoTool,
    "SQLmap": SQLmapTool,
    "Dirsearch": DirsearchTool,
    "WPScan": WPScanTool,
    "SSLyze": SSLyzeTool,
    "Masscan": MasscanTool,
    "Gobuster": GobusterTool,
    "Amass": AmassTool,
    "Hydra": HydraTool,
    "Metasploit": MetasploitTool,
    "Wapiti": WapitiTool,
    "ZAP": ZAPTool,
    "Wappalyzer": WappalyzerTool,
    "WhatWeb": WhatWebTool,
    "Googler": GooglerTool,
    "Skipfish": SkipfishTool,
    "Tshark": TsharkTool,
    "Fierce": FierceTool,
    "DNSenum": DNSenumTool,
    "THC-SSL-DOS": THCSSLDOSTool,
}


def get_tools_for_os() -> dict[str, tuple[bool, bool]]:
    current_os = platform.system()
    return {
        name: (cls.check_installed(), current_os in cls.supported_os())
        for name, cls in TOOL_REGISTRY.items()
    }


def get_active_tools(selected_names: list[str]) -> list:
    return [TOOL_REGISTRY[name] for name in selected_names if name in TOOL_REGISTRY]
