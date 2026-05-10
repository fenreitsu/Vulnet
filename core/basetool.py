import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod

from core.models import ScanConfig, Finding, Severity


class BaseTool(ABC):
    def __init__(self, config: ScanConfig):
        self.config = config
        self._name = self.__class__.__name__.replace("Tool", "")
        self.temp_files = []

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    @abstractmethod
    def get_executable(cls) -> str:
        ...

    @classmethod
    def check_installed(cls) -> bool:
        return shutil.which(cls.get_executable()) is not None

    @classmethod
    @abstractmethod
    def supported_os(cls) -> list[str]:
        ...

    @abstractmethod
    def build_command(self) -> list[str]:
        ...

    @abstractmethod
    def parse_results(self, stdout: str) -> list[Finding]:
        ...

    def create_temp_file(self, suffix=".txt"):
        fd, path = tempfile.mkstemp(suffix=f"_{self.name}{suffix}")
        os.close(fd)
        self.temp_files.append(path)
        return path

    def create_temp_dir(self, suffix=""):
        path = tempfile.mkdtemp(suffix=f"_{self.name}{suffix}")
        self.temp_files.append(path)
        return path

    def cleanup(self):
        for f in self.temp_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def _get_web_target(self) -> str:
        return f"http://{self.config.target_domain}"

    def run(self, log_callback) -> list[Finding]:
        if not self.check_installed():
            log_callback(
                f"[!] {self.name} NO instalada. Saltando."
            )
            return [
                Finding(
                    title="Herramienta no instalada",
                    severity=Severity.INFO,
                    description=f"No se encontró '{self.get_executable()}' en el PATH.",
                    remediation="Instalar la herramienta.",
                    tool=self.name,
                )
            ]

        cmd = self.build_command()
        if not cmd:
            log_callback(f"[!] {self.name}: comando vacío. Saltando.")
            return []

        log_callback(f"[*] Ejecutando: {' '.join(cmd)}")
        log_callback(f"[*] Iniciando {self.name}...")

        full_output = []

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            for line in process.stdout:
                clean = line.strip()
                if clean:
                    log_callback(f"   > {clean}")
                    full_output.append(line)

            process.wait()
            final = "".join(full_output)
            results = self.parse_results(final)

            if not results:
                results.append(
                    Finding(
                        title="Sin hallazgos",
                        severity=Severity.CLEAN,
                        description="Ejecución correcta sin vulnerabilidades reportadas.",
                        remediation="-",
                        tool=self.name,
                    )
                )

            return results

        except Exception as e:
            log_callback(f"[!] Error en {self.name}: {e}")
            return [
                Finding(
                    title="Error de ejecución",
                    severity=Severity.LOW,
                    description=str(e),
                    remediation="Revisar instalación o permisos.",
                    tool=self.name,
                )
            ]
        finally:
            self.cleanup()
