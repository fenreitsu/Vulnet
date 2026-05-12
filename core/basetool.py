import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod

ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

from core.models import ScanConfig, Finding, Severity


class BaseTool(ABC):
    def __init__(self, config: ScanConfig):
        self.config = config
        self._name = self.__class__.__name__.replace("Tool", "")
        self.temp_files = []
        self._process = None

    def kill(self):
        if self._process and self._process.poll() is None:
            self._process.kill()
            self._process.wait()
            try:
                self._process.stdout.close()
            except Exception:
                pass

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

    def get_skip_reason(self) -> str:
        return "comando vacío"

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
            log_callback(f"[!] {self.name}: {self.get_skip_reason()}. Saltando.")
            return []

        log_callback(f"[*] Ejecutando: {' '.join(cmd)}")
        log_callback(f"[*] Iniciando {self.name}...")

        full_output = []

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            if self.config.parallel:
                try:
                    stdout_data, _ = self._process.communicate(timeout=self.config.timeout)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    stdout_data, _ = self._process.communicate()
                full_output.append(ANSI_RE.sub('', stdout_data or ""))
            else:
                for line in self._process.stdout:
                    clean = ANSI_RE.sub('', line.strip())
                    if clean:
                        log_callback(f"   > {clean}")
                        full_output.append(ANSI_RE.sub('', line))
                self._process.wait()

            MAX_RAW_SIZE = 100 * 1024
            final = "".join(full_output)
            if len(final) > MAX_RAW_SIZE:
                final = final[:MAX_RAW_SIZE] + (
                    f"\n\n[... TRUNCATED: {len(final)} bytes. "
                    f"Mostrando primeros {MAX_RAW_SIZE}.]"
                )
            self.config.raw_outputs[self.name] = final
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
            self._process = None
            self.cleanup()
