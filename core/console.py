import platform
import sys
from datetime import datetime

import colorama
from rich.console import Console

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.text import Text
from rich import box

from core.models import Severity, Finding

colorama.just_fix_windows_console()

console = Console(legacy_windows=False)

SEVERITY_STYLES = {
    Severity.CRITICAL: ("🔴", "red", "bright_red"),
    Severity.HIGH: ("🟠", "orange1", "dark_orange"),
    Severity.MEDIUM: ("🟡", "yellow", "gold1"),
    Severity.LOW: ("🟢", "green", "green"),
    Severity.INFO: ("🔵", "blue", "cyan"),
    Severity.CLEAN: ("✅", "white", "grey62"),
}


def print_banner():
    banner = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗████████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝╚══██╔══╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗     ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝     ██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗   ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝     - by @Fenreitsu
    """
    console.print(Panel(Text(banner, style="bold cyan"), box=box.ROUNDED))
    console.print(
        f"   Security Vulnerability Test CLI  v1.0  |  {datetime.now():%Y-%m-%d %H:%M}\n",
        style="italic grey62",
    )


def print_os_warning():
    console.print(
        Panel(
            Text(
                "⚠️  Vulnet en Windows — Funcionalidad Limitada\n\n"
                "11 de 21 herramientas disponibles.\n"
                "Las herramientas Linux-only se omitirán automáticamente.\n"
                "Para experiencia completa: usa WSL o Linux nativo.",
                style="bold yellow",
            ),
            title="Aviso",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def print_health_check(tools_status: dict[str, bool], os_name: str):
    table = Table(
        title=f"🔍 Health Check — {os_name}",
        box=box.SIMPLE,
        title_style="bold cyan",
    )
    table.add_column("Estado", width=4)
    table.add_column("Herramienta", width=20)
    table.add_column("Compatible", width=12)

    for name, (installed, compatible) in sorted(tools_status.items()):
        if installed:
            icon = "✅"
            status = "Instalada"
            style = "green"
        elif not compatible:
            icon = "⛔"
            status = "No compatible"
            style = "red"
        else:
            icon = "❌"
            status = "No instalada"
            style = "yellow"

        compat = "✅ Sí" if compatible else "❌ No"
        table.add_row(icon, name, compat, style=style)

    console.print(table)
    console.print()


def print_mode_info(mode: str, target: str, ip: str, tools_count: int):
    console.print(
        Panel(
            Text(
                f"Target: {target} ({ip})\n"
                f"Modo: {mode.upper()}\n"
                f"Herramientas activas: {tools_count}",
                style="bold white",
            ),
            title="🚀 Iniciando escaneo",
            border_style="green",
            box=box.ROUNDED,
        )
    )
    console.print()


def print_findings_table(findings: list[Finding]):
    if not findings:
        console.print("\n[bold yellow]No hay hallazgos para mostrar.[/]\n")
        return

    table = Table(box=box.SIMPLE, title="📊 Resultados", title_style="bold cyan")
    table.add_column("Severidad", width=10)
    table.add_column("Herramienta", width=14)
    table.add_column("Hallazgo", width=50)
    table.add_column("Acción", width=30)

    for f in findings:
        emoji, color, _ = SEVERITY_STYLES.get(f.severity, ("", "white", "grey"))
        table.add_row(
            f"{emoji} {f.severity.value}",
            f.tool,
            f.title,
            f.remediation,
            style=color,
        )

    console.print(table)
    console.print()


def print_stats(findings: list[Finding]):
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in Severity:
        emoji, _, style = SEVERITY_STYLES.get(sev, ("", "white", "grey62"))
        count = counts.get(sev, 0)
        if count > 0:
            parts.append(f"[{style}]{emoji} {sev.value}: {count}[/]")

    stats = "  |  ".join(parts)
    console.print(f"[bold]📈 Estadísticas:[/] {len(findings)} hallazgos totales")
    console.print(stats)
    console.print()


def create_progress():
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


def print_separator():
    console.print("-" * 60, style="grey62")


def print_step(step: int, total: int, message: str):
    console.print(f"\n[bold cyan][{step}/{total}][/] {message}")


def ask_yes_no(prompt: str) -> bool:
    result = console.input(f"\n[bold]{prompt}[/] [cyan](s/n)[/]: ").strip().lower()
    return result == "s" or result == "si" or result == "sí"


def ask_choice(prompt: str, options: list[str], default: int = 0) -> int:
    console.print(f"\n[bold]{prompt}[/]")
    for i, opt in enumerate(options, 1):
        console.print(f"  [{i}] {opt}")
    result = console.input(f"[cyan]Selección[/] [default {default}]: ").strip()
    if not result:
        return default
    try:
        return int(result)
    except ValueError:
        return default


def ask_input(prompt: str, default: str = "") -> str:
    if default:
        result = console.input(f"[bold]{prompt}[/] [grey62](default: {default})[/]: ").strip()
    else:
        result = console.input(f"[bold]{prompt}[/]: ").strip()
    return result if result else default
