#!/usr/bin/env python3
import argparse
import ipaddress
import os
import platform
import socket
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

import yaml

from core.console import (
    console,
    print_banner,
    print_os_warning,
    print_root_warning,
    print_health_check,
    print_mode_info,
    print_findings_table,
    print_stats,
    print_separator,
    print_step,
    ask_yes_no,
    ask_choice,
    ask_input,
    create_progress,
)
from core.exporter import export_all
from core.models import ScanConfig, Mode
from tools import TOOL_REGISTRY, get_tools_for_os, get_active_tools
from tools.thc_ssl_dos import THCSSLDOSTool

MODE_TIMEOUTS = {Mode.SIMPLE: 120, Mode.NORMAL: 300, Mode.COMPLEX: 600, Mode.CUSTOM: 600}


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_wordlist(config: dict, os_name: str, config_mode: str) -> str:
    os_key = "windows" if os_name == "Windows" else "linux"
    os_block = config.get(os_key, {})
    wordlists = os_block.get("wordlists", {})

    wordlist_options = []
    if wordlists.get("directory"):
        wordlist_options.append(("Por defecto (directory)", wordlists["directory"]))
    if wordlists.get("passwords"):
        wordlist_options.append(("Passwords", wordlists["passwords"]))
    if wordlists.get("subdomains"):
        wordlist_options.append(("Subdominios", wordlists["subdomains"]))
    for entry in wordlists.get("custom", []):
        wordlist_options.append((f"{entry['alias']}", entry["path"]))

    if config_mode != "custom":
        wordlist_options = [opt for opt in wordlist_options if "passwords" not in opt[0].lower()]

    if not wordlist_options:
        return ask_input("Ruta de wordlist (o Enter para omitir)")

    console.print("\n[bold]Selecciona wordlist:[/]")
    options_display = [label for label, _ in wordlist_options]
    options_display.append("Ingresar ruta manual")

    choice = ask_choice("Wordlist", options_display, default=1)
    if choice == len(options_display):
        return ask_input("Ruta de wordlist")
    return wordlist_options[choice - 1][1]


def is_valid_ip(raw: str) -> bool:
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def resolve_target(raw: str, scan_type: str) -> tuple[str, str]:
    tmp = raw if "://" in raw else "http://" + raw
    host = urlparse(tmp).hostname or raw

    if scan_type == "ip":
        ip = host
        domain = ip
    else:
        domain = host
        info = socket.getaddrinfo(domain, None)
        ip = info[0][4][0]

    return ip, domain


def confirm_thc_ssl_dos(tool_names: list[str]) -> list[str]:
    if "THC-SSL-DOS" in tool_names:
        if not THCSSLDOSTool.show_disclaimer():
            console.print("[bold yellow]THC-SSL-DOS omitido por el usuario.[/]")
            tool_names.remove("THC-SSL-DOS")
    return tool_names


def interactive_menu(config: dict) -> ScanConfig:
    os_name = platform.system()

    print_banner()
    if os_name == "Windows":
        print_os_warning()

    tools_status = get_tools_for_os()

    console.print("[bold cyan]Health Check de herramientas:[/]")
    print_health_check(tools_status, os_name)

    raw_target = ask_input("Target (IP / dominio / URL)", default="scanme.nmap.org")

    scan_type = "ip" if is_valid_ip(raw_target) else "domain"

    mode_options = ["Simple - Rapido", "Normal - Balanceado", "Complejo - Exhaustivo", "Personalizado"]
    mode_choice = ask_choice("Modo de escaneo", mode_options, default=2)
    mode_map = {1: Mode.SIMPLE, 2: Mode.NORMAL, 3: Mode.COMPLEX, 4: Mode.CUSTOM}
    mode = mode_map[mode_choice]

    selected_tools = []
    if mode == Mode.CUSTOM:
        console.print("\n[bold]Selecciona herramientas a usar:[/]")
        tool_names = sorted(tools_status.keys())
        for i, name in enumerate(tool_names, 1):
            installed, compatible = tools_status[name]
            if not compatible:
                status = " [red](no compatible)[/]"
            elif not installed:
                status = " [yellow](no instalada)[/]"
            else:
                status = " [green](ok)[/]"
            console.print(f"  [{i}] {name}{status}")
        console.print("  [0] Seleccionar todas las disponibles")
        raw = console.input("[cyan]Numeros separados por coma[/]: ").strip()
        if raw == "0":
            selected_tools = [name for name in tool_names if tools_status[name][0] and tools_status[name][1]]
        else:
            indices = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
            for idx in indices:
                if 1 <= idx <= len(tool_names):
                    name = tool_names[idx - 1]
                    if tools_status[name][0] and tools_status[name][1]:
                        selected_tools.append(name)
    else:
        selected_tools = [
            name for name, (installed, compatible) in tools_status.items()
            if installed and compatible
        ]

    if not selected_tools:
        console.print("[bold red]No hay herramientas seleccionadas/disponibles.[/]")
        sys.exit(1)

    if mode in (Mode.CUSTOM, Mode.COMPLEX):
        wordlist = resolve_wordlist(config, os_name, mode.value)
    else:
        wordlist = ""

    parallel = False
    if len(selected_tools) > 1:
        parallel = ask_yes_no("Modo rapido? (paralelo, 3 hilos maximo)")

    output_formats = []
    if ask_yes_no("Exportar resultados a CSV?"):
        output_formats.append("csv")
    if ask_yes_no("Exportar resultados a JSON?"):
        output_formats.append("json")

    custom_output_dir = ask_input("Directorio de reportes", default=config.get("general", {}).get("output_dir", "./reports"))

    try:
        ip, domain = resolve_target(raw_target, scan_type)
    except Exception as e:
        console.print(f"[bold red]Error al resolver target: {e}[/]")
        sys.exit(1)

    timeout = config.get("general", {}).get("timeout", MODE_TIMEOUTS.get(mode, 600))

    return ScanConfig(
        target_ip=ip,
        target_domain=domain,
        mode=mode,
        wordlist=wordlist,
        timeout=timeout,
        selected_tools=selected_tools,
        output_formats=output_formats,
        parallel=parallel,
        output_dir=custom_output_dir,
    )


def run_scan(config: ScanConfig) -> list:
    findings = []
    tool_classes = get_active_tools(config.selected_tools)
    total = len(tool_classes)

    print_separator()
    print_mode_info(config.mode.value, config.target_domain, config.target_ip, total)

    console_lock = threading.Lock()

    def log(msg):
        with console_lock:
            console.print(msg)

    def parallel_log(msg):
        if msg.startswith("   >"):
            return
        with console_lock:
            console.print(msg)

    progress = create_progress()

    if config.parallel:
        threads = []
        lock = threading.Lock()
        results_per_tool = {}
        tools_in_flight = []
        interrupted = False
        task_start = {}
        monitor_active = True

        def worker(tool, task_id):
            res = tool.run(parallel_log)
            with lock:
                results_per_tool[tool.name] = res
            with console_lock:
                try:
                    progress.update(task_id, visible=False)
                except Exception:
                    pass

        def monitor():
            while monitor_active:
                now = time.time()
                for tid, tstart in list(task_start.items()):
                    elapsed = now - tstart
                    try:
                        progress.update(tid, completed=min(elapsed, config.timeout), total=config.timeout, refresh=True)
                    except Exception:
                        pass
                time.sleep(0.5)

        with progress:
            for i, cls in enumerate(tool_classes, 1):
                t_name = cls.__name__.replace("Tool", "")
                print_step(i, total, f"Lanzando {t_name}...")
                task_id = progress.add_task(f"[cyan]{t_name}", total=config.timeout)
                task_start[task_id] = time.time()
                tool = cls(config)
                tools_in_flight.append(tool)
                t = threading.Thread(target=worker, args=(tool, task_id), daemon=True)
                threads.append(t)
                t.start()

            t_monitor = threading.Thread(target=monitor, daemon=True)
            t_monitor.start()

            POLL_INTERVAL = 0.5
            deadline = time.time() + config.timeout
            for t in threads:
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    try:
                        t.join(timeout=min(POLL_INTERVAL, remaining))
                    except KeyboardInterrupt:
                        interrupted = True
                        break
                    if not t.is_alive():
                        break
                if interrupted or time.time() >= deadline:
                    break

            if interrupted or time.time() >= deadline:
                if interrupted:
                    console.print("\n[bold red]\u2716 Escaneo interrumpido por el usuario.[/]")
                else:
                    console.print(f"\n[bold red]\u23f1 Tiempo de espera agotado ({config.timeout}s). Matando procesos restantes.[/]")
                for tool in tools_in_flight:
                    tool.kill()

        monitor_active = False

        for cls in tool_classes:
            t_name = cls.__name__.replace("Tool", "")
            if t_name in results_per_tool:
                findings.extend(results_per_tool[t_name])
    else:
        with progress:
            for i, cls in enumerate(tool_classes, 1):
                t_name = cls.__name__.replace("Tool", "")
                print_step(i, total, f"Ejecutando {t_name}...")
                task_id = progress.add_task(f"[cyan]{t_name}", total=None)
                tool = cls(config)
                res = tool.run(log)
                findings.extend(res)
                progress.update(task_id, visible=False)

    return findings


def main():
    if platform.system() == "Linux" and os.geteuid() != 0:
        print_root_warning()
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Vulnet Security Scanner CLI",
        usage="vulnet.py [opciones]",
    )
    parser.add_argument("--target", help="IP/dominio/URL objetivo")
    parser.add_argument("--mode", choices=["simple", "normal", "complejo"], help="Modo de escaneo")
    parser.add_argument("--tools", help="Herramientas separadas por coma")
    parser.add_argument("--output", default="./reports", help="Directorio de reportes")
    parser.add_argument("--wordlist", help="Ruta de wordlist")
    parser.add_argument("--fast", action="store_true", help="Modo paralelo")
    parser.add_argument("--no-export", action="store_true", help="No exportar resultados")
    args = parser.parse_args()

    config_data = load_config()

    if args.target:
        config = ScanConfig(
            target_ip="",
            target_domain=args.target,
            mode=Mode(args.mode) if args.mode else Mode.NORMAL,
            wordlist=args.wordlist or "",
            timeout=config_data.get("general", {}).get("timeout", MODE_TIMEOUTS.get(Mode(args.mode) if args.mode else Mode.NORMAL, 300)),
            selected_tools=args.tools.split(",") if args.tools else [],
            output_formats=[] if args.no_export else ["csv", "json"],
            parallel=args.fast,
            output_dir=args.output,
        )
        try:
            cli_scan_type = "ip" if is_valid_ip(args.target) else "domain"
            ip, domain = resolve_target(config.target_domain, cli_scan_type)
            config.target_ip = ip
            config.target_domain = domain
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/]")
            sys.exit(1)

        if not config.selected_tools:
            tools_status = get_tools_for_os()
            config.selected_tools = [
                name for name, (installed, compatible) in tools_status.items()
                if installed and compatible
            ]
    else:
        config = interactive_menu(config_data)

    config.selected_tools = confirm_thc_ssl_dos(config.selected_tools)

    if not config.selected_tools:
        console.print("[bold red]No hay herramientas para ejecutar.[/]")
        sys.exit(1)

    if config.output_dir:
        os.makedirs(config.output_dir, exist_ok=True)

    findings = []

    try:
        findings = run_scan(config)
    except Exception as e:
        console.print(f"\n[bold red]Error durante el escaneo: {e}[/]")

    console.print("\n" + "=" * 60)
    console.print("[bold]RESUMEN FINAL[/]".center(60))
    console.print("=" * 60)

    print_findings_table(findings)
    print_stats(findings)

    if config.output_formats and findings:
        tools_used = list({f.tool for f in findings})
        try:
            created = export_all(
                findings=findings,
                target=config.target_domain,
                config=config,
                tools_used=tools_used,
                formats=config.output_formats,
                base_dir=config.output_dir,
            )
            for fmt, path in created.items():
                if fmt == "raw_tools":
                    count = len(config.raw_outputs)
                    console.print(f"  [green]RAW LOGS[/] -> {path}  ({count} archivos)")
                else:
                    console.print(f"  [green]{fmt.upper()}[/] -> {path}")
        except Exception as e:
            console.print(f"[bold red]Error al exportar: {e}[/]")

    console.print("\n[bold green]Escaneo completado.[/]")
    console.print(f"[grey62]{datetime.now():%Y-%m-%d %H:%M:%S}[/]")


if __name__ == "__main__":
    main()
