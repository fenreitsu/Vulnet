import csv
import json
import platform
from datetime import datetime
from pathlib import Path

from core.models import Finding, ScanConfig, Severity


def _safe_filename(target: str) -> str:
    return target.replace("://", "_").replace("/", "_").replace(":", "_")


def _generate_report_path(target: str, base_dir: str = "./reports") -> tuple[Path, str]:
    safe_target = _safe_filename(target)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_dir = Path(base_dir) / f"{safe_target}_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir, datetime.now().strftime("%Y%m%d_%H%M%S")


def export_csv(
    findings: list[Finding],
    output_dir: Path,
    target: str,
    timestamp: str,
) -> Path:
    filepath = output_dir / f"{_safe_filename(target)}_{timestamp}.csv"
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "severity", "tool", "title", "description", "remediation"])
        for finding in findings:
            writer.writerow(
                [
                    timestamp,
                    finding.severity.value,
                    finding.tool,
                    finding.title,
                    finding.description.replace("\n", " | "),
                    finding.remediation,
                ]
            )
    return filepath


def export_json(
    findings: list[Finding],
    output_dir: Path,
    target: str,
    timestamp: str,
    config: ScanConfig,
    tools_used: list[str],
) -> Path:
    stats = {sev.value: 0 for sev in Severity}
    for f in findings:
        stats[f.severity.value] = stats.get(f.severity.value, 0) + 1

    filepath = output_dir / f"{_safe_filename(target)}_{timestamp}.json"
    data = {
        "metadata": {
            "tool": "Vulnet Security Scanner",
            "version": "1.0",
            "target": target,
            "target_ip": config.target_ip,
            "date": datetime.now().isoformat(),
            "mode": config.mode.value,
            "os": platform.system(),
            "tools_requested": config.selected_tools,
            "tools_executed": tools_used,
            "parallel": config.parallel,
        },
        "stats": stats,
        "findings": [
            {
                "severity": f.severity.value,
                "tool": f.tool,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filepath


def export_raw_outputs(raw_outputs: dict[str, str], report_dir: Path) -> Path:
    raw_dir = report_dir / "raw_tools"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name, output in raw_outputs.items():
        path = raw_dir / f"{name}.txt"
        path.write_text(output, encoding="utf-8")
    return raw_dir


def export_all(
    findings: list[Finding],
    target: str,
    config: ScanConfig,
    tools_used: list[str],
    formats: list[str],
    base_dir: str = "./reports",
) -> dict[str, Path]:
    report_dir, timestamp = _generate_report_path(target, base_dir)
    logs_dir = report_dir / "vulnet_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    created = {}

    if "csv" in formats:
        path = export_csv(findings, logs_dir, target, timestamp)
        created["csv"] = path

    if "json" in formats:
        path = export_json(findings, logs_dir, target, timestamp, config, tools_used)
        created["json"] = path

    if config.raw_outputs:
        raw_dir = export_raw_outputs(config.raw_outputs, report_dir)
        created["raw_tools"] = raw_dir

    return created
