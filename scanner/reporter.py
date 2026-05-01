"""
Handles all output — terminal report and JSON file.

Colours: red for FAIL, yellow for WARN, green for PASS.
The JSON report is a flat list of findings, same structure as the terminal output,
so it's easy to pipe into jq or import into other tools.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from scanner.checks import Finding

# ANSI colour codes — check if the terminal actually supports colour
_COLOURS = sys.stdout.isatty()

RED = "\033[0;31m" if _COLOURS else ""
YELLOW = "\033[1;33m" if _COLOURS else ""
GREEN = "\033[0;32m" if _COLOURS else ""
CYAN = "\033[0;36m" if _COLOURS else ""
BOLD = "\033[1m" if _COLOURS else ""
RESET = "\033[0m" if _COLOURS else ""

STATUS_COLOUR = {
    "FAIL": RED,
    "WARN": YELLOW,
    "PASS": GREEN,
}

STATUS_ICON = {
    "FAIL": "✗",
    "WARN": "⚠",
    "PASS": "✓",
}


def print_report(
    findings: List[Finding],
    profile: str,
    region: str,
    output_path: Optional[str] = None,
) -> None:
    """Print the terminal report and optionally save a JSON file."""
    _print_header(profile, region)
    _print_findings(findings)
    _print_summary(findings)

    saved_path = _save_json(findings, output_path)
    print(f"\n{BOLD}Report saved{RESET} → {saved_path}")


def _print_header(profile: str, region: str) -> None:
    width = 50
    title = "AWS Misconfiguration Scanner"
    padding = (width - len(title) - 2) // 2

    print()
    print(f"{CYAN}{BOLD}╔{'═' * width}╗{RESET}")
    print(f"{CYAN}{BOLD}║{' ' * padding}{title}{' ' * (width - padding - len(title))}║{RESET}")
    print(f"{CYAN}{BOLD}╚{'═' * width}╝{RESET}")
    print()
    print(f"  {BOLD}Profile{RESET} : {profile}")
    print(f"  {BOLD}Region{RESET}  : {region}")
    print()


def _print_findings(findings: List[Finding]) -> None:
    # Group by service for a cleaner layout
    services: dict = {}
    for f in findings:
        services.setdefault(f.service, []).append(f)

    for service, service_findings in services.items():
        print(f"{BOLD}[{service}]{RESET}")
        for f in service_findings:
            colour = STATUS_COLOUR.get(f.status, "")
            icon = STATUS_ICON.get(f.status, "?")
            resource = f.resource.ljust(35)
            print(f"  {colour}{icon} {f.status:<4}{RESET}  {resource} — {f.message}")
        print()


def _print_summary(findings: List[Finding]) -> None:
    fail = sum(1 for f in findings if f.status == "FAIL")
    warn = sum(1 for f in findings if f.status == "WARN")
    passed = sum(1 for f in findings if f.status == "PASS")

    print(
        f"{BOLD}Summary:{RESET}  "
        f"{RED}{fail} FAIL{RESET}  "
        f"{YELLOW}{warn} WARN{RESET}  "
        f"{GREEN}{passed} PASS{RESET}"
    )


def _save_json(findings: List[Finding], output_path: Optional[str]) -> Path:
    """Save findings to a JSON file. Auto-generates the filename if not specified."""
    if output_path:
        path = Path(output_path)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"misconfig_report_{timestamp}.json")

    data = {
        "generated_at": datetime.now().isoformat(),
        "total": len(findings),
        "summary": {
            "fail": sum(1 for f in findings if f.status == "FAIL"),
            "warn": sum(1 for f in findings if f.status == "WARN"),
            "pass": sum(1 for f in findings if f.status == "PASS"),
        },
        "findings": [f.to_dict() for f in findings],
    }

    with path.open("w") as fp:
        json.dump(data, fp, indent=2)

    return path
