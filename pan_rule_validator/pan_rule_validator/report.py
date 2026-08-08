"""
report.py
=========

Renders findings (see analysis.Finding) as console text, Markdown, or JSON.
This phase intentionally has no AI-generated narrative -- see the
architecture doc's Phase 2 for where that layer plugs in, taking this
module's JSON output as its input.
"""

from __future__ import annotations

import json
from typing import List

from .analysis import Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def to_markdown(findings: List[Finding], title: str = "Panorama rule validation findings") -> str:
    lines = [f"# {title}", ""]
    by_severity = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.device_group, f.rule_name))

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- High severity: {counts.get('high', 0)}")
    lines.append(f"- Medium severity: {counts.get('medium', 0)}")
    lines.append(f"- Low severity: {counts.get('low', 0)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not by_severity:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("| Severity | Type | Device group | Rule | Detail |")
    lines.append("|---|---|---|---|---|")
    for f in by_severity:
        detail = f.detail.replace("|", "\\|")
        lines.append(f"| {f.severity} | {f.finding_type} | {f.device_group} | {f.rule_name} | {detail} |")

    return "\n".join(lines)


def to_console(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."
    by_severity = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.device_group, f.rule_name))
    lines = []
    for f in by_severity:
        lines.append(f"[{f.severity.upper():6}] ({f.finding_type}) {f.device_group}/{f.rule_name}: {f.detail}")
    return "\n".join(lines)
