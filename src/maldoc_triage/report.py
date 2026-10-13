"""Rendering of Report objects to text and JSON."""

from __future__ import annotations

import json
import os
import sys
from typing import List

from .models import Report, Severity

# ANSI colors keyed by risk band / severity label.
_COLORS = {
    "clean": "\033[32m",
    "low": "\033[36m",
    "medium": "\033[33m",
    "high": "\033[31m",
    "critical": "\033[1;31m",
    "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_RESET}"


def render_json(reports: List[Report]) -> str:
    return json.dumps([r.to_dict() for r in reports], indent=2)


def render_text(reports: List[Report], stream=None, verbose: bool = False) -> str:
    stream = stream or sys.stdout
    color = _use_color(stream)
    lines: List[str] = []

    for report in reports:
        band = report.risk
        header = f"{report.path}"
        risk_tag = f"[{band.upper()}]"
        lines.append(
            f"{_c(risk_tag, band, color)} {_BOLD if color else ''}{header}{_RESET if color else ''}"
        )
        lines.append(
            f"    type={report.file_type}  size={report.size}  "
            f"score={report.score}  sha256={report.sha256[:16]}..."
        )

        if report.errors:
            for err in report.errors:
                lines.append(f"    {_c('! ' + err, 'high', color)}")

        # Findings sorted by severity (desc), then id.
        findings = sorted(
            report.findings,
            key=lambda f: (-int(f.severity), f.id),
        )
        shown = findings if verbose else [f for f in findings if f.severity >= Severity.LOW]
        if not shown and findings:
            # Only info-level findings: show them so output is never empty.
            shown = findings

        for f in shown:
            sev = f.severity.label
            lines.append(f"    {_c('• ' + sev.upper().ljust(8), sev, color)} {f.title}  ({f.id})")
            if f.location:
                lines.append(f"        location: {f.location}")
            if verbose and f.detail:
                lines.append(f"        {f.detail}")
            if verbose and f.evidence:
                lines.append(f"        evidence: {json.dumps(f.evidence)}")

        if report.iocs:
            lines.append(f"    {_BOLD if color else ''}IOCs:{_RESET if color else ''}")
            for kind, values in report.iocs.items():
                preview = values[:10]
                extra = f" (+{len(values) - 10} more)" if len(values) > 10 else ""
                lines.append(f"        {kind}: {', '.join(preview)}{extra}")

        lines.append("")

    # Summary line.
    if len(reports) > 1:
        counts = {}
        for r in reports:
            counts[r.risk] = counts.get(r.risk, 0) + 1
        summary = "  ".join(
            f"{_c(band, band, color)}={counts[band]}"
            for band in ("critical", "high", "medium", "low", "clean")
            if band in counts
        )
        lines.append(f"{_BOLD if color else ''}Summary ({len(reports)} files):{_RESET if color else ''} {summary}")

    return "\n".join(lines)
