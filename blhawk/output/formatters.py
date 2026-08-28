"""Render findings as terminal text, JSON, JSONL, CSV or Markdown."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

try:  # colorama is an optional, purely cosmetic dependency
    from colorama import Fore, Style
except ModuleNotFoundError:  # pragma: no cover - exercised only without colorama

    class _NoColor:
        """Fallback that renders every color/style attribute as an empty string."""

        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = Style = _NoColor()

from ..core.models import Finding, Verdict

FORMATS = ("terminal", "json", "jsonl", "csv", "markdown")

_VERDICT_COLOR = {
    Verdict.CONFIRMED_BY_SAFE_VERIFICATION: Fore.RED,
    Verdict.LIKELY_TAKEOVER: Fore.RED,
    Verdict.RECLAIMABILITY_UNCONFIRMED: Fore.YELLOW,
    Verdict.POTENTIALLY_RECLAIMABLE: Fore.YELLOW,
    Verdict.DEAD_RESOURCE: Fore.CYAN,
    Verdict.NOT_VULNERABLE: Fore.GREEN,
    Verdict.UNKNOWN: Fore.WHITE,
}


def _color(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def format_terminal(findings: list[Finding], use_color: bool = True, verbose: bool = False) -> str:
    lines: list[str] = []
    for f in findings:
        color = _VERDICT_COLOR.get(f.verdict, Fore.WHITE)
        header = _color(
            f"[{f.severity.value.upper()}] {f.provider or 'unknown'} :: {f.verdict.value}",
            color,
            use_color,
        )
        lines.append(header)
        lines.append(f"  Target:     {f.target.url}")
        lines.append(f"  Confidence: {int(round(f.confidence * 100))}%")
        lines.append(
            f"  Scope:      {f.scope.status.value}"
            + (f" ({f.scope.program})" if f.scope.program else "")
        )
        if f.evidence.http_status is not None:
            lines.append(f"  HTTP:       {f.evidence.http_status}")
        if f.evidence.reclaimability is not None:
            lines.append(f"  Reclaim:    {f.evidence.reclaimability.value}")
        if f.evidence.signals:
            lines.append(f"  Evidence:   {', '.join(f.evidence.signals)}")
        if verbose and f.evidence.notes:
            for note in f.evidence.notes:
                lines.append(f"  Note:       {note}")
        if f.errors:
            lines.append(f"  Errors:     {'; '.join(f.errors)}")
        lines.append("")
    if not findings:
        lines.append("No findings.")
    return "\n".join(lines).rstrip() + "\n"


def format_silent(findings: list[Finding]) -> str:
    """Machine-friendly: one ``VERDICT<TAB>target`` line per finding."""
    return "".join(f"{f.verdict.value}\t{f.target.url}\n" for f in findings)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2) + "\n"


def format_jsonl(findings: list[Finding]) -> str:
    return "".join(json.dumps(f.to_dict()) + "\n" for f in findings)


_CSV_FIELDS = [
    "target",
    "provider",
    "status",
    "severity",
    "confidence",
    "scope_status",
    "program",
    "http_status",
    "reclaimability",
    "signals",
    "timestamp",
]


def format_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for f in findings:
        writer.writerow(
            {
                "target": f.target.url,
                "provider": f.provider or "",
                "status": f.verdict.value,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 4),
                "scope_status": f.scope.status.value,
                "program": f.scope.program or "",
                "http_status": f.evidence.http_status if f.evidence.http_status is not None else "",
                "reclaimability": f.evidence.reclaimability.value,
                "signals": "; ".join(f.evidence.signals),
                "timestamp": f.timestamp,
            }
        )
    return buf.getvalue()


def format_markdown(findings: list[Finding]) -> str:
    lines = ["# BLHawk findings", "", f"Total: {len(findings)}", ""]
    lines.append("| Severity | Provider | Status | Confidence | Scope | Target |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for f in findings:
        lines.append(
            f"| {f.severity.value} | {f.provider or ''} | {f.verdict.value} | "
            f"{int(round(f.confidence * 100))}% | {f.scope.status.value} | {f.target.url} |"
        )
    return "\n".join(lines) + "\n"


def format_findings(
    findings: list[Finding],
    fmt: str = "terminal",
    use_color: bool = True,
    verbose: bool = False,
    silent: bool = False,
) -> str:
    if silent:
        return format_silent(findings)
    fmt = fmt.lower()
    if fmt == "terminal":
        return format_terminal(findings, use_color=use_color, verbose=verbose)
    if fmt == "json":
        return format_json(findings)
    if fmt == "jsonl":
        return format_jsonl(findings)
    if fmt == "csv":
        return format_csv(findings)
    if fmt == "markdown":
        return format_markdown(findings)
    raise ValueError(f"unknown output format: {fmt}")


def write_findings(findings: list[Finding], path: str | Path, fmt: str) -> None:
    text = format_findings(findings, fmt=fmt, use_color=False)
    Path(path).write_text(text, encoding="utf-8")
