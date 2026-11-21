"""Plain-text tables and JSON documents."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from ._version import __version__
from .check import Report, ResolverResult
from .emailauth import EMAIL_CHECKS, EmailReport
from .resolvers import Resolver

_COLORS = {"green": "32", "red": "31", "yellow": "33", "dim": "2", "bold": "1"}


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, color: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\033[{_COLORS[color]}m{text}\033[0m"


def clean(text: str) -> str:
    """Escape control characters so records cannot inject terminal escape sequences."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)


def _truncate(text: str, width: int) -> str:
    text = clean(text)
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(1, width - 3)] + "..."


def _status_text(row: ResolverResult) -> tuple[str, str]:
    status = row.result.status
    if row.matches is True:
        return "match", "green"
    if row.matches is False and status == "ok":
        return "MISMATCH", "red"
    if status == "ok":
        return "ok", "green"
    if status in ("nxdomain", "noanswer"):
        return status.upper() if row.matches is False else status, "yellow"
    return status.upper(), "red"


def _table(headers: Sequence[str], rows: list[list[tuple[str, str]]], style: Style) -> list[str]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, (text, _) in enumerate(row):
            widths[i] = max(widths[i], len(text))
    lines = ["  ".join(style(h.ljust(widths[i]), "bold") for i, h in enumerate(headers)).rstrip()]
    for row in rows:
        cells = []
        for i, (text, color) in enumerate(row):
            padded = text.ljust(widths[i]) if i < len(row) - 1 else text
            cells.append(style(padded, color) if color else padded)
        lines.append("  ".join(cells).rstrip())
    return lines


def render_report(report: Report, style: Style, wide: bool = False) -> str:
    width = 0 if wide else 60
    title = f"{report.name} {report.rdtype}"
    lines = [style(title, "bold")]
    if report.expectation is not None:
        source = "" if report.expectation.source == "cli" else f" (from {report.expectation.source} servers)"
        lines.append(f"expected{source}: {report.expectation.describe()}")
    lines.append("")
    headers = ("RESOLVER", "REGION", "ADDRESS", "STATUS", "TTL", "TIME", "ANSWER")
    rows: list[list[tuple[str, str]]] = []
    for row in report.results:
        status, color = _status_text(row)
        answers = list(row.result.answers) or [row.result.error or ""]
        region = row.target.resolver.country or row.target.resolver.region
        if row.target.resolver.region == "global" and row.target.resolver.country:
            region = "global"
        base = [
            (_truncate(row.target.label, 28), ""),
            (region, "dim"),
            (_truncate(row.target.endpoint, 38 if not wide else 0), "dim"),
            (status, color),
            ("" if row.result.ttl is None else str(row.result.ttl), ""),
            (f"{row.result.elapsed_ms:.0f} ms" if row.result.elapsed_ms else "", "dim"),
            (_truncate(answers[0], width), "" if row.result.answers else "dim"),
        ]
        rows.append(base)
        for extra in answers[1:]:
            rows.append([("", "")] * 6 + [(_truncate(extra, width), "")])
    lines.extend(_table(headers, rows, style))
    lines.append("")
    lines.extend(render_summary(report, style))
    for note in report.notes:
        lines.append(style(f"note: {note}", "yellow"))
    return "\n".join(lines)


def render_summary(report: Report, style: Style) -> list[str]:
    lines: list[str] = []
    if report.expectation is not None:
        pct = report.propagation_pct or 0.0
        color = "green" if report.propagated else "red"
        lines.append(
            style(f"Propagation: {pct:g}%", color)
            + f" ({report.matching}/{report.total} resolvers match, threshold {report.threshold:g}%)"
        )
    majority = report.majority
    if majority is None:
        lines.append(style("No resolver answered.", "red"))
    else:
        status, answers = majority
        agreed = ", ".join(answers) if answers else status.upper()
        color = "green" if report.consistency_pct >= 100 else "yellow"
        lines.append(
            style(f"Consistency: {report.consistency_pct:g}%", color)
            + f" of {report.responded} responding resolvers agree on: {_truncate(agreed, 100)}"
        )
    failed = report.total - report.responded
    if failed:
        lines.append(style(f"{failed} resolver(s) timed out or failed.", "yellow"))
    return lines


def render_round(round_no: int, reports: Iterable[Report], style: Style) -> str:
    parts = []
    for report in reports:
        if report.expectation is not None:
            value = f"{report.propagation_pct or 0:g}% ({report.matching}/{report.total})"
        else:
            value = f"{report.consistency_pct:g}% consistent"
        mark = style("done", "green") if report.propagated else style("waiting", "yellow")
        parts.append(f"{report.rdtype} {value} {mark}")
    return f"round {round_no}: " + "; ".join(parts)


def render_resolvers(resolvers: Sequence[Resolver], style: Style) -> str:
    headers = ("ID", "NAME", "REGION", "COUNTRY", "UDP", "DOH", "TAGS")
    rows = [
        [
            (r.id, "bold"),
            (r.name, ""),
            (r.region, ""),
            (r.country or "-", ""),
            (r.address or "-", ""),
            (r.doh or "-", "dim"),
            (",".join(r.tags) or "-", "dim"),
        ]
        for r in resolvers
    ]
    return "\n".join(_table(headers, rows, style))


_LEVEL_COLORS = {"ok": "green", "info": "dim", "warning": "yellow", "error": "red"}


def render_email(report: EmailReport, style: Style) -> str:
    lines = [style(f"Email authentication for {report.domain}", "bold"), ""]
    for check in EMAIL_CHECKS:
        findings = [f for f in report.findings if f.check == check]
        if not findings:
            continue
        lines.append(style(check.upper(), "bold"))
        records = report.records.get(check)
        if isinstance(records, list):
            for record in records:
                lines.append(style(f"  {clean(str(record))}", "dim"))
        elif isinstance(records, dict):
            for selector, info in records.items():
                lines.append(style(f"  {selector}: {_truncate(str(info['record']), 90)}", "dim"))
        if check == "spf" and "spf_lookups" in report.records:
            lines.append(style(f"  DNS lookups: {report.records['spf_lookups']}/10", "dim"))
        for finding in findings:
            label = finding.level.upper().ljust(7)
            lines.append(f"  {style(label, _LEVEL_COLORS[finding.level])} {clean(finding.message)}")
        lines.append("")
    verdict = "passed" if report.errors == 0 else "failed"
    color = "green" if report.errors == 0 else "red"
    lines.append(style(f"Result: {verdict}", color) + f" ({report.errors} error(s), {report.warnings} warning(s))")
    return "\n".join(lines)


def to_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


def reports_document(reports: Sequence[Report], **extra: Any) -> dict[str, Any]:
    return {
        "tool": "dns-propagation",
        "version": __version__,
        "propagated": bool(reports) and all(r.propagated for r in reports),
        **extra,
        "checks": [r.to_dict() for r in reports],
    }
