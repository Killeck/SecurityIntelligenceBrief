# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.
# Last modified: v6.1.6

"""Presentation layer for the Weekly Vulnerability Report.

The underlying vulnerability lifecycle and scoring model remains in
``vulnerability_reporting.py``. This module keeps raw internal priority scores
out of the user-facing report, aligns Outlook table columns explicitly, adds the
ISO week number, and ensures every displayed full CVE identifier links directly
to its NVD record.
"""

from __future__ import annotations

import html
import re
from datetime import date
from typing import Any, Iterable

from .branding import LOGO_CONTENT_ID
from .models import Item
from .utils import truncate
from .vulnerability_reporting import VulnerabilityRecord


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", flags=re.IGNORECASE)


def cve_url(cve: str) -> str:
    """Return the canonical NVD deep-dive URL for one CVE."""
    return f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"


def iso_week_label(value: date) -> str:
    """Return an unambiguous ISO week/year label."""
    iso = value.isocalendar()
    return f"Week {iso.week} / {iso.year}"


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _cve_html(cve: str, colour: str) -> str:
    normalised = cve.upper()
    return (
        f'<a href="{html.escape(cve_url(normalised), quote=True)}" '
        f'style="color:{colour};text-decoration:underline;white-space:nowrap;">'
        f"{_esc(normalised)}</a>"
    )


def _cve_plain(cve: str) -> str:
    normalised = cve.upper()
    return f"{normalised} <{cve_url(normalised)}>"


def _type_and_scope(record: VulnerabilityRecord) -> str:
    """Explain what the vulnerability is and identify its affected scope."""

    title = record.title.strip().rstrip(".")
    summary = record.summary.strip().rstrip(".")
    scope = (record.affected or record.product or record.category).strip().rstrip(".")
    details = [f"{title}." if title else "Vulnerability details unavailable."]
    if summary and summary.casefold() != title.casefold():
        details.append(f"{summary}.")
    details.append(f"Affected scope: {scope or 'Not stated' }.")
    details.append(
        f"Evidence: {record.confidence} "
        f"({record.corroboration_count} source(s))."
    )
    return " ".join(details)


def _linkify_cves_html(text: str, colour: str) -> str:
    parts: list[str] = []
    position = 0
    for match in CVE_PATTERN.finditer(text):
        parts.append(_esc(text[position:match.start()]))
        parts.append(_cve_html(match.group(0), colour))
        position = match.end()
    parts.append(_esc(text[position:]))
    return "".join(parts)


def _linkify_cves_plain(text: str) -> str:
    return CVE_PATTERN.sub(lambda match: _cve_plain(match.group(0)), text)


def _counts(records: Iterable[VulnerabilityRecord]) -> dict[str, int | float]:
    values = list(records)
    return {
        "total": len(values),
        "critical": sum(1 for record in values if (record.cvss or 0) >= 9.0),
        "high": sum(1 for record in values if 7.0 <= (record.cvss or 0) < 9.0),
        "kev": sum(1 for record in values if record.kev),
        "exploited": sum(1 for record in values if record.exploited),
        "zero_day": sum(1 for record in values if record.zero_day),
        "highest_epss": max((record.epss for record in values), default=0.0),
        "vendors": len({record.vendor for record in values}),
    }


def _vendor_summary(
    records: Iterable[VulnerabilityRecord],
) -> list[tuple[str, int, int, int, int]]:
    grouped: dict[str, list[VulnerabilityRecord]] = {}
    for record in records:
        grouped.setdefault(record.vendor or "Unknown", []).append(record)
    return sorted(
        (
            (
                vendor,
                len(values),
                sum((value.cvss or 0) >= 9 for value in values),
                sum(value.exploited for value in values),
                sum(value.kev for value in values),
            )
            for vendor, values in grouped.items()
        ),
        key=lambda row: (row[1], row[2], row[3], row[0].casefold()),
        reverse=True,
    )



def _prominent_vulnerabilities(
    records: Iterable[VulnerabilityRecord],
    *,
    limit: int,
) -> list[VulnerabilityRecord]:
    """Return the most decision-relevant vulnerabilities for a period.

    Prominence is evidence-first rather than simply newest-first: zero-days,
    confirmed exploitation/CISA KEV, remediation priority, CVSS and EPSS lead.
    This keeps the Weekly and month-rearview sections focused on vulnerabilities
    that materially changed exposure or remediation urgency.
    """

    unique: dict[str, VulnerabilityRecord] = {}
    for record in records:
        key = record.cve.upper().strip()
        existing = unique.get(key)
        if existing is None or (
            record.priority_score, record.cvss or 0.0, record.epss
        ) > (
            existing.priority_score, existing.cvss or 0.0, existing.epss
        ):
            unique[key] = record

    values = list(unique.values())
    values.sort(
        key=lambda record: (
            record.zero_day,
            record.exploited or record.kev,
            record.kev,
            record.exploited,
            record.priority_score,
            record.cvss or 0.0,
            record.epss,
            record.published,
        ),
        reverse=True,
    )
    return values[: max(0, limit)]


def _prominent_plain(record: VulnerabilityRecord, rank: int) -> str:
    flags: list[str] = []
    if record.zero_day:
        flags.append("Zero-day")
    if record.exploited:
        flags.append("Exploited")
    if record.kev:
        flags.append("CISA KEV")
    if record.ransomware:
        flags.append("Ransomware-linked")
    status = ", ".join(flags) or "No confirmed exploitation"
    cvss = f"{record.cvss:.1f}" if record.cvss is not None else "N/A"
    summary = record.summary.strip() or record.title.strip()
    return (
        f"{rank}. {_cve_plain(record.cve)} | {record.vendor} | CVSS {cvss} | "
        f"{status} | {summary} | Action: {record.action}"
    )


def _prominent_table(
    records: list[VulnerabilityRecord],
    *,
    colours: dict[str, str],
    marker: str,
) -> str:
    """Render a compact Outlook-safe prominent-vulnerability table."""

    if not records:
        return (
            f'<p style="margin:0;color:{colours["muted"]};">'
            "No qualifying vulnerability records for this period.</p>"
        )

    rows: list[str] = []
    for rank, record in enumerate(records, start=1):
        flags: list[str] = []
        if record.zero_day:
            flags.append("Zero-day")
        if record.exploited:
            flags.append("Exploited")
        if record.kev:
            flags.append("KEV")
        if record.ransomware:
            flags.append("Ransomware")
        status = " · ".join(flags) or "Watch"
        cvss = f"{record.cvss:.1f}" if record.cvss is not None else "N/A"
        reason = record.summary.strip() or record.title.strip()
        rows.append(
            f'<tr data-{marker}-entry="1">'
            f'<td width="5%" align="center" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};">{rank}</td>'
            f'<td width="15%" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};">{_cve_html(record.cve, colours["link"])}</td>'
            f'<td width="13%" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};color:{colours["text"]};">{_esc(record.vendor)}</td>'
            f'<td width="8%" align="center" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};font-weight:700;">{_esc(cvss)}</td>'
            f'<td width="15%" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};color:{colours["high"]};">{_esc(status)}</td>'
            f'<td width="30%" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};color:{colours["text"]};line-height:1.35;">{_esc(reason)}</td>'
            f'<td width="14%" valign="top" style="padding:7px;border-top:1px solid {colours["border"]};color:{colours["muted"]};line-height:1.35;">{_esc(record.action)}</td>'
            "</tr>"
        )

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="width:100%;table-layout:fixed;border-collapse:collapse;font-size:10px;">'
        f'<tr style="color:{colours["muted"]};">'
        '<th width="5%" style="padding:6px;">#</th>'
        '<th width="15%" align="left" style="padding:6px;">CVE</th>'
        '<th width="13%" align="left" style="padding:6px;">Vendor</th>'
        '<th width="8%" style="padding:6px;">CVSS</th>'
        '<th width="15%" align="left" style="padding:6px;">Status</th>'
        '<th width="30%" align="left" style="padding:6px;">Why it matters</th>'
        '<th width="14%" align="left" style="padding:6px;">Action</th>'
        '</tr>' + "".join(rows) + "</table>"
    )


_VULN_CLASSES = (
    ("Authentication bypass", ("authentication bypass", "auth bypass", "missing authentication", "improper authentication")),
    ("Remote code execution", ("remote code execution", "arbitrary code execution", "code execution", " rce ")),
    ("Command injection", ("command injection", "os command", "shell command")),
    ("Privilege escalation", ("privilege escalation", "elevation of privilege")),
    ("Information disclosure", ("information disclosure", "sensitive information", "data exposure", "information leak")),
    ("Memory corruption", ("use-after-free", "buffer overflow", "out-of-bounds", "memory corruption")),
    ("SQL injection", ("sql injection", "sqli")),
    ("Cross-site scripting", ("cross-site scripting", "cross site scripting", " xss ")),
    ("Path traversal", ("path traversal", "directory traversal")),
    ("Server-side request forgery", ("server-side request forgery", "server side request forgery", " ssrf ")),
    ("Deserialization", ("deserialization", "deserialisation")),
    ("Denial of service", ("denial of service", "denial-of-service")),
)


def vulnerability_class(record: VulnerabilityRecord) -> str:
    source = f" {record.title} {record.summary} {record.product} {record.affected} {record.category} ".casefold()
    for label, terms in _VULN_CLASSES:
        if any(term in source for term in terms):
            return label
    return record.category or "Other vulnerability"


def _group_changes(changes: list[str], records: Iterable[VulnerabilityRecord]) -> list[tuple[str, list[tuple[str, list[str]]]]]:
    lookup = {record.cve.upper(): record for record in records}
    grouped: dict[str, dict[str, list[str]]] = {}
    for change in changes[:30]:
        match = CVE_PATTERN.search(change)
        record = lookup.get(match.group(0).upper()) if match else None
        vendor = record.vendor if record else "Unknown vendor"
        kind = vulnerability_class(record) if record else "Lifecycle / exploitation state"
        grouped.setdefault(vendor, {}).setdefault(kind, []).append(change)
    return [
        (vendor, [(kind, values) for kind, values in sorted(classes.items())])
        for vendor, classes in sorted(grouped.items())
    ]


def _changes_plain(changes: list[str], records: Iterable[VulnerabilityRecord]) -> list[str]:
    if not changes:
        return ["No lifecycle state changes identified."]
    lines: list[str] = []
    for vendor, classes in _group_changes(changes, records):
        lines.append(vendor)
        for kind, values in classes:
            lines.append(f"  {kind}")
            lines.extend(f"    - {_linkify_cves_plain(value)}" for value in values)
    return lines


def _changes_html(changes: list[str], records: Iterable[VulnerabilityRecord], colours: dict[str, str]) -> str:
    if not changes:
        return f'<p style="margin:0;color:{colours["muted"]};">No lifecycle state changes identified.</p>'
    blocks: list[str] = []
    for vendor, classes in _group_changes(changes, records):
        inner: list[str] = []
        for kind, values in classes:
            rows = "".join(
                f'<tr><td width="18" valign="top" style="padding:3px 5px 3px 0;color:{colours["purple"]};">◆</td>'
                f'<td style="padding:3px;color:{colours["text"]};font-size:10px;">{_linkify_cves_html(value, colours["link"])}</td></tr>'
                for value in values
            )
            inner.append(
                f'<div style="margin-top:4px;color:{colours["high"]};font-size:10px;font-weight:700;">{_esc(kind)}</div>'
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>'
            )
        blocks.append(
            f'<div style="margin:0 0 8px;padding:8px;background:{colours["panel_alt"]};border:1px solid {colours["border"]};border-radius:5px;">'
            f'<strong style="color:{colours["text"]};font-size:11px;">{_esc(vendor)}</strong>'
            + "".join(inner) + "</div>"
        )
    return "".join(blocks)


_REMEDIATION_BANDS = ("Patch immediately", "Patch within 7 days", "Validate exposure", "Monitor")


def _remediation_plain(records: Iterable[VulnerabilityRecord]) -> list[str]:
    values = list(records)
    lines: list[str] = []
    for band in _REMEDIATION_BANDS:
        lines.append(band)
        selected = [record for record in values if record.remediation_band == band]
        vendors: dict[str, list[VulnerabilityRecord]] = {}
        for record in selected:
            vendors.setdefault(record.vendor or "Unknown", []).append(record)
        if not vendors:
            lines.append("  None")
            continue
        for vendor in sorted(vendors):
            lines.append(f"  {vendor}")
            for record in sorted(vendors[vendor], key=lambda r: (r.cvss or 0, r.epss), reverse=True):
                lines.append(f"    - {_cve_plain(record.cve)} · {vulnerability_class(record)} · Advisory: {record.link}")
    return lines


def _remediation_html(records: Iterable[VulnerabilityRecord], colours: dict[str, str]) -> str:
    values = list(records)
    blocks: list[str] = []
    for band in _REMEDIATION_BANDS:
        selected = [record for record in values if record.remediation_band == band]
        vendors: dict[str, list[VulnerabilityRecord]] = {}
        for record in selected:
            vendors.setdefault(record.vendor or "Unknown", []).append(record)
        vendor_html: list[str] = []
        for vendor in sorted(vendors):
            rows = "".join(
                f'<tr><td width="18" valign="top" style="padding:3px 5px 3px 0;color:{colours["high"]};">•</td>'
                f'<td style="padding:3px;color:{colours["text"]};font-size:10px;">'
                f'{_cve_html(record.cve, colours["link"])} · {_esc(vulnerability_class(record))}'
                + (f' · <a href="{html.escape(record.link, quote=True)}" style="color:{colours["link"]};">Advisory ›</a>' if record.link else "")
                + '</td></tr>'
                for record in sorted(vendors[vendor], key=lambda r: (r.cvss or 0, r.epss), reverse=True)
            )
            vendor_html.append(
                f'<div style="margin-top:5px;color:{colours["text"]};font-size:10px;font-weight:700;">{_esc(vendor)}</div>'
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>'
            )
        body = "".join(vendor_html) or f'<span style="color:{colours["muted"]};font-size:10px;">None</span>'
        blocks.append(
            f'<div style="margin:0 0 7px;padding:8px;background:{colours["panel_alt"]};border:1px solid {colours["border"]};border-radius:5px;">'
            f'<strong style="color:{colours["high"]};font-size:11px;">{_esc(band)}</strong>{body}</div>'
        )
    return "".join(blocks)


def _quarter_plain(trend: dict[str, Any]) -> list[str]:
    totals = trend.get("totals", {})
    latest = trend.get("latest_four", {})
    previous = trend.get("previous_four", {})
    keys = ("Zero-Day", "Critical", "High", "Medium")
    return [
        "Quarterly Vulnerability Trend — rolling 13 weeks",
        "-----------------------------------------------",
        f"Direction: {trend.get('direction', 'stable')} · latest 4 weeks {sum(int(latest.get(k,0)) for k in keys)} vs previous 4 weeks {sum(int(previous.get(k,0)) for k in keys)}",
        f"Quarter totals: Zero-Day {totals.get('Zero-Day',0)} · Critical {totals.get('Critical',0)} · High {totals.get('High',0)} · Medium {totals.get('Medium',0)}",
        f"Peak week: {trend.get('peak_week') or 'N/A'} · {trend.get('peak_count',0)} observation(s)",
        str(trend.get("counting_note", "")),
    ]


def _quarter_html(trend: dict[str, Any], colours: dict[str, str]) -> str:
    weeks = list(trend.get("weeks") or [])
    mapping = {"Zero-Day": colours["purple"], "Critical": colours["critical"], "High": colours["high"], "Medium": colours["medium"]}
    maximum = max((int(bucket.get(series,0)) for bucket in weeks for series in mapping), default=1) or 1
    header = "".join(f'<th style="padding:3px 1px;color:{colours["muted"]};font-size:8px;">{_esc(bucket.get("label",""))}</th>' for bucket in weeks)
    rows: list[str] = []
    for series, colour in mapping.items():
        cells: list[str] = []
        for bucket in weeks:
            count = int(bucket.get(series, 0))
            width = round((count / maximum) * 100) if count else 0
            bar = (
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>'
                f'<td width="{width}%" height="4" bgcolor="{colour}" style="height:4px;background:{colour};font-size:1px;">&nbsp;</td>'
                f'<td width="{100-width}%" height="4" style="height:4px;font-size:1px;">&nbsp;</td></tr></table>'
                if count else ""
            )
            cells.append(f'<td align="center" style="padding:3px 1px;border-left:1px solid {colours["border"]};font-size:9px;">{count}{bar}</td>')
        rows.append(f'<tr><td width="72" style="padding:4px;color:{colour};font-size:9px;font-weight:700;">{series}</td>' + "".join(cells) + "</tr>")
    totals, latest, previous = trend.get("totals", {}), trend.get("latest_four", {}), trend.get("previous_four", {})
    keys = tuple(mapping)
    concentrations = trend.get("concentrations") or []
    concentration = " · ".join(f"{x.get('vendor')} / {x.get('category')} ({x.get('count')})" for x in concentrations[:3]) or "No material concentration identified yet."
    insight = (
        f'<div style="margin-bottom:8px;font-size:10px;line-height:1.45;">'
        f'<strong>Direction:</strong> {_esc(str(trend.get("direction","stable")).title())} · latest 4 weeks {sum(int(latest.get(k,0)) for k in keys)} vs previous 4 weeks {sum(int(previous.get(k,0)) for k in keys)}<br>'
        f'<strong>Quarter totals:</strong> Zero-Day {totals.get("Zero-Day",0)} · Critical {totals.get("Critical",0)} · High {totals.get("High",0)} · Medium {totals.get("Medium",0)}<br>'
        f'<strong>Peak:</strong> {_esc(trend.get("peak_week") or "N/A")} · {trend.get("peak_count",0)} observation(s)<br>'
        f'<strong>Concentration:</strong> {_esc(concentration)}</div>'
    )
    graph = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="table-layout:fixed;border-collapse:collapse;">' + f'<tr><th width="72"></th>{header}</tr>' + "".join(rows) + "</table>"
    note = f'<div style="margin-top:7px;color:{colours["muted"]};font-size:9px;">{_esc(trend.get("counting_note",""))}</div>'
    return insight + graph + note


def _health_state(entry: dict[str, Any]) -> str:
    state = str(entry.get("health_state", "")).upper()
    if state:
        return state
    if str(entry.get("status", "")).upper() != "OK":
        return "FAILED"
    return "CONTENT" if int(entry.get("items", 0) or 0) else "QUIET"


def _ai_digest_entries(items: list[Item] | None, limit: int = 12) -> list[Item]:
    """Select and order this week's AI Security/Development digest entries.

    Deduplicates by link (the same story can surface from more than one
    source route), then sorts by recency - this is an awareness digest,
    not a severity-ranked list, so "most recent" is the right ordering
    rather than the score-based ranking used for vulnerability records.
    """

    if not items:
        return []
    seen_links: set[str] = set()
    deduped: list[Item] = []
    for item in items:
        if item.link in seen_links:
            continue
        seen_links.add(item.link)
        deduped.append(item)
    deduped.sort(key=lambda item: item.published, reverse=True)
    return deduped[:limit]


def _ai_digest_plain(items: list[Item]) -> list[str]:
    if not items:
        return ["No qualifying AI security or AI development items this week."]
    lines: list[str] = []
    for item in items:
        summary = truncate(item.summary, 160) if item.summary else ""
        lines.append(f"- {item.title} ({item.source}, {item.published.date().isoformat()})")
        if summary:
            lines.append(f"  {summary}")
        lines.append(f"  {item.link}")
    return lines


def _ai_digest_html(items: list[Item], colours: dict[str, str]) -> str:
    if not items:
        return (
            f'<div style="color:{colours["muted"]};">'
            "No qualifying AI security or AI development items this week.</div>"
        )
    rows = []
    for item in items:
        summary = truncate(item.summary, 160) if item.summary else ""
        rows.append(
            '<div style="margin-bottom:10px;padding-bottom:10px;'
            f'border-bottom:1px solid {colours["border"]};">'
            f'<a href="{_esc(item.link)}" style="color:{colours["link"]};'
            f'font-weight:700;text-decoration:none;font-size:13px;">{_esc(item.title)}</a>'
            f'<div style="color:{colours["muted"]};font-size:11px;margin-top:2px;">'
            f'{_esc(item.source)} &middot; {item.published.date().isoformat()}</div>'
            + (
                f'<div style="color:{colours["text"]};font-size:12px;margin-top:4px;">{_esc(summary)}</div>'
                if summary
                else ""
            )
            + "</div>"
        )
    return "".join(rows)


def render_weekly_vulnerability_report(
    records: list[VulnerabilityRecord],
    changes: list[str],
    mtd_records: list[VulnerabilityRecord],
    monthly_counts: list[tuple[str, int]],
    week_start: date,
    week_end: date,
    source_health: list[dict[str, Any]],
    *,
    quarterly_trend: dict[str, Any] | None = None,
    ai_digest: list[Item] | None = None,
) -> tuple[str, str]:
    """Render aligned text/HTML weekly reports with ISO week identification."""

    weekly = _counts(records)
    mtd = _counts(mtd_records)
    week_label = iso_week_label(week_end)
    top_week = _prominent_vulnerabilities(records, limit=10)
    rearview = _prominent_vulnerabilities(mtd_records, limit=20)
    ai_digest_entries = _ai_digest_entries(ai_digest)
    quarterly_trend = quarterly_trend or {"weeks": [], "totals": {}, "latest_four": {}, "previous_four": {}, "direction": "stable", "peak_week": "", "peak_count": 0, "concentrations": [], "counting_note": "No lifecycle trend history available yet."}

    lines = [
        f"Weekly Vulnerability Report — {week_label}",
        f"Reporting window: {week_start.isoformat()} to {week_end.isoformat()}",
        "",
        "Executive vulnerability posture",
        f"Relevant vulnerabilities: {weekly['total']}",
        f"Critical: {weekly['critical']} | High: {weekly['high']}",
        (
            f"Actively exploited: {weekly['exploited']} | "
            f"CISA KEV: {weekly['kev']} | Zero-days: {weekly['zero_day']}"
        ),
        (
            f"Highest EPSS: {weekly['highest_epss']:.1%} | "
            f"Vendors affected: {weekly['vendors']}"
        ),
        "",
        "Top Vulnerabilities of the Week",
        "-------------------------------",
    ]
    if top_week:
        lines.extend(_prominent_plain(record, rank) for rank, record in enumerate(top_week, start=1))
    else:
        lines.append("No qualifying vulnerabilities for the week.")

    lines.extend(["", "Critical & exploited vulnerabilities"])

    for record in records[:25]:
        lines.append(
            f"{_cve_plain(record.cve)} | {_type_and_scope(record)} | {record.vendor} | "
            f"CVSS {record.cvss if record.cvss is not None else 'N/A'} | "
            f"EPSS {record.epss:.1%} | "
            f"KEV {'Yes' if record.kev else 'No'} | "
            f"Exploited {'Yes' if record.exploited else 'No'} | "
            f"{record.remediation_band} | Advisory: {record.link}"
        )

    lines.extend(["", "3. Exploitation, KEV & EPSS Changes"])
    lines.extend(_changes_plain(changes, list(records) + list(mtd_records)))
    lines.extend(["", "4. Remediation Priority"])
    lines.extend(_remediation_plain(records))
    lines.extend([""])
    lines.extend(_quarter_plain(quarterly_trend))

    lines.extend(
        [
            "",
            f"Month-to-date overview — {week_end.strftime('%B %Y')}",
            (
                f"Relevant: {mtd['total']} | Critical: {mtd['critical']} | "
                f"High: {mtd['high']} | KEV: {mtd['kev']} | "
                f"Exploited: {mtd['exploited']} | Zero-days: {mtd['zero_day']}"
            ),
            "",
            "A month in the Rearview",
            "-----------------------",
        ]
    )
    if rearview:
        lines.extend(_prominent_plain(record, rank) for rank, record in enumerate(rearview, start=1))
    else:
        lines.append("No month-to-date vulnerability history available.")

    lines.extend(
        [
            "",
            "AI Security and AI Development",
            "-------------------------------",
        ]
    )
    lines.extend(_ai_digest_plain(ai_digest_entries))

    failed = [
        entry["source"]
        for entry in source_health
        if _health_state(entry) == "FAILED"
    ]
    if failed:
        lines.extend(["", "Source unavailable — status unknown: " + ", ".join(failed)])

    colours = {
        "background": "#00090A",
        "panel": "#022329",
        "panel_alt": "#032D32",
        "border": "#0D4650",
        "text": "#EEF3F8",
        "muted": "#9CB6BA",
        "critical": "#ff5f57",
        "high": "#ff9f43",
        "medium": "#f6c945",
        "green": "#4dd4ac",
        "blue": "#6ea8fe",
        "purple": "#b778ff",
        "link": "#c084fc",
    }

    def panel(title: str, body: str, accent: str) -> str:
        return (
            f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
            f'bgcolor="{colours["panel"]}" style="background:{colours["panel"]};'
            f'border:1px solid {colours["border"]};border-radius:8px;margin-bottom:12px;">'
            f'<tr><td style="padding:13px 15px 7px;color:{accent};font-size:16px;font-weight:700;">{_esc(title)}</td></tr>'
            f'<tr><td style="padding:4px 15px 15px;color:{colours["text"]};">{body}</td></tr></table>'
        )

    metric_cells = "".join(
        f'<td width="14.28%" align="left" valign="top" style="padding:4px;">'
        f'<div style="background:{colours["panel_alt"]};border:1px solid {colours["border"]};border-radius:6px;padding:9px;">'
        f'<div style="font-size:10px;color:{colours["muted"]};">{_esc(label)}</div>'
        f'<div style="font-size:19px;font-weight:700;color:{colour};">{_esc(value)}</div></div></td>'
        for label, value, colour in (
            ("Relevant", weekly["total"], colours["blue"]),
            ("Zero-days", weekly["zero_day"], colours["high"]),
            ("Critical", weekly["critical"], colours["critical"]),
            ("High", weekly["high"], colours["high"]),
            ("Exploited", weekly["exploited"], colours["critical"]),
            ("CISA KEV", weekly["kev"], colours["purple"]),
            ("Highest EPSS", f"{weekly['highest_epss']:.1%}", colours["green"]),
        )
    )

    columns = (
        ("CVE", "14%", "left"),
        ("Vulnerability details", "32%", "left"),
        ("Vendor", "11%", "left"),
        ("CVSS", "7%", "center"),
        ("EPSS", "7%", "center"),
        ("KEV", "7%", "center"),
        ("Exploited", "8%", "center"),
        ("Action", "14%", "left"),
    )
    header_cells = "".join(
        f'<th width="{width}" align="{alignment}" '
        f'style="width:{width};padding:7px 8px;text-align:{alignment};'
        f'vertical-align:bottom;color:{colours["muted"]};font-weight:700;'
        f'border-bottom:1px solid {colours["border"]};">{_esc(label)}</th>'
        for label, width, alignment in columns
    )

    vulnerability_rows_parts: list[str] = []
    for record in records[:25]:
        advisory = (
            f'<a href="{html.escape(record.link, quote=True)}" '
            f'style="color:{colours["link"]};text-decoration:underline;">Advisory ›</a>'
            if record.link
            else ""
        )
        action = (
            f'<span style="color:{colours["high"]};font-weight:700;">'
            f'{_esc(record.remediation_band)}</span>'
            + (f'<br><span style="font-size:10px;">{advisory}</span>' if advisory else "")
        )
        border = f"border-top:1px solid {colours['border']};"
        vulnerability_rows_parts.append(
            "<tr>"
            f'<td width="14%" align="left" valign="top" style="width:14%;padding:8px;{border}text-align:left;">{_cve_html(record.cve, colours["link"])}</td>'
            f'<td width="32%" align="left" valign="top" style="width:32%;padding:8px;{border}text-align:left;color:{colours["text"]};line-height:1.45;">{_esc(_type_and_scope(record))}</td>'
            f'<td width="11%" align="left" valign="top" style="width:11%;padding:8px;{border}text-align:left;color:{colours["text"]};">{_esc(record.vendor)}</td>'
            f'<td width="7%" align="center" valign="top" style="width:7%;padding:8px;{border}text-align:center;white-space:nowrap;">{_esc(f"{record.cvss:.1f}" if record.cvss is not None else "N/A")}</td>'
            f'<td width="7%" align="center" valign="top" style="width:7%;padding:8px;{border}text-align:center;white-space:nowrap;">{record.epss:.1%}</td>'
            f'<td width="7%" align="center" valign="top" style="width:7%;padding:8px;{border}text-align:center;white-space:nowrap;">{"Yes" if record.kev else "No"}</td>'
            f'<td width="8%" align="center" valign="top" style="width:8%;padding:8px;{border}text-align:center;white-space:nowrap;">{"Yes" if record.exploited else "No"}</td>'
            f'<td width="14%" align="left" valign="top" style="width:14%;padding:8px;{border}text-align:left;line-height:1.35;">{action}</td>'
            "</tr>"
        )
    vulnerability_rows = "".join(vulnerability_rows_parts) or (
        f'<tr><td colspan="8" align="left" style="padding:8px;color:{colours["muted"]};">No qualifying CVEs.</td></tr>'
    )
    vulnerability_table = (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="width:100%;table-layout:fixed;border-collapse:collapse;font-size:11px;">'
        f'<tr>{header_cells}</tr>{vulnerability_rows}</table>'
    )

    vendor_cells = [
        f'<td width="25%" valign="top" style="padding:4px;">'
        f'<div style="background:{colours["panel_alt"]};border:1px solid {colours["border"]};'
        f'border-radius:6px;padding:9px;font-size:11px;">'
        f'<strong style="color:{colours["text"]};">{_esc(vendor)}</strong><br>'
        f'<span style="color:{colours["blue"]};">{total} vulnerabilities</span><br>'
        f'{critical} Critical · {exploited} exploited · {kev} KEV</div></td>'
        for vendor, total, critical, exploited, kev in _vendor_summary(records)[:8]
    ]
    vendor_rows = "".join(
        "<tr>" + "".join(vendor_cells[i:i + 4]) + "</tr>"
        for i in range(0, len(vendor_cells), 4)
    )
    vendor_cards = (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        + vendor_rows
        + "</table>"
    )

    change_body = _changes_html(changes, list(records) + list(mtd_records), colours)
    remediation_body = _remediation_html(records, colours)
    quarterly_trend_body = _quarter_html(quarterly_trend, colours)

    mtd_vendor_cells = "".join(
        f'<td width="25%" valign="top" style="padding:4px;">'
        f'<div style="background:{colours["panel_alt"]};border:1px solid {colours["border"]};'
        f'border-radius:6px;padding:9px;font-size:11px;">'
        f'<strong>{_esc(vendor)}</strong><br>{total} vulnerabilities · '
        f'{critical} Critical · {exploited} exploited · {kev} KEV</div></td>'
        for vendor, total, critical, exploited, kev in _vendor_summary(mtd_records)[:8]
    )
    category_counts: dict[str, int] = {}
    for record in mtd_records:
        category_counts[record.category] = category_counts.get(record.category, 0) + 1
    category_rows = "".join(
        f'<tr><td style="padding:3px;color:{colours["text"]};">{_esc(category)}</td>'
        f'<td align="right" style="padding:3px;color:{colours["blue"]};">{count}</td></tr>'
        for category, count in sorted(
            category_counts.items(),
            key=lambda pair: pair[1],
            reverse=True,
        )
    )
    trend_rows = "".join(
        f'<tr><td style="padding:3px;color:{colours["text"]};">{_esc(month)}</td>'
        f'<td align="right" style="padding:3px;color:{colours["green"]};">{count}</td></tr>'
        for month, count in monthly_counts
    )
    mtd_body = (
        f'<p style="color:{colours["muted"]};">Relevant {mtd["total"]} · '
        f'Critical {mtd["critical"]} · High {mtd["high"]} · KEV {mtd["kev"]} · '
        f'Exploited {mtd["exploited"]} · Zero-days {mtd["zero_day"]}</p>'
        f'<table role="presentation" width="100%"><tr>{mtd_vendor_cells}</tr></table>'
        f'<table role="presentation" width="100%"><tr>'
        f'<td width="50%" valign="top"><strong style="color:{colours["purple"]};">'
        f'Top technology categories</strong><table>{category_rows}</table></td>'
        f'<td width="50%" valign="top"><strong style="color:{colours["purple"]};">'
        f'Month-to-month trend</strong><table>{trend_rows}</table></td></tr></table>'
    )

    top_week_body = _prominent_table(
        top_week,
        colours=colours,
        marker="top-week",
    )
    rearview_body = (
        f'<p style="margin:0 0 8px;color:{colours["muted"]};font-size:11px;">'
        f'Most prominent vulnerability records observed during {week_end.strftime("%B %Y")}; '
        'limited to 20.</p>'
        + _prominent_table(
            rearview,
            colours=colours,
            marker="rearview",
        )
    )

    content = [entry["source"] for entry in source_health if _health_state(entry) == "CONTENT"]
    quiet = [entry["source"] for entry in source_health if _health_state(entry) == "QUIET"]
    degraded = [
        entry["source"]
        for entry in source_health
        if _health_state(entry) in {"DEGRADED", "STALE"}
    ]
    failed_sources = [
        entry["source"]
        for entry in source_health
        if _health_state(entry) == "FAILED"
    ]
    source_rows: list[str] = []
    if content:
        source_rows.append(
            f'<div style="color:{colours["green"]};margin-bottom:4px;">'
            f'Collected qualifying content: {len(content)} source(s)</div>'
        )
    if quiet:
        source_rows.append(
            f'<div style="color:{colours["blue"]};margin-bottom:4px;">'
            f'Checked — no qualifying update: {len(quiet)} source(s)</div>'
        )
    if degraded:
        source_rows.append(
            f'<div style="color:{colours["medium"]};margin-bottom:4px;">'
            f'Degraded / partial: {_esc(", ".join(degraded))}</div>'
        )
    if failed_sources:
        source_rows.append(
            f'<div style="color:{colours["critical"]};margin-bottom:4px;">'
            f'Source unavailable — status unknown: {_esc(", ".join(failed_sources))}</div>'
        )
    if not source_rows:
        source_rows.append(
            f'<div style="color:{colours["muted"]};">No source-health data.</div>'
        )
    source_note = "".join(source_rows)

    html_body = f"""<!doctype html><html lang="en"><body bgcolor="{colours['background']}" style="margin:0;padding:0;background:{colours['background']};font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" bgcolor="{colours['background']}" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:16px 10px;">
    <table role="presentation" width="1000" style="width:100%;max-width:1000px;"><tr><td style="padding-bottom:14px;">
    <img src="cid:{LOGO_CONTENT_ID}" alt="Daily Security Brief" width="300" style="display:block;width:100%;max-width:300px;height:auto;border:0;">
    <div style="margin-top:8px;color:{colours['text']};font-size:24px;font-weight:700;">Weekly Vulnerability Report — {_esc(week_label)}</div>
    <div style="color:{colours['muted']};font-size:11px;">{week_start.isoformat()} — {week_end.isoformat()}</div></td></tr>
    <tr><td><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="table-layout:fixed;"><tr>{metric_cells}</tr></table></td></tr>
    <tr><td>{panel('Top Vulnerabilities of the Week', top_week_body, colours['critical'])}</td></tr>
    <tr><td>{panel('1. Critical & Exploited Vulnerabilities', vulnerability_table, colours['critical'])}</td></tr>
    <tr><td>{panel('2. Priority Vendor Vulnerability Overview', vendor_cards, colours['blue'])}</td></tr>
    <tr><td>{panel('3. Exploitation, KEV & EPSS Changes', change_body, colours['purple'])}</td></tr>
    <tr><td>{panel('4. Remediation Priority', remediation_body, colours['high'])}</td></tr>
    <tr><td>{panel('Quarterly Vulnerability Trend — Rolling 13 Weeks', quarterly_trend_body, colours['blue'])}</td></tr>
    <tr><td>{panel('A month in the Rearview', rearview_body, colours['green'])}</td></tr>
    <tr><td>{panel('AI Security and AI Development', _ai_digest_html(ai_digest_entries, colours), colours['purple'])}</td></tr>
    <tr><td>{panel('Month-to-Date Vulnerability Overview — ' + week_end.strftime('%B %Y'), mtd_body, colours['green'])}</td></tr>
    <tr><td>{panel('Source Coverage & Trust', source_note + '<p style="color:' + colours['muted'] + ';font-size:11px;">Tier A authoritative · Tier B primary research · Tier C trusted reporting · Tier D discovery only.</p>', colours['blue'])}</td></tr>
    </table></td></tr></table></body></html>"""
    return "\n".join(lines), html_body
