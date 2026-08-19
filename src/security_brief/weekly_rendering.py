# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

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


def _clip(value: str, limit: int) -> str:
    """Return compact single-line prose without cutting through a word."""

    cleaned = " ".join(value.split()).strip().rstrip(".")
    if len(cleaned) <= limit:
        return cleaned
    shortened = cleaned[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{shortened}…"


def _type_and_scope(record: VulnerabilityRecord) -> str:
    """Give a compact explanation of vulnerability nature and impact area."""

    title = _clip(record.title, 90)
    summary = _clip(record.summary, 170)
    scope = _clip(record.affected or record.product or record.category, 90)
    nature = summary or title or "Technical nature not stated by the source"
    if title and title.casefold() not in nature.casefold():
        nature = f"{title}: {nature}"
    return (
        f"Nature: {nature}. Impact area: {scope or 'Not stated'}. "
        f"Evidence: {record.confidence}, {record.corroboration_count} source(s)."
    )


def _change_with_context(
    change: str,
    records_by_cve: dict[str, VulnerabilityRecord],
) -> str:
    """Add concise vulnerability nature and impact context to a lifecycle change."""

    match = CVE_PATTERN.search(change)
    record = records_by_cve.get(match.group(0).upper()) if match else None
    if record is None:
        return change
    nature = _clip(record.summary or record.title or record.category, 135)
    impact = _clip(record.affected or record.product or record.category, 80)
    return f"{change} — Nature: {nature}. Impact area: {impact}."


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


def _health_state(entry: dict[str, Any]) -> str:
    state = str(entry.get("health_state", "")).upper()
    if state:
        return state
    if str(entry.get("status", "")).upper() != "OK":
        return "FAILED"
    return "CONTENT" if int(entry.get("items", 0) or 0) else "QUIET"


def render_weekly_vulnerability_report(
    records: list[VulnerabilityRecord],
    changes: list[str],
    mtd_records: list[VulnerabilityRecord],
    monthly_counts: list[tuple[str, int]],
    week_start: date,
    week_end: date,
    source_health: list[dict[str, Any]],
) -> tuple[str, str]:
    """Render aligned text/HTML weekly reports with ISO week identification."""

    weekly = _counts(records)
    mtd = _counts(mtd_records)
    week_label = iso_week_label(week_end)

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
        "Critical & exploited vulnerabilities",
    ]

    for record in records[:25]:
        lines.append(
            f"{_cve_plain(record.cve)} | {_type_and_scope(record)} | {record.vendor} | "
            f"CVSS {record.cvss if record.cvss is not None else 'N/A'} | "
            f"EPSS {record.epss:.1%} | "
            f"KEV {'Yes' if record.kev else 'No'} | "
            f"Exploited {'Yes' if record.exploited else 'No'} | "
            f"{record.remediation_band} | Advisory: {record.link}"
        )

    records_by_cve = {record.cve.upper(): record for record in records}
    contextual_changes = [
        _change_with_context(change, records_by_cve)
        for change in changes[:20]
    ]

    lines.extend(["", "Exploitation & KEV changes"])
    if changes:
        lines.extend(_linkify_cves_plain(change) for change in contextual_changes)
    else:
        lines.append("No lifecycle state changes identified.")

    lines.extend(
        [
            "",
            f"Month-to-date overview — {week_end.strftime('%B %Y')}",
            (
                f"Relevant: {mtd['total']} | Critical: {mtd['critical']} | "
                f"High: {mtd['high']} | KEV: {mtd['kev']} | "
                f"Exploited: {mtd['exploited']} | Zero-days: {mtd['zero_day']}"
            ),
        ]
    )

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
        ("CVE", "13%", "left"),
        ("Vulnerability details", "34%", "left"),
        ("Vendor", "10%", "left"),
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
            f'<td width="13%" align="left" valign="top" style="width:13%;padding:8px;{border}text-align:left;">{_cve_html(record.cve, colours["link"])}</td>'
            f'<td width="34%" align="left" valign="top" style="width:34%;padding:8px;{border}text-align:left;color:{colours["text"]};line-height:1.4;">{_esc(_type_and_scope(record))}</td>'
            f'<td width="10%" align="left" valign="top" style="width:10%;padding:8px;{border}text-align:left;color:{colours["text"]};">{_esc(record.vendor)}</td>'
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

    change_rows = "".join(
        '<tr><td valign="top" style="padding:4px 8px 4px 0;'
        f'color:{colours["purple"]};">◆</td>'
        f'<td style="padding:4px;color:{colours["text"]};">'
        f'{_linkify_cves_html(change, colours["link"])}</td></tr>'
        for change in contextual_changes
    ) or (
        f'<tr><td style="color:{colours["muted"]};">'
        "No lifecycle state changes identified.</td></tr>"
    )

    remediation_cells: list[str] = []
    for band in (
        "Patch immediately",
        "Patch within 7 days",
        "Validate exposure",
        "Monitor",
    ):
        selected = [record for record in records if record.remediation_band == band]
        cve_rows = "<br>".join(
            _cve_html(record.cve, colours["link"])
            for record in selected[:8]
        ) or "None"
        remediation_cells.append(
            f'<td width="25%" valign="top" style="padding:4px;">'
            f'<div style="background:{colours["panel_alt"]};border:1px solid {colours["border"]};'
            f'border-radius:6px;padding:9px;">'
            f'<strong style="color:{colours["high"]};font-size:11px;">{_esc(band)}</strong>'
            f'<div style="margin-top:5px;color:{colours["text"]};font-size:11px;'
            f'line-height:1.5;">{cve_rows}</div></div></td>'
        )

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
    <tr><td>{panel('1. Critical & Exploited Vulnerabilities', vulnerability_table, colours['critical'])}</td></tr>
    <tr><td>{panel('2. Priority Vendor Vulnerability Overview', vendor_cards, colours['blue'])}</td></tr>
    <tr><td>{panel('3. Exploitation, KEV & EPSS Changes', '<table role="presentation">' + change_rows + '</table>', colours['purple'])}</td></tr>
    <tr><td>{panel('4. Remediation Priority', '<table role="presentation" width="100%"><tr>' + ''.join(remediation_cells) + '</tr></table>', colours['high'])}</td></tr>
    <tr><td>{panel('Month-to-Date Vulnerability Overview — ' + week_end.strftime('%B %Y'), mtd_body, colours['green'])}</td></tr>
    <tr><td>{panel('Source Coverage & Trust', source_note + '<p style="color:' + colours['muted'] + ';font-size:11px;">Tier A authoritative · Tier B primary research · Tier C trusted reporting · Tier D discovery only.</p>', colours['blue'])}</td></tr>
    </table></td></tr></table></body></html>"""
    return "\n".join(lines), html_body
