# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Daily report quality policy for vendor truth and vulnerability ordering.

This module deliberately sits between orchestration and the established renderer.
It adds release-policy behaviour without duplicating the large base renderer:

- KEV / priority-vendor status is calculated from all collected items, not only
  the final report selection.
- Vendor negative states depend on the health of the vendor's authoritative
  collection path.
- Critical/zero-day presentation uses a deterministic evidence-first order.
- Critical/exploited/KEV records are retained even when normal report limits are
  reached.
- Plain-text CVE identifiers always carry a direct NVD link.

The base rendering module remains the owner of the email layout.
"""

from __future__ import annotations

import html
import re
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Iterable

from . import rendering as base
from .models import Item
from .utils import truncate
from .vendor_coverage import CISA_KEV_COVERAGE, VENDOR_COVERAGE, VendorCoverage


EPSS_PATTERN = re.compile(
    r"EPSS:\s*(\d+(?:\.\d+)?)%",
    flags=re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", flags=re.IGNORECASE)
_RENDER_LOCK = threading.Lock()


@dataclass(frozen=True)
class VendorStatus:
    """One truthful KEV or priority-vendor status result."""

    label: str
    status: str
    colour: str
    count: int
    entries: tuple[Item, ...]
    information_url: str


def cve_url(cve: str) -> str:
    """Return the canonical NVD deep-dive URL for one CVE identifier."""

    return f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"


def epss_probability(item: Item) -> float:
    """Read FIRST EPSS percentage already appended during enrichment."""

    match = EPSS_PATTERN.search(item.why or "")
    if not match:
        return 0.0
    try:
        return max(0.0, min(float(match.group(1)) / 100.0, 1.0))
    except ValueError:
        return 0.0


def vulnerability_order_key(item: Item) -> tuple[Any, ...]:
    """Return the evidence-first order for the critical vulnerability view.

    Order:
    1. current zero-days;
    2. confirmed exploitation / CISA KEV;
    3. remaining vulnerabilities by CVSS descending;
    4. EPSS descending for equal CVSS;
    5. existing intelligence score and publication time.
    """

    if item.zero_day:
        evidence_rank = 3
    elif item.exploited or item.kev:
        evidence_rank = 2
    else:
        evidence_rank = 1

    published = item.published
    if isinstance(published, datetime):
        published_rank = published.timestamp()
    else:
        published_rank = 0.0

    return (
        evidence_rank,
        item.cvss_score if item.cvss_score is not None else -1.0,
        epss_probability(item),
        item.score,
        published_rank,
    )


def critical_vulnerability_items(items: Iterable[Item]) -> list[Item]:
    """Return all report-critical vulnerability records in display order."""

    selected = [
        item
        for item in items
        if item.zero_day
        or item.exploited
        or item.kev
        or (item.cvss_score is not None and item.cvss_score >= 9.0)
    ]
    return sorted(selected, key=vulnerability_order_key, reverse=True)


def _item_key(item: Item) -> str:
    if item.cves:
        return "|".join(sorted(cve.upper() for cve in item.cves))
    return item.link.lower().rstrip("/")


def ensure_mandatory_vulnerabilities(
    selected_items: list[Item],
    all_items: list[Item],
) -> list[Item]:
    """Retain zero-day, exploited, KEV and CVSS 9+ records past normal limits."""

    result = list(selected_items)
    seen = {_item_key(item) for item in result}
    for item in critical_vulnerability_items(all_items):
        key = _item_key(item)
        if key in seen:
            continue
        result.append(item)
        seen.add(key)
    return result


def _normalised_health_state(entry: dict[str, Any]) -> str:
    explicit = str(entry.get("health_state", "")).upper().strip()
    if explicit in {"CONTENT", "QUIET", "DEGRADED", "STALE", "PARTIAL", "FAILED"}:
        return explicit

    if str(entry.get("status", "")).upper() != "OK":
        return "FAILED"
    return "CONTENT" if int(entry.get("items", 0) or 0) > 0 else "QUIET"


def _health_for_sources(
    source_names: tuple[str, ...],
    source_health: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """Resolve expected source operations to CHECKED/DEGRADED/UNAVAILABLE/UNKNOWN."""

    by_name = {
        str(entry.get("source", "")): entry
        for entry in source_health
    }
    matched = [
        by_name[name]
        for name in source_names
        if name in by_name
    ]
    missing = [name for name in source_names if name not in by_name]

    if not matched:
        return "UNKNOWN", []

    states = [_normalised_health_state(entry) for entry in matched]
    failed = sum(state == "FAILED" for state in states)
    degraded = sum(state in {"DEGRADED", "STALE", "PARTIAL"} for state in states)
    healthy = sum(state in {"CONTENT", "QUIET"} for state in states)

    if failed == len(states) and not missing:
        return "UNAVAILABLE", matched
    if failed or degraded or missing:
        return "DEGRADED", matched
    if healthy == len(states):
        return "CHECKED", matched
    return "UNKNOWN", matched


def _matches_vendor(item: Item, coverage: VendorCoverage) -> bool:
    combined = (
        f" {item.vendor} {item.source} {item.section} "
        f"{item.title} {item.summary} "
    ).lower()
    return any(term in combined for term in coverage.terms)


def _material_vendor_items(
    items: Iterable[Item],
    coverage: VendorCoverage,
) -> list[Item]:
    matched = [item for item in items if _matches_vendor(item, coverage)]
    material = [
        item
        for item in matched
        if item.kev
        or item.exploited
        or item.zero_day
        or (item.cvss_score is not None and item.cvss_score >= 7.0)
    ]
    return sorted(
        material,
        key=lambda item: (
            item.zero_day,
            item.exploited or item.kev,
            item.cvss_score or 0.0,
            epss_probability(item),
            item.score,
            item.published,
        ),
        reverse=True,
    )


def vendor_statuses(
    items: list[Item],
    source_health: list[dict[str, Any]],
) -> list[VendorStatus]:
    """Build truthful status cards using all collected items and source health."""

    statuses: list[VendorStatus] = []

    kev_items = sorted(
        [item for item in items if item.kev],
        key=vulnerability_order_key,
        reverse=True,
    )
    kev_health, _ = _health_for_sources(
        CISA_KEV_COVERAGE.authoritative_sources,
        source_health,
    )
    if kev_items:
        kev_status = f"{len(kev_items)} addition(s)"
        kev_colour = base.DASHBOARD_COLOURS["critical"]
    elif kev_health == "CHECKED":
        kev_status = "Checked — no new additions"
        kev_colour = base.DASHBOARD_COLOURS["green"]
    elif kev_health == "DEGRADED":
        kev_status = "Degraded / partial — status incomplete"
        kev_colour = base.DASHBOARD_COLOURS["medium"]
    elif kev_health == "UNAVAILABLE":
        kev_status = "Source unavailable — status unknown"
        kev_colour = base.DASHBOARD_COLOURS["critical"]
    else:
        kev_status = "Status unknown"
        kev_colour = base.DASHBOARD_COLOURS["medium"]

    statuses.append(
        VendorStatus(
            label="CISA KEV",
            status=kev_status,
            colour=kev_colour,
            count=len(kev_items),
            entries=tuple(kev_items),
            information_url=base.CISA_KEV_CATALOGUE,
        )
    )

    for coverage in VENDOR_COVERAGE:
        material = _material_vendor_items(items, coverage)
        matched = [item for item in items if _matches_vendor(item, coverage)]

        if coverage.has_public_authoritative_path:
            health, _ = _health_for_sources(
                coverage.authoritative_sources,
                source_health,
            )

            if material and health == "CHECKED":
                status = f"{len(material)} material update(s)"
                colour = base.DASHBOARD_COLOURS["high"]
            elif material and health in {"DEGRADED", "UNKNOWN"}:
                status = f"{len(material)} material update(s) · partial coverage"
                colour = base.DASHBOARD_COLOURS["medium"]
            elif material and health == "UNAVAILABLE":
                status = f"{len(material)} material update(s) · source unavailable"
                colour = base.DASHBOARD_COLOURS["medium"]
            elif health == "CHECKED":
                status = "Checked — no material update"
                colour = base.DASHBOARD_COLOURS["green"]
            elif health == "DEGRADED":
                status = "Degraded / partial — status incomplete"
                colour = base.DASHBOARD_COLOURS["medium"]
            elif health == "UNAVAILABLE":
                status = "Source unavailable — status unknown"
                colour = base.DASHBOARD_COLOURS["critical"]
            else:
                status = "Status unknown"
                colour = base.DASHBOARD_COLOURS["medium"]
        else:
            supporting = coverage.supporting_sources
            health, _ = _health_for_sources(supporting, source_health)
            if material:
                status = f"{len(material)} material update(s) · supporting coverage"
                colour = base.DASHBOARD_COLOURS["high"]
            elif health == "UNAVAILABLE":
                status = "Supporting sources unavailable — status unknown"
                colour = base.DASHBOARD_COLOURS["critical"]
            elif health == "DEGRADED":
                status = "Supporting coverage degraded — authoritative status unknown"
                colour = base.DASHBOARD_COLOURS["medium"]
            else:
                status = "Supporting coverage checked — authoritative status unknown"
                colour = base.DASHBOARD_COLOURS["medium"]

        statuses.append(
            VendorStatus(
                label=coverage.label,
                status=status,
                colour=colour,
                count=len(material),
                entries=tuple(material),
                information_url=base._vendor_information_url(
                    coverage.label,
                    matched,
                ),
            )
        )

    statuses.sort(
        key=lambda value: (
            -value.count,
            value.label.casefold(),
        )
    )
    return statuses


def _cve_links(cves: Iterable[str]) -> str:
    links = []
    for cve in cves:
        normalised = cve.upper().strip()
        if not CVE_PATTERN.fullmatch(normalised):
            continue
        links.append(
            base._link(
                normalised,
                cve_url(normalised),
                colour=base.DASHBOARD_COLOURS["link"],
            )
        )
    return ", ".join(links) if links else "—"


def render_vulnerability_table(
    items: list[Item],
    limit: int = 8,
) -> str:
    """Render evidence-first critical/zero-day rows with direct CVE links."""

    selected = critical_vulnerability_items(items)[:limit]
    if not selected:
        return (
            f'<p style="margin:0;color:{base.DASHBOARD_COLOURS["muted"]};">'
            "No critical, exploited, KEV or zero-day vulnerabilities identified."
            "</p>"
        )

    rows: list[str] = []
    for item in selected:
        severity = base.priority(item)
        colour = base._severity_colour(severity)
        cvss = (
            f"{item.cvss_score:.1f}"
            if item.cvss_score is not None
            else "N/A"
        )
        rows.append(
            f"""
            <tr>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">
                {base._pill(severity, colour)}
              </td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};
                         color:{base.DASHBOARD_COLOURS['text']};font-weight:700;">
                {base._escape(item.vendor or item.source)}
              </td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">
                {_cve_links(item.cves)}
              </td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};
                         color:{colour};font-weight:700;">{base._escape(cvss)}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">
                {base._pill(base._exploit_label(item))}
              </td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};
                         color:{base.DASHBOARD_COLOURS['muted']};font-size:12px;">
                {base._escape(base._short_tldr(item))}
              </td>
            </tr>
            """
        )

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="border-collapse:collapse;font-size:12px;">
      <tr style="color:{base.DASHBOARD_COLOURS['muted']};text-align:left;">
        <th style="padding:7px 8px;">Severity</th>
        <th style="padding:7px 8px;">Vendor</th>
        <th style="padding:7px 8px;">CVE</th>
        <th style="padding:7px 8px;">CVSS</th>
        <th style="padding:7px 8px;">Status</th>
        <th style="padding:7px 8px;">TL;DR</th>
      </tr>
      {''.join(rows)}
    </table>
    """


def render_priority_vendor_status(
    items: list[Item],
    source_health: list[dict[str, Any]],
) -> str:
    """Render vendor cards from the truthful status model."""

    cells: list[str] = []
    for vendor_status in vendor_statuses(items, source_health):
        entries = vendor_status.entries
        entry_rows: list[str] = []
        for item in entries[:2]:
            identifier = item.cves[0].upper() if item.cves else ""
            title = truncate(item.title, 68)
            if identifier and identifier.lower() not in title.lower():
                title = f"{identifier} — {title}"

            if identifier:
                visible = (
                    base._link(
                        identifier,
                        cve_url(identifier),
                        colour=base.DASHBOARD_COLOURS["highlight"],
                    )
                    + " — "
                    + base._link(
                        truncate(item.title.replace(identifier, "").strip(" —-"), 50),
                        item.link,
                        source=item.source,
                        colour=base.DASHBOARD_COLOURS["highlight"],
                    )
                )
            else:
                visible = base._link(
                    title,
                    item.link,
                    source=item.source,
                    colour=base.DASHBOARD_COLOURS["highlight"],
                )

            entry_rows.append(
                '<tr><td valign="top" style="padding:3px 5px 0 0;'
                f'color:{vendor_status.colour};font-size:9px;">•</td>'
                '<td style="padding:3px 0 0;font-size:10px;line-height:1.3;">'
                f"{visible}</td></tr>"
            )

        entries_html = ""
        if entry_rows:
            entries_html = (
                '<table role="presentation" width="100%" cellspacing="0" '
                'cellpadding="0" style="margin-top:3px;">'
                + "".join(entry_rows)
                + "</table>"
            )

        information_link = base._link(
            "More information ›",
            vendor_status.information_url,
            source=vendor_status.label,
        )
        cells.append(
            f'<td width="33.33%" valign="top" style="padding:4px;">'
            f'<div style="background:{base.DASHBOARD_COLOURS["panel_alt"]};'
            f'border:1px solid {base.DASHBOARD_COLOURS["border"]};border-radius:5px;'
            f'padding:8px 9px;font-size:10px;color:{base.DASHBOARD_COLOURS["muted"]};">'
            f'<strong style="color:{base.DASHBOARD_COLOURS["text"]};">'
            f"{base._escape(vendor_status.label)}</strong><br>"
            f'<span style="color:{vendor_status.colour};">'
            f"{base._escape(vendor_status.status)}</span>"
            f"{entries_html}"
            f'<div style="margin-top:5px;font-size:9px;">{information_link}</div>'
            "</div></td>"
        )

    rows = [
        "<tr>" + "".join(cells[index:index + 3]) + "</tr>"
        for index in range(0, len(cells), 3)
    ]
    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        + "".join(rows)
        + "</table>"
    )


def _linkify_plain_cves(text: str) -> str:
    """Append an NVD URL to unlinked full CVE identifiers in plain text."""

    lines: list[str] = []
    for line in text.splitlines():
        matches = list(CVE_PATTERN.finditer(line))
        if not matches:
            lines.append(line)
            continue

        parts: list[str] = []
        position = 0
        for match in matches:
            parts.append(line[position:match.start()])
            cve = match.group(0).upper()
            prefix = line[max(0, match.start() - 24):match.start()].lower()
            if prefix.endswith("/detail/") or cve_url(cve) in line:
                parts.append(cve)
            else:
                parts.append(f"{cve} <{cve_url(cve)}>")
            position = match.end()
        parts.append(line[position:])
        lines.append("".join(parts))
    return "\n".join(lines)


def render_report(
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
    upcoming_events: list[dict[str, str]],
    upcoming_days: int,
    source_health: list[dict[str, Any]],
    executive_news: list[Any],
    sector_impacts: list[Any],
    detection_opportunities: list[Any],
    regional_links: list[Any],
    exposure_signals: list[Any],
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
    *,
    status_items: list[Item] | None = None,
) -> tuple[str, str]:
    """Render the base report with release-5.6.5 correctness policies applied."""

    all_status_items = status_items if status_items is not None else items

    with _RENDER_LOCK:
        original_table = base._render_vulnerability_table
        original_vendor_status = base._render_priority_vendor_status
        original_build_context = base.build_report_context

        def patched_context(*args: Any, **kwargs: Any) -> Any:
            context = original_build_context(*args, **kwargs)
            context_items = args[0] if args else kwargs.get("items", items)
            return replace(
                context,
                critical_special=critical_vulnerability_items(context_items),
            )

        try:
            base._render_vulnerability_table = render_vulnerability_table
            base._render_priority_vendor_status = (
                lambda _selected, _failed=(): render_priority_vendor_status(
                    all_status_items,
                    source_health,
                )
            )
            base.build_report_context = patched_context

            text_body, html_body = base.render_report(
                items,
                warnings,
                lookback_hours,
                upcoming_events,
                upcoming_days,
                source_health,
                executive_news,
                sector_impacts,
                detection_opportunities,
                regional_links,
                exposure_signals,
                monitored_brands,
                monitored_domains,
            )
        finally:
            base._render_vulnerability_table = original_table
            base._render_priority_vendor_status = original_vendor_status
            base.build_report_context = original_build_context

    for item in critical_vulnerability_items(items):
        if item.zero_day or (item.cvss_score is not None and item.cvss_score >= 9.0):
            continue
        marker = "CISA KEV" if item.kev else "Exploited"
        text_body = text_body.replace(
            f"- : {item.title} ",
            f"- {marker}: {item.title} ",
        )

    return _linkify_plain_cves(text_body), html_body
