# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Daily report quality, source-truth and decision-support policy."""

from __future__ import annotations

import html
import re
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import rendering as base
from .models import Item
from .threat_activity import merge_activity
from .utils import truncate
from .vendor_coverage import CISA_KEV_COVERAGE, VENDOR_COVERAGE, VendorCoverage


EPSS_PATTERN = re.compile(r"EPSS:\s*(\d+(?:\.\d+)?)%", flags=re.IGNORECASE)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", flags=re.IGNORECASE)
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^\)]+\)")
_MARKDOWN_PREFIX = re.compile(r"(?:^|\s)(?:#{1,6}|[-*]{1,3}|>{1,3})\s+")
_MARKDOWN_EMPHASIS = re.compile(r"[*_`]{1,3}")
_ACTIVITY_TERMS = (
    "targeted",
    "targeting",
    "exploited in the wild",
    "active exploitation",
    "exploitation campaign",
    "intrusion campaign",
    "compromised",
    "compromise campaign",
    "deployed malware",
    "ransomware",
    "malicious infrastructure",
    "breach",
    "credential theft",
    "phishing campaign",
)
_RENDER_LOCK = threading.Lock()

_VENDOR_URLS = {
    "HPE": "https://support.hpe.com/connect/s/securitybulletinlibrary",
    "Aruba": "https://support.hpe.com/connect/s/product?language=en_US&tab=alerts",
}


@dataclass(frozen=True)
class VendorStatus:
    label: str
    status: str
    colour: str
    count: int
    entries: tuple[Item, ...]
    information_url: str


def cve_url(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"


def epss_probability(item: Item) -> float:
    match = EPSS_PATTERN.search(item.why or "")
    if not match:
        return 0.0
    try:
        return max(0.0, min(float(match.group(1)) / 100.0, 1.0))
    except ValueError:
        return 0.0


def vulnerability_order_key(item: Item) -> tuple[Any, ...]:
    if item.zero_day:
        evidence_rank = 3
    elif item.exploited or item.kev:
        evidence_rank = 2
    else:
        evidence_rank = 1
    published = item.published.timestamp() if isinstance(item.published, datetime) else 0.0
    return (
        evidence_rank,
        item.cvss_score if item.cvss_score is not None else -1.0,
        epss_probability(item),
        item.score,
        published,
    )


def critical_vulnerability_items(items: Iterable[Item]) -> list[Item]:
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
    result = list(selected_items)
    seen = {_item_key(item) for item in result}
    for item in critical_vulnerability_items(all_items):
        key = _item_key(item)
        if key in seen:
            continue
        result.append(item)
        seen.add(key)
    return result


def _normalise_tldr(item: Item) -> str:
    """Return compact natural language without Markdown/source artefacts."""

    text = base._short_tldr(item) or item.summary or item.title
    text = html.unescape(str(text)).replace("\r", " ").replace("\n", " ")
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _MARKDOWN_PREFIX.sub(" ", text)
    text = _MARKDOWN_EMPHASIS.sub("", text)
    text = re.sub(r"#(?=\d)", "__HASHREF__", text)
    text = re.sub(r"\s*#+\s*", " ", text)
    text = text.replace("__HASHREF__", "#")
    text = re.sub(r"\s+", " ", text).strip(" -–—:;|#")
    text = re.sub(r"([.!?])\1+", r"\1", text)
    return truncate(text, 240)


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
    by_name = {str(entry.get("source", "")): entry for entry in source_health}
    matched = [by_name[name] for name in source_names if name in by_name]
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
        f"{item.title} {item.summary} {item.affected} "
    ).lower()
    product_text = f" {item.title} {item.summary} {item.affected} ".lower()

    # HPE's bulletin library is also Aruba's authoritative publication path.
    # The parser currently labels both as HPE, so use product/title context to
    # prevent every Aruba advisory from also appearing as a generic HPE finding.
    if coverage.label == "Aruba":
        return any(term in product_text for term in coverage.terms)
    if coverage.label == "HPE":
        if any(term in product_text for term in ("aruba", "arubaos", "aos-cx", "clearpass", "instant on")):
            return any(term in product_text for term in ("proliant", "oneview", "simplivity"))
        return any(term in combined for term in coverage.terms)

    return any(term in combined for term in coverage.terms)


def _material_vendor_items(items: Iterable[Item], coverage: VendorCoverage) -> list[Item]:
    matched = [item for item in items if _matches_vendor(item, coverage)]
    material = [
        item
        for item in matched
        if item.kev
        or item.exploited
        or item.zero_day
        or (item.cvss_score is not None and item.cvss_score >= 7.0)
    ]
    return sorted(material, key=vulnerability_order_key, reverse=True)


def _days_ago(value: datetime, now: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0, (now - value.astimezone(timezone.utc)).days)


def _latest_identifier(item: Item) -> str:
    if item.cves:
        return item.cves[0].upper()
    return truncate(item.title, 38)


def _vendor_information_url(label: str, matched: list[Item]) -> str:
    if label in _VENDOR_URLS:
        return _VENDOR_URLS[label]
    return base._vendor_information_url(label, matched)


def vendor_statuses(
    items: list[Item],
    source_health: list[dict[str, Any]],
    *,
    lookback_hours: int = 36,
    now: datetime | None = None,
) -> list[VendorStatus]:
    """Separate source health, in-window priority findings and historical context."""

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    window_cutoff = now - timedelta(hours=max(1, lookback_hours))
    statuses: list[VendorStatus] = []

    kev_items = sorted(
        [item for item in items if item.kev and item.published >= window_cutoff],
        key=vulnerability_order_key,
        reverse=True,
    )
    kev_health, _ = _health_for_sources(CISA_KEV_COVERAGE.authoritative_sources, source_health)
    if kev_items:
        kev_status = f"{len(kev_items)} new addition(s) in reporting window"
        kev_colour = base.DASHBOARD_COLOURS["critical"]
    elif kev_health == "CHECKED":
        kev_status = "Source checked · no new KEV additions in reporting window"
        kev_colour = base.DASHBOARD_COLOURS["green"]
    elif kev_health == "DEGRADED":
        kev_status = "Coverage incomplete · KEV status cannot be confirmed"
        kev_colour = base.DASHBOARD_COLOURS["medium"]
    elif kev_health == "UNAVAILABLE":
        kev_status = "Source unavailable · KEV status unknown"
        kev_colour = base.DASHBOARD_COLOURS["critical"]
    else:
        kev_status = "KEV status unknown"
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
        matched = sorted(
            [item for item in items if _matches_vendor(item, coverage)],
            key=lambda item: item.published,
            reverse=True,
        )
        material = _material_vendor_items(items, coverage)
        current_material = [item for item in material if item.published >= window_cutoff]
        current_matched = [item for item in matched if item.published >= window_cutoff]
        latest_material = material[0] if material else None
        latest_any = matched[0] if matched else None

        expected_sources = (
            coverage.authoritative_sources
            if coverage.has_public_authoritative_path
            else coverage.supporting_sources
        )
        health, _ = _health_for_sources(expected_sources, source_health)

        if current_material:
            status = f"{len(current_material)} priority advisory update(s) in reporting window"
            colour = base.DASHBOARD_COLOURS["high"]
            entries = current_material[:2]
        elif health == "CHECKED" and latest_material is not None:
            age = _days_ago(latest_material.published, now)
            status = (
                "No new priority advisory in reporting window · latest "
                f"{_latest_identifier(latest_material)} · {age} day(s) ago"
            )
            colour = base.DASHBOARD_COLOURS["green"]
            entries = [latest_material]
        elif health == "CHECKED" and current_matched:
            status = "Source checked · no qualifying priority advisory in reporting window"
            colour = base.DASHBOARD_COLOURS["green"]
            entries = current_matched[:1]
        elif health == "CHECKED" and latest_any is not None:
            age = _days_ago(latest_any.published, now)
            status = f"No priority advisory in reporting window · latest advisory {age} day(s) ago"
            colour = base.DASHBOARD_COLOURS["green"]
            entries = [latest_any]
        elif health == "CHECKED":
            status = "Source checked · no qualifying advisory found in retained context"
            colour = base.DASHBOARD_COLOURS["green"]
            entries = []
        elif health == "DEGRADED":
            status = "Coverage incomplete · vendor status cannot be confirmed"
            colour = base.DASHBOARD_COLOURS["medium"]
            entries = [latest_material or latest_any] if (latest_material or latest_any) else []
        elif health == "UNAVAILABLE":
            status = "Source unavailable · vendor status unknown"
            colour = base.DASHBOARD_COLOURS["critical"]
            entries = [latest_material or latest_any] if (latest_material or latest_any) else []
        else:
            status = "Status unknown"
            colour = base.DASHBOARD_COLOURS["medium"]
            entries = [latest_material or latest_any] if (latest_material or latest_any) else []

        if not coverage.has_public_authoritative_path:
            if current_material:
                status += " · supporting coverage only"
            elif health == "CHECKED":
                status += " · authoritative status unknown"
                colour = base.DASHBOARD_COLOURS["medium"]

        statuses.append(
            VendorStatus(
                label=coverage.label,
                status=status,
                colour=colour,
                count=len(current_material),
                entries=tuple(item for item in entries if item is not None),
                information_url=_vendor_information_url(coverage.label, matched),
            )
        )

    statuses.sort(key=lambda value: (-value.count, value.label.casefold()))
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


def render_vulnerability_table(items: list[Item], limit: int = 8) -> str:
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
        cvss = f"{item.cvss_score:.1f}" if item.cvss_score is not None else "N/A"
        rows.append(
            f"""
            <tr>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">{base._pill(severity, colour)}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};color:{base.DASHBOARD_COLOURS['text']};font-weight:700;">{base._escape(item.vendor or item.source)}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">{_cve_links(item.cves)}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};color:{colour};font-weight:700;">{base._escape(cvss)}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};">{base._pill(base._exploit_label(item))}</td>
              <td style="padding:8px;border-top:1px solid {base.DASHBOARD_COLOURS['border']};color:{base.DASHBOARD_COLOURS['muted']};font-size:12px;">{base._escape(_normalise_tldr(item))}</td>
            </tr>
            """
        )
    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:12px;">
      <tr style="color:{base.DASHBOARD_COLOURS['muted']};text-align:left;">
        <th style="padding:7px 8px;">Severity</th><th style="padding:7px 8px;">Vendor</th>
        <th style="padding:7px 8px;">CVE</th><th style="padding:7px 8px;">CVSS</th>
        <th style="padding:7px 8px;">Status</th><th style="padding:7px 8px;">TL;DR</th>
      </tr>{''.join(rows)}
    </table>
    """


def render_priority_vendor_status(
    items: list[Item],
    source_health: list[dict[str, Any]],
    *,
    lookback_hours: int,
) -> str:
    cells: list[str] = []
    for vendor_status in vendor_statuses(
        items,
        source_health,
        lookback_hours=lookback_hours,
    ):
        entry_rows: list[str] = []
        for item in vendor_status.entries[:2]:
            identifier = item.cves[0].upper() if item.cves else ""
            title = truncate(item.title, 68)
            if identifier and identifier.lower() not in title.lower():
                title = f"{identifier} — {title}"
            if identifier:
                visible = (
                    base._link(identifier, cve_url(identifier), colour=base.DASHBOARD_COLOURS["highlight"])
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
        entries_html = (
            '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:3px;">'
            + "".join(entry_rows)
            + "</table>"
            if entry_rows
            else ""
        )
        information_link = base._link(
            "More information ›",
            vendor_status.information_url,
            source=vendor_status.label,
        )
        cells.append(
            f'<td width="33.33%" valign="top" style="padding:4px;">'
            f'<div style="background:{base.DASHBOARD_COLOURS["panel_alt"]};border:1px solid {base.DASHBOARD_COLOURS["border"]};border-radius:5px;padding:8px 9px;font-size:10px;color:{base.DASHBOARD_COLOURS["muted"]};">'
            f'<strong style="color:{base.DASHBOARD_COLOURS["text"]};">{base._escape(vendor_status.label)}</strong><br>'
            f'<span style="color:{vendor_status.colour};">{base._escape(vendor_status.status)}</span>'
            f'{entries_html}<div style="margin-top:5px;font-size:9px;">{information_link}</div></div></td>'
        )
    rows = ["<tr>" + "".join(cells[index:index + 3]) + "</tr>" for index in range(0, len(cells), 3)]
    return '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">' + "".join(rows) + "</table>"


def _threat_candidate(item: Item) -> dict[str, Any] | None:
    combined = f"{item.title} {item.summary} {item.category} {item.why}".lower()
    category = item.category.lower().strip()
    active = (
        item.exploited
        or item.ransomware
        or category in {"active exploitation", "threat actor activity", "ransomware"}
        or any(term in combined for term in _ACTIVITY_TERMS)
    )
    if not active:
        return None

    actor = ""
    confidence = item.confidence or "Single-source report"

    # Prefer explicit actor/campaign identifiers. This does not infer attribution;
    # it only extracts a name already present in the source material.
    patterns = (
        r"\bAPT\d{1,3}\b",
        r"\bUNC\d{3,6}\b",
        r"\bStorm-\d{3,6}\b",
        r"\bTA\d{3,5}\b",
        r"\bLazarus(?: Group)?\b",
        r"\bScattered Spider\b",
        r"\bVolt Typhoon\b",
        r"\bSalt Typhoon\b",
        r"\bLockBit\b",
        r"\bCl0p\b",
        r"\bBlack Basta\b",
        r"\bAkira\b",
    )
    source_text = f"{item.title} {item.summary}"
    for pattern in patterns:
        match = re.search(pattern, source_text, flags=re.IGNORECASE)
        if match:
            actor = match.group(0)
            break

    actor_function = getattr(base, "_actor_from_item", None)
    if not actor and callable(actor_function):
        try:
            actor, actor_confidence = actor_function(item)
            if actor_confidence:
                confidence = actor_confidence
        except Exception:
            actor = ""

    if not actor and (item.ransomware or "campaign" in combined or "threat actor" in combined):
        actor = truncate(item.title, 64)
    if not actor and item.exploited and item.cves:
        actor = f"Exploitation campaign — {item.cves[0].upper()}"
    if not actor:
        return None

    return {
        "key": actor.casefold(),
        "label": actor,
        "activity": truncate(_normalise_tldr(item), 210),
        "last_seen": item.published.isoformat(),
        "confidence": confidence,
        "source": item.source,
        "link": item.link,
    }


def render_threat_activity(items: list[Item], limit: int = 10) -> str:
    """Render the persistent rolling 90-day actor/campaign activity view."""

    candidates = [candidate for item in items if (candidate := _threat_candidate(item))]
    activity = merge_activity(candidates, retention_days=90)[:limit]
    if not activity:
        return (
            f'<p style="margin:0;color:{base.DASHBOARD_COLOURS["muted"]};">'
            "No material tracked threat-actor or campaign activity identified in the rolling 90-day view."
            "</p>"
        )

    now = datetime.now(timezone.utc)
    rows: list[str] = []
    for value in activity:
        try:
            last_seen = datetime.fromisoformat(str(value["last_seen"]).replace("Z", "+00:00"))
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        days = max(0, (now - last_seen.astimezone(timezone.utc)).days)
        evidence = base._link(
            value.get("source") or "Evidence",
            value.get("link") or "",
            source=value.get("source") or "",
            colour=base.DASHBOARD_COLOURS["link"],
        )
        rows.append(
            "<tr>"
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};color:{base.DASHBOARD_COLOURS["text"]};font-weight:700;">{base._escape(value.get("label", ""))}</td>'
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};color:{base.DASHBOARD_COLOURS["muted"]};">{base._escape(value.get("activity", ""))}</td>'
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};white-space:nowrap;">{last_seen.date().isoformat()}</td>'
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};white-space:nowrap;">{days} day(s)</td>'
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};">{base._escape(value.get("confidence", ""))}</td>'
            f'<td style="padding:7px;border-top:1px solid {base.DASHBOARD_COLOURS["border"]};">{evidence}</td>'
            "</tr>"
        )
    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:11px;">
      <tr style="color:{base.DASHBOARD_COLOURS['muted']};text-align:left;">
        <th style="padding:6px;">Actor / campaign</th><th style="padding:6px;">Activity & targeting</th>
        <th style="padding:6px;">Last observed</th><th style="padding:6px;">Days ago</th>
        <th style="padding:6px;">Confidence</th><th style="padding:6px;">Evidence</th>
      </tr>{''.join(rows)}
    </table>
    """


def _watch_theme(item: Item) -> str:
    text = f"{item.section} {item.category} {item.title} {item.summary}".lower()
    if item.cves or item.kev or item.exploited or "vulnerab" in text:
        return "Vulnerability / Exposure"
    if any(term in text for term in ("identity", "entra", "azure", "cloud", "okta", "aws")):
        return "Identity / Cloud"
    if item.ransomware or any(term in text for term in ("threat actor", "ransomware", "campaign", "malware")):
        return "Threat Actor / Ransomware"
    if any(term in text for term in ("artificial intelligence", " ai ", "agentic", "copilot", "llm", "model")):
        return "AI Security & Trust"
    if item.section in {"Compliance", "Standards", "GRC", "Norwegian Security Governance"}:
        return "Governance / Regulation"
    return "Sector / Business Impact"


def _watch_groups(items: list[Item], limit: int) -> list[tuple[str, Item]]:
    selected: dict[str, Item] = {}
    for item in items:
        key = item.cves[0].upper() if item.cves else re.sub(r"[^a-z0-9]+", " ", item.title.lower()).strip()[:80]
        existing = selected.get(key)
        if existing is None or vulnerability_order_key(item) > vulnerability_order_key(existing):
            selected[key] = item
    ordered = sorted(selected.values(), key=vulnerability_order_key, reverse=True)[:limit]
    return [(_watch_theme(item), item) for item in ordered]


def _watch_horizon(item: Item) -> str:
    if item.zero_day or item.exploited or item.kev or (item.cvss_score or 0.0) >= 9.0:
        return "24h"
    return "72h"


def _watch_next_text(item: Item, horizon: str) -> str:
    if horizon == "24h":
        return "Confirm exposure, vendor remediation status and any exploitation/detection changes during the next operational cycle."
    return "Watch for vendor revisions, exploitation confirmation, new detections and sector-specific impact over the next three days."


def render_watch_next(
    items: list[Item],
    exposure_signals: list[Any],
    limit: int = 8,
) -> str:
    """Render grouped 24/72-hour CISO decision support with correlated evidence."""

    groups = _watch_groups(items, limit)
    if not groups:
        return (
            f'<p style="margin:0;color:{base.DASHBOARD_COLOURS["muted"]};">'
            "No material 24/72-hour developments require escalation."
            "</p>"
        )

    sections: list[str] = []
    for horizon, heading in (("24h", "Next 24h — action & verification"), ("72h", "Next 72h — emerging & monitoring")):
        cards: list[str] = []
        for theme, item in groups:
            if _watch_horizon(item) != horizon:
                continue
            cves = ", ".join(item.cves[:3]) or "No CVE identifier"
            cvss = f"CVSS {item.cvss_score:.1f}" if item.cvss_score is not None else "CVSS not stated"
            evidence = (
                f"{item.source} · {cves} · {cvss} · "
                f"{item.confidence} ({item.corroboration_count} source(s))"
            )
            enterprise = item.why or item.affected or "Validate organisational exposure and business impact."
            sector = item.affected or f"Relevant to organisations using affected {item.vendor or item.source} technology."
            source_link = base._link(
                "Evidence ›",
                item.link,
                source=item.source,
                colour=base.DASHBOARD_COLOURS["link"],
            )
            cards.append(
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:0 0 7px 0;background:{base.DASHBOARD_COLOURS["panel_alt"]};border:1px solid {base.DASHBOARD_COLOURS["border"]};border-radius:5px;">'
                f'<tr><td style="padding:8px 10px;color:{base.DASHBOARD_COLOURS["text"]};font-size:11px;line-height:1.4;">'
                f'<strong style="color:{base.DASHBOARD_COLOURS["purple"]};">{base._escape(theme)}</strong><br>'
                f'<strong>Development:</strong> {base._escape(truncate(item.title, 140))}<br>'
                f'<strong>Evidence:</strong> {base._escape(evidence)} · {source_link}<br>'
                f'<strong>Enterprise relevance:</strong> {base._escape(truncate(enterprise, 220))}<br>'
                f'<strong>Sector relevance:</strong> {base._escape(truncate(sector, 180))}<br>'
                f'<strong>What to watch next:</strong> {base._escape(_watch_next_text(item, horizon))}<br>'
                f'<strong>Recommended action:</strong> {base._escape(truncate(item.action or "Validate exposure and apply vendor guidance.", 220))}'
                "</td></tr></table>"
            )
        # Exposure intelligence is kept separate from vulnerability evidence, but
        # high-confidence/high-severity signals still belong in CISO decision support.
        for signal in exposure_signals[:2]:
            severity = str(getattr(signal, "severity", "")).lower()
            confidence = str(getattr(signal, "confidence", "")).lower()
            signal_horizon = "24h" if severity in {"critical", "high"} and "unverified" not in confidence else "72h"
            if signal_horizon != horizon:
                continue
            source = str(getattr(signal, "source", "Exposure intelligence"))
            link = str(getattr(signal, "link", ""))
            source_link = base._link(
                "Evidence ›",
                link,
                source=source,
                confidence=str(getattr(signal, "confidence", "")),
                colour=base.DASHBOARD_COLOURS["link"],
            )
            cards.append(
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:0 0 7px 0;background:{base.DASHBOARD_COLOURS["panel_alt"]};border:1px solid {base.DASHBOARD_COLOURS["border"]};border-radius:5px;">'
                f'<tr><td style="padding:8px 10px;color:{base.DASHBOARD_COLOURS["text"]};font-size:11px;line-height:1.4;">'
                f'<strong style="color:{base.DASHBOARD_COLOURS["purple"]};">Exposure / External Signal</strong><br>'
                f'<strong>Development:</strong> {base._escape(truncate(str(getattr(signal, "title", "Exposure signal")), 140))}<br>'
                f'<strong>Evidence:</strong> {base._escape(source)} · {base._escape(str(getattr(signal, "confidence", "Unknown confidence")))} · {source_link}<br>'
                f'<strong>Enterprise relevance:</strong> {base._escape(truncate(str(getattr(signal, "summary", "Validate whether the signal affects the organisation.")), 220))}<br>'
                f'<strong>Sector relevance:</strong> {base._escape(truncate(str(getattr(signal, "affected", "Potentially affected organisations and exposed identities/assets.")), 180))}<br>'
                f'<strong>What to watch next:</strong> {base._escape("Confirm the signal, scope exposure and watch for corroborating incident or credential activity." if horizon == "24h" else "Watch for corroboration, broader targeting and material changes in confidence or scope.")}<br>'
                f'<strong>Recommended action:</strong> {base._escape(truncate(str(getattr(signal, "action", "Validate exposure before escalation.")), 220))}'
                "</td></tr></table>"
            )

        if cards:
            sections.append(
                f'<div style="margin:7px 0 5px;color:{base.DASHBOARD_COLOURS["highlight"]};font-size:12px;font-weight:700;">{heading}</div>'
                + "".join(cards)
            )
    return "".join(sections)




def _plain_threat_activity(items: list[Item], limit: int = 10) -> list[str]:
    candidates = [candidate for item in items if (candidate := _threat_candidate(item))]
    activity = merge_activity(candidates, retention_days=90)[:limit]
    lines = [
        "2. Active Exploitation / Threat Actor Activity",
        "----------------------------------------------",
    ]
    if not activity:
        lines.append(
            "No material tracked threat-actor or campaign activity identified in the rolling 90-day view."
        )
        return lines

    now = datetime.now(timezone.utc)
    for value in activity:
        try:
            last_seen = datetime.fromisoformat(str(value["last_seen"]).replace("Z", "+00:00"))
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        days = max(0, (now - last_seen.astimezone(timezone.utc)).days)
        lines.append(
            f"- {value.get('label', '')} | {value.get('activity', '')} | "
            f"Last observed {last_seen.date().isoformat()} ({days} day(s) ago) | "
            f"{value.get('confidence', '')} | {value.get('source', '')}: {value.get('link', '')}"
        )
    return lines


def _replace_plain_threat_activity(text: str, items: list[Item]) -> str:
    start_marker = "2. Active Exploitation / Threat Actor Activity"
    start = text.find(start_marker)
    if start < 0:
        return text

    end_markers = (
        "\\n3. Dark Web / Exposure\\n",
        "\\nDark Web / Exposure\\n",
        "\\n3. Vendor Updates\\n",
    )
    ends = [position for marker in end_markers if (position := text.find(marker, start)) >= 0]
    end = min(ends) if ends else len(text)
    replacement = "\\n".join(_plain_threat_activity(items))
    return text[:start].rstrip() + "\\n\\n" + replacement + "\\n\\n" + text[end:].lstrip("\\n")


def _plain_watch_next(items: list[Item], exposure_signals: list[Any], limit: int = 8) -> list[str]:
    """Return the same decision-oriented 24/72 model for the plain-text body."""

    lines = [
        "Security Advisory & CISO Watch Next — 24/72h",
        "----------------------------------------------",
    ]
    groups = _watch_groups(items, limit)
    for horizon, heading in (("24h", "Next 24h — action & verification"), ("72h", "Next 72h — emerging & monitoring")):
        lines.extend(["", heading])
        count = 0
        for theme, item in groups:
            if _watch_horizon(item) != horizon:
                continue
            count += 1
            cves = ", ".join(item.cves[:3]) or "No CVE identifier"
            cvss = f"CVSS {item.cvss_score:.1f}" if item.cvss_score is not None else "CVSS not stated"
            lines.extend(
                [
                    f"- [{theme}] Development: {truncate(item.title, 140)}",
                    f"  Evidence: {item.source} · {cves} · {cvss} · {item.confidence} ({item.corroboration_count} source(s)) · {item.link}",
                    f"  Enterprise relevance: {truncate(item.why or item.affected or 'Validate organisational exposure and business impact.', 220)}",
                    f"  Sector relevance: {truncate(item.affected or 'Validate affected sectors and technology dependencies.', 180)}",
                    f"  What to watch next: {_watch_next_text(item, horizon)}",
                    f"  Recommended action: {truncate(item.action or 'Validate exposure and apply vendor guidance.', 220)}",
                ]
            )
        for signal in exposure_signals[:2]:
            severity = str(getattr(signal, "severity", "")).lower()
            confidence = str(getattr(signal, "confidence", "")).lower()
            signal_horizon = "24h" if severity in {"critical", "high"} and "unverified" not in confidence else "72h"
            if signal_horizon != horizon:
                continue
            count += 1
            lines.extend(
                [
                    f"- [Exposure / External Signal] Development: {truncate(str(getattr(signal, 'title', 'Exposure signal')), 140)}",
                    f"  Evidence: {getattr(signal, 'source', 'Exposure intelligence')} · {getattr(signal, 'confidence', 'Unknown confidence')} · {getattr(signal, 'link', '')}",
                    f"  Enterprise relevance: {truncate(str(getattr(signal, 'summary', 'Validate whether the signal affects the organisation.')), 220)}",
                    f"  Sector relevance: {truncate(str(getattr(signal, 'affected', 'Potentially affected organisations and exposed identities/assets.')), 180)}",
                    "  What to watch next: Confirm or corroborate the signal and monitor changes in scope/confidence.",
                    f"  Recommended action: {truncate(str(getattr(signal, 'action', 'Validate exposure before escalation.')), 220)}",
                ]
            )
        if count == 0:
            lines.append("- No material developments assigned to this horizon.")
    return lines


def _replace_plain_watch_next(text: str, items: list[Item], exposure_signals: list[Any]) -> str:
    """Replace the legacy flat plain-text watch list with the grouped 6.1.3 model."""

    start_marker = "Security Advisory & CISO Watch Next — 24/72h"
    start = text.find(start_marker)
    if start < 0:
        return text
    end = text.find("\nSource Coverage\n", start)
    if end < 0:
        end = len(text)
    replacement = "\n".join(_plain_watch_next(items, exposure_signals))
    prefix = text[:start].rstrip()
    suffix = text[end:].lstrip("\n")
    return prefix + "\n\n" + replacement + ("\n\n" + suffix if suffix else "")

def _linkify_plain_cves(text: str) -> str:
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
    """Render the base report with 6.1.3 intelligence-quality policies applied."""

    all_status_items = status_items if status_items is not None else items
    with _RENDER_LOCK:
        original_table = base._render_vulnerability_table
        original_vendor_status = base._render_priority_vendor_status
        original_build_context = base.build_report_context
        original_threat_rows = base._render_threat_rows
        original_watch_next = base._render_watch_next

        def patched_context(*args: Any, **kwargs: Any) -> Any:
            context = original_build_context(*args, **kwargs)
            context_items = args[0] if args else kwargs.get("items", items)
            return replace(context, critical_special=critical_vulnerability_items(context_items))

        try:
            base._render_vulnerability_table = render_vulnerability_table
            base._render_priority_vendor_status = (
                lambda _selected, _failed=(): render_priority_vendor_status(
                    all_status_items,
                    source_health,
                    lookback_hours=lookback_hours,
                )
            )
            base._render_threat_rows = (
                lambda _selected, limit=5: render_threat_activity(
                    all_status_items,
                    limit=max(limit, 10),
                )
            )
            base._render_watch_next = render_watch_next
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
            base._render_threat_rows = original_threat_rows
            base._render_watch_next = original_watch_next
            base.build_report_context = original_build_context

    for item in critical_vulnerability_items(items):
        if item.zero_day or (item.cvss_score is not None and item.cvss_score >= 9.0):
            continue
        marker = "CISA KEV" if item.kev else "Exploited"
        text_body = text_body.replace(f"- : {item.title} ", f"- {marker}: {item.title} ")
    text_body = _replace_plain_threat_activity(text_body, all_status_items)
    text_body = _replace_plain_watch_next(text_body, items, exposure_signals)
    return _linkify_plain_cves(text_body), html_body
