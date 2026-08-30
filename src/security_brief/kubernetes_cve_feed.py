# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Kubernetes official CVE collection via its JSON Feed.

kubernetes.io publishes a JSON Feed (jsonfeed.org spec) of every official
CVE, auto-refreshed from the upstream tracking issues. This is preferred
over the equivalent RSS/Atom-style feed: dates arrive as clean ISO8601 in
``date_published`` rather than requiring feedparser's struct_time handling,
and ``id`` is the literal CVE identifier rather than something to extract
from title text via regex - fewer places for a parsing edge case to
silently drop an entry.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .analysis import build_item
from .config import USER_AGENT
from .http_client import get as http_get
from .models import Item, Source

KUBERNETES_CVE_FEED_SOURCE = Source(
    name="Kubernetes Official CVE Feed",
    vendor="Kubernetes",
    url="https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
    source_type="api",
    base_score=30,
    section="Cloud and Identity",
    freshness_days=30,
)

_CVSS_SCORE_IN_PARENS = re.compile(r"\((?:[Ss]core:\s*)?(\d\.\d)(?:,\s*\w+)?\)")
_CVSS_SCORE_BEFORE_SEVERITY = re.compile(
    r"(?<!CVSS:)(?<!/)(\d\.\d)\s*\((?:CRITICAL|HIGH|MEDIUM|LOW)\)", re.IGNORECASE
)


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "Not available"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_cvss_score(content_text: str) -> float | None:
    """Best-effort CVSS base score extraction from the free-text advisory body.

    The JSON Feed does not carry a structured CVSS field - the score appears
    inline in ``content_text`` in inconsistent formats across advisories
    (e.g. "Medium (6.5)", "(Score: 6.5)", "8.8 (Medium)"). Deliberately
    anchored on a number inside parentheses (or immediately followed by a
    parenthesised severity word) rather than any bare decimal, since the
    CVSS *vector* string itself always contains a bare, non-parenthesised
    version number (e.g. "CVSS:3.1/AV:N/...") that a looser pattern would
    incorrectly match as the score. Returns None (not a fabricated 0.0)
    when no confident match is found, matching the same "absence over
    guess" behaviour used elsewhere (e.g. CISA CSAF).
    """

    match = _CVSS_SCORE_IN_PARENS.search(content_text)
    if not match:
        match = _CVSS_SCORE_BEFORE_SEVERITY.search(content_text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def fetch_kubernetes_cve_feed(cutoff: datetime) -> list[Item]:
    """Collect Kubernetes CVE Feed entries published since ``cutoff``."""

    response = http_get(
        KUBERNETES_CVE_FEED_SOURCE.url,
        timeout=45,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()

    items: list[Item] = []
    for entry in payload.get("items", []):
        cve_id = str(entry.get("id", "")).strip().upper()
        summary = str(entry.get("summary", "")).strip()
        published_raw = entry.get("date_published")
        link = str(entry.get("external_url") or entry.get("url") or "")
        if not cve_id or not summary or not published_raw or not link:
            continue

        try:
            published = datetime.fromisoformat(str(published_raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        published = published.astimezone(timezone.utc)

        base_item = build_item(
            source=KUBERNETES_CVE_FEED_SOURCE,
            title=f"{cve_id} - {summary}",
            summary=summary,
            link=link,
            published=published,
            cutoff=cutoff,
        )
        if base_item is None:
            continue

        score = _extract_cvss_score(str(entry.get("content_text", "")))
        if cve_id not in base_item.cves:
            base_item.cves = [cve_id]
        base_item.cvss_score = score
        base_item.cvss_severity = _severity_from_score(score)
        items.append(base_item)

    return items
