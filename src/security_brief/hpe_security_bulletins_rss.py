# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""HPE Security Bulletin Library collection via HPE's official RSS feed.

Replaces the HTML table scrape of the Security Bulletin Library search page
with HPE's own RSS feed at ``support.hpe.com``. This is intentionally
best-effort on CVSS/severity extraction: unlike the CSAF/Kubernetes JSON
sources, this feed's item description format has not been directly
inspected against live content in this environment (only cross-referenced
via search results confirming the feed URL and real bulletin IDs). If a
description does not yield a confident CVSS match, the item is still
collected with ``cvss_score=None`` / ``cvss_severity="Not available"``
rather than a fabricated value or a dropped item - the same "absence over
guess" principle used in ``cisa_csaf.py`` and ``kubernetes_cve_feed.py``.

Flagged for a follow-up confirmation pass once a real fetch of this feed's
raw item content is available, to verify whether the severity-extraction
pattern below actually matches HPE's real formatting.
"""

from __future__ import annotations

import re
from datetime import datetime

import feedparser

from .analysis import build_item
from .config import USER_AGENT
from .http_client import get as http_get
from .models import Item, Source
from .utils import feed_entry_time

HPE_SECURITY_BULLETIN_RSS_SOURCE = Source(
    name="HPE Security Bulletin Library",
    vendor="HPE",
    url="https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed.xml",
    source_type="rss",
    base_score=52,
    section="HPE and Aruba",
    freshness_days=30,
)

_CVSS_SCORE_PATTERN = re.compile(
    r"CVSS[^0-9]{0,20}(\d\.\d)", re.IGNORECASE
)
_SEVERITY_WORD_PATTERN = re.compile(
    r"\b(Critical|High|Medium|Low)\b", re.IGNORECASE
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


def _extract_cvss(text: str) -> tuple[float | None, str]:
    """Best-effort CVSS score/severity extraction from title+summary text.

    Tries a numeric score first (more precise); falls back to a bare
    severity word (e.g. "Critical") if no confident numeric match is
    found, so at least coarse triage is possible even without a score.
    """

    score_match = _CVSS_SCORE_PATTERN.search(text)
    if score_match:
        try:
            score = float(score_match.group(1))
            return score, _severity_from_score(score)
        except ValueError:
            pass

    severity_match = _SEVERITY_WORD_PATTERN.search(text)
    if severity_match:
        return None, severity_match.group(1).title()

    return None, "Not available"


def fetch_hpe_security_bulletins_rss(cutoff: datetime) -> list[Item]:
    """Collect HPE Security Bulletin Library entries via the official RSS feed."""

    response = http_get(
        HPE_SECURITY_BULLETIN_RSS_SOURCE.url,
        timeout=60,
        headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml"},
    )
    response.raise_for_status()

    feed = feedparser.parse(response.content)
    if not feed.entries:
        raise RuntimeError("HPE Security Bulletin RSS feed returned no entries")

    items: list[Item] = []
    for entry in feed.entries:
        title = str(getattr(entry, "title", "")).strip()
        link = str(getattr(entry, "link", "")).strip()
        summary = str(getattr(entry, "summary", "") or getattr(entry, "description", "")).strip()
        published = feed_entry_time(entry)
        if not title or not link or published is None:
            continue

        base_item = build_item(
            source=HPE_SECURITY_BULLETIN_RSS_SOURCE,
            title=title,
            summary=summary or title,
            link=link,
            published=published,
            cutoff=cutoff,
        )
        if base_item is None:
            continue

        score, severity = _extract_cvss(f"{title} {summary}")
        base_item.cvss_score = score
        base_item.cvss_severity = severity
        items.append(base_item)

    return items
