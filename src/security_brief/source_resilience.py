# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Resilient adapters for sources that do not fit one stable generic selector."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from .collectors import fetch_html
from .config import USER_AGENT
from .http_client import get as http_get
from .models import Item, Source
from .utils import clean_text, ensure_utc


_CLAROTY_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CLAROTY_DATE = re.compile(r"\b\d{2}-\d{2}-\d{4}\b")

# These sources have changed page templates often enough that a conservative
# selector fallback is preferable to silently treating a selector miss as
# absence of security content.
RESILIENT_HTML_SOURCES = frozenset(
    {
        "Dragos",
        "FBI Cyber News",
        "ISACA News and Trends",
        "ISO News",
        "NIST CSRC News",
        "Nozomi Networks Labs Blog",
        "Splunk Security Blog",
    }
)


def fetch_resilient_html(source: Source, cutoff: datetime) -> list[Item]:
    """Use the configured parser first, then broader fallback tiers.

    Tier 2 assumes semantic wrapper tags (main/article/h2/h3) - it does not
    help sites (e.g. Webflow-built ones) that render content as plain
    div/a structures with no semantic markup at all. Tier 3 makes no
    structural assumption whatsoever: it selects every anchor on the page
    and relies entirely on the source's include/exclude URL patterns to
    filter to relevant content, so it degrades gracefully even when a
    site's markup shares nothing with a "normal" article-list layout.
    """

    try:
        return fetch_html(source, cutoff)
    except RuntimeError as error:
        if not _is_selector_health_error(error):
            raise

    tier2 = replace(
        source,
        selectors=(
            "main article a[href]",
            "main h2 a[href]",
            "main h3 a[href]",
            "article h2 a[href]",
            "article h3 a[href]",
            "article a[href]",
            "main a[href]",
        ),
        max_candidates=max(source.max_candidates, 50),
    )
    try:
        return fetch_html(tier2, cutoff)
    except RuntimeError as error:
        if not _is_selector_health_error(error):
            raise

    tier3 = replace(
        source,
        selectors=("a[href]",),
        max_candidates=max(source.max_candidates, 60),
    )
    return fetch_html(tier3, cutoff)


def _is_selector_health_error(error: Exception) -> bool:
    message = str(error).lower()
    return any(term in message for term in ("selector", "candidate", "article", "link"))


def _claroty_published(text: str) -> datetime | None:
    match = _CLAROTY_DATE.search(text)
    if not match:
        return None
    try:
        parsed = date_parser.parse(match.group(0), dayfirst=False)
    except (ValueError, TypeError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return ensure_utc(parsed)


def fetch_claroty_team82_disclosures(cutoff: datetime) -> list[Item]:
    """Collect Team82's structured CPS vulnerability disclosure dashboard.

    The research landing page is useful for reading but poor as a vulnerability
    feed. The disclosure dashboard exposes publication date, CVE, vendor and
    product in a stable tabular form and is therefore the correct collection
    surface for vulnerability intelligence.
    """

    url = (
        "https://claroty.com/team82/disclosure-dashboard"
        "?vulnerabilities_direction=desc&vulnerabilities_sort=date"
    )
    response = http_get(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
        timeout=45,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    items: list[Item] = []
    seen: set[str] = set()
    for row in soup.select("table tr"):
        row_text = clean_text(row.get_text(" ", strip=True))
        cve_match = _CLAROTY_CVE.search(row_text)
        published = _claroty_published(row_text)
        if cve_match is None or published is None or published < cutoff:
            continue
        cve = cve_match.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)

        cells = [clean_text(cell.get_text(" ", strip=True)) for cell in row.select("td")]
        vendor = cells[2] if len(cells) >= 3 else "CPS vendor"
        product = cells[3] if len(cells) >= 4 else "cyber-physical system"
        detail = row.select_one("a[href]")
        link = urljoin(url, str(detail.get("href", ""))) if detail else url

        items.append(
            Item(
                title=f"{cve} — {vendor} {product}",
                summary=(
                    f"Claroty Team82 disclosed {cve} affecting {vendor} {product}. "
                    "Validate the vendor advisory and NVD record for severity, affected versions and remediation."
                ),
                link=link,
                published=published,
                source="Claroty Team82",
                vendor=vendor,
                section="OT, Energy and Oil & Gas",
                category="Vulnerability research",
                score=38,
                cves=[cve],
                affected=f"{vendor} {product}",
                action="Validate exposure and apply the affected vendor's remediation or mitigation.",
                why="Team82 coordinated vulnerability disclosure is high-value primary research for CPS/OT environments.",
                confidence="Primary research",
            )
        )

    if not items and not soup.select("table"):
        raise RuntimeError("Claroty Team82 disclosure table not found")
    return items
