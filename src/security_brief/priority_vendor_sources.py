# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Authoritative security-bulletin coverage for priority enterprise vendors.

The general source catalogue remains focused on broad research, advisory and
news collection. This module adds vendor-owned vulnerability channels where the
vendor publishes a dedicated PSIRT/security-bulletin feed and provides a
structured HPE Security Bulletin Library adapter.

NVD remains a corroborating/fallback source. Its priority-vendor coverage is
implemented here with vendor-specific attribution so AWS, Google, Okta, Palo
Alto Networks and other priority vendors are not hidden inside broad buckets.
"""

from __future__ import annotations

import os
import re
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag
from dateutil import parser as date_parser

from .analysis import build_item
from .collectors import (
    english_nvd_description,
    fetch_rss,
    select_cvss_metric,
)
from .config import NVD_CVE_API, USER_AGENT
from .http_client import get as http_get
from .models import Item, Source
from .rules import ACTIONS, WHY
from .utils import clean_text, ensure_utc, extract_cves


AUTHORITATIVE_VENDOR_RSS_SOURCES: tuple[Source, ...] = (
    Source(
        name="Cisco Security Advisories",
        vendor="Cisco",
        url="https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        source_type="rss",
        base_score=54,
        section="Other Vendor Advisories",
        freshness_days=7,
    ),
    Source(
        name="Fortinet PSIRT RSS",
        vendor="Fortinet",
        url="https://fortiguard.fortinet.com/rss/ir.xml",
        source_type="rss",
        base_score=54,
        section="Fortinet",
    ),
    Source(
        name="AWS Security Bulletins",
        vendor="AWS",
        url="https://aws.amazon.com/security/security-bulletins/rss/feed/",
        source_type="rss",
        base_score=50,
        section="Cloud and Identity",
    ),
    Source(
        name="Google Cloud Security Bulletins",
        vendor="Google",
        url="https://cloud.google.com/feeds/google-cloud-security-bulletins.xml",
        source_type="rss",
        base_score=50,
        section="Cloud and Identity",
    ),
    Source(
        name="Google Chrome Releases",
        vendor="Google",
        url=(
            "https://chromereleases.googleblog.com/feeds/posts/"
            "default?alt=rss"
        ),
        source_type="rss",
        base_score=50,
        section="Other Vendor Advisories",
        topic_keywords=(
            "stable channel update",
            "security fixes",
            "cve-",
        ),
    ),
    Source(
        name="Palo Alto Networks Security Advisories",
        vendor="Palo Alto Networks",
        url="https://security.paloaltonetworks.com/rss.xml",
        source_type="rss",
        base_score=52,
        section="Other Vendor Advisories",
    ),
    Source(
        name="Okta Security Advisories",
        vendor="Okta",
        url="https://trust.okta.com/security-advisories.xml",
        source_type="rss",
        base_score=48,
        section="Cloud and Identity",
    ),
)

HPE_SECURITY_BULLETIN_SOURCE = Source(
    name="HPE Security Bulletin Library",
    vendor="HPE",
    url=(
        "https://support.hpe.com/connect/s/securitybulletinlibrary"
        "?language=en_US"
    ),
    source_type="html",
    base_score=52,
    section="HPE and Aruba",
)

# Generic index-page collectors superseded by the dedicated authoritative
# adapters above. Research sources such as Unit 42, FortiGuard Labs, Google
# Security Blog and AWS Security Blog remain enabled separately.
REPLACED_GENERIC_HTML_SOURCES = frozenset(
    {
        "Fortinet PSIRT",
        "HPE Security Bulletin Library",
        "Okta Security",
        "CISA ICS Advisories",
    }
)

# Specific attribution is intentionally used instead of the older broad NVD
# buckets. Order matters where product names could overlap.
NVD_PRIORITY_VENDOR_COVERAGE: tuple[
    tuple[str, str, tuple[str, ...]], ...
] = (
    (
        "Fortinet",
        "Fortinet",
        (
            "fortinet",
            "fortios",
            "fortigate",
            "fortimanager",
            "fortianalyzer",
            "forticlient",
            "fortiweb",
            "fortimail",
            "fortisandbox",
            "fortinac",
            "fortiproxy",
        ),
    ),
    (
        "HPE",
        "HPE and Aruba",
        (
            "hewlett packard enterprise",
            "hpe aruba",
            "aruba networks",
            "aruba central",
            "arubaos",
            "aos-cx",
            "hpe proliant",
            "hpe oneview",
            "hpe simplivity",
            "hpe networking",
        ),
    ),
    (
        "Palo Alto Networks",
        "Other Vendor Advisories",
        (
            "palo alto networks",
            "pan-os",
            "globalprotect",
            "prisma access",
            "prisma cloud",
            "cortex xdr",
            "cortex xsoar",
            "cortex xsiam",
        ),
    ),
    (
        "Cisco",
        "Other Vendor Advisories",
        (
            "cisco secure",
            "cisco ios xe",
            "cisco nx-os",
            "cisco asa",
            "cisco firepower",
            "cisco adaptive security appliance",
            "cisco ",
        ),
    ),
    (
        "AWS",
        "Cloud and Identity",
        (
            "amazon web services",
            "amazon linux",
            "amazon elastic kubernetes service",
            "amazon eks",
            "amazon elastic container service",
            "amazon ecs",
            "aws sdk",
            "aws cdk",
            "aws-lc",
        ),
    ),
    (
        "Google",
        "Other Vendor Advisories",
        (
            "google chrome",
            "chromium",
            "google cloud",
            "google kubernetes engine",
            "google compute engine",
            "firebase",
            "google looker",
        ),
    ),
    (
        "Okta",
        "Cloud and Identity",
        (
            "okta verify",
            "okta access gateway",
            "okta agent",
            "okta ",
        ),
    ),
    (
        "Apple",
        "Other Vendor Advisories",
        (
            "apple macos",
            "apple ios",
            "apple ipados",
            "apple safari",
            "macos",
            "ipados",
        ),
    ),
    (
        "CrowdStrike",
        "Other Vendor Advisories",
        (
            "crowdstrike",
            "falcon sensor",
        ),
    ),
    (
        "Microsoft",
        "Microsoft, Azure and Identity",
        (
            "microsoft azure",
            "microsoft entra",
            "entra id",
            "microsoft 365",
            "office 365",
            "active directory",
            "microsoft windows",
            "windows server",
            "microsoft exchange",
            "microsoft sharepoint",
        ),
    ),
)

_EXPLICIT_CVSS_RE = re.compile(
    r"\bCVSS(?:v(?:2(?:\.0)?|3(?:\.0|\.1)?|4(?:\.0)?))?"
    r"(?:\s+(?:base\s+)?score)?\s*(?:[:=|\-]\s*)?"
    r"(10(?:\.0)?|[0-9](?:\.\d)?)\b",
    flags=re.IGNORECASE,
)
_HPE_DATE_RE = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2},\s+\d{4}\b",
    flags=re.IGNORECASE,
)
_HPE_DOC_RE = re.compile(
    r"\b(hpesb[a-z]{2}\d+[a-z0-9_]*)\b",
    flags=re.IGNORECASE,
)
_CVSS_VALUE_RE = re.compile(
    r"(?<![\d.])(10(?:\.0)?|[0-9](?:\.\d)?)(?![\d.])"
)


def _severity_from_score(score: float | None) -> str:
    """Return the standard display severity for a CVSS base score."""

    if score is None:
        return "Not available"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _apply_explicit_feed_cvss(item: Item) -> None:
    """Retain the highest explicit bulletin-level CVSS value when supplied."""

    values: list[float] = []
    for raw in _EXPLICIT_CVSS_RE.findall(f"{item.title} {item.summary}"):
        try:
            value = float(raw)
        except ValueError:
            continue
        if 0.0 <= value <= 10.0:
            values.append(value)

    if not values:
        return

    score = max(values)
    if item.cvss_score is None or score > item.cvss_score:
        item.cvss_score = score
        item.cvss_severity = _severity_from_score(score)


def fetch_authoritative_vendor_rss(
    source: Source,
    cutoff: datetime,
) -> list[Item]:
    """Collect one vendor-owned security bulletin or release feed."""

    items = fetch_rss(source, cutoff)
    for item in items:
        _apply_explicit_feed_cvss(item)
    return items


def match_priority_vendor(description: str) -> tuple[str, str] | None:
    """Map an NVD description to one specific priority vendor."""

    lowered = f" {description.lower()} "
    for vendor, section, terms in NVD_PRIORITY_VENDOR_COVERAGE:
        if any(term in lowered for term in terms):
            return vendor, section
    return None


def fetch_priority_vendor_nvd(cutoff: datetime) -> list[Item]:
    """Collect recent NVD CVEs using specific priority-vendor attribution."""

    end = datetime.now(timezone.utc)
    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key

    response = http_get(
        NVD_CVE_API,
        params={
            "pubStartDate": cutoff.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "pubEndDate": end.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "resultsPerPage": 2000,
        },
        headers=headers,
        timeout=90,
    )
    response.raise_for_status()

    items: list[Item] = []
    for vulnerability in response.json().get("vulnerabilities", []):
        cve_record = vulnerability.get("cve", {})
        cve_id = clean_text(cve_record.get("id"))
        description = english_nvd_description(cve_record)
        if not cve_id or not description:
            continue

        coverage = match_priority_vendor(description)
        if coverage is None:
            continue
        vendor, section = coverage

        try:
            published = date_parser.parse(str(cve_record.get("published")))
            if published.tzinfo is None:
                published = published.replace(tzinfo=timezone.utc)
            published = ensure_utc(published)
        except (ValueError, TypeError, OverflowError):
            continue

        cvss_score, cvss_severity, cvss_vector = select_cvss_metric(cve_record)
        category = (
            "Critical vulnerability"
            if cvss_score is not None and cvss_score >= 8.0
            else "Vendor advisory"
        )

        score = 40
        if cvss_score == 10.0:
            score += 50
        elif cvss_score is not None and cvss_score >= 9.0:
            score += 30
        elif cvss_score is not None and cvss_score >= 8.0:
            score += 18
        elif cvss_score is not None and cvss_score >= 7.0:
            score += 10

        items.append(
            Item(
                title=f"{cve_id} — {vendor}",
                summary=description,
                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=published,
                source="NVD Priority Vendor CVEs",
                vendor=vendor,
                section=section,
                category=category,
                score=score,
                cves=[cve_id],
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                affected=(
                    f"Organisations using affected {vendor} products or "
                    "services described in the NVD record."
                ),
                action=ACTIONS.get(category, ACTIONS["General security"]),
                why=WHY.get(category, WHY["General security"]),
            )
        )

    return items


def _clean_hpe_title(value: str) -> str:
    """Remove HPE portal UI text from a bulletin title."""

    title = clean_text(value)
    for marker in (
        " Sign in to continue",
        " Support level validated",
        " Validate your support level",
        " Popular",
    ):
        if marker in title:
            title = title.split(marker, 1)[0].strip()
    return title


def _hpe_release_date(text: str) -> datetime | None:
    match = _HPE_DATE_RE.search(text)
    if not match:
        return None
    try:
        parsed = date_parser.parse(match.group(0))
    except (ValueError, TypeError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return ensure_utc(parsed)


def _hpe_cvss_values(cells: list[str]) -> list[float]:
    """Return CVSS values from the table cell immediately after the CVE cell."""

    cve_index = next(
        (index for index, value in enumerate(cells) if "CVE-" in value.upper()),
        None,
    )
    if cve_index is None or cve_index + 1 >= len(cells):
        return []

    values: list[float] = []
    for raw in _CVSS_VALUE_RE.findall(cells[cve_index + 1]):
        try:
            numeric = float(raw)
        except ValueError:
            continue
        if 0.0 <= numeric <= 10.0:
            values.append(numeric)
    return values


def _hpe_link(row: Tag, row_text: str, page_url: str) -> str:
    anchor = row.select_one(
        "a[href*='docDisplay'], a[href*='docId'], a[href]"
    )
    if isinstance(anchor, Tag):
        href = str(anchor.get("href", "")).strip()
        if href:
            return urljoin(page_url, href)

    document_match = _HPE_DOC_RE.search(row_text)
    if not document_match:
        return ""
    document_id = document_match.group(1)
    return (
        "https://support.hpe.com/hpesc/public/docDisplay"
        f"?docId={document_id}&docLocale=en_US"
    )


def parse_hpe_security_bulletins_html(
    payload: str,
    cutoff: datetime,
    *,
    page_url: str = HPE_SECURITY_BULLETIN_SOURCE.url,
) -> list[Item]:
    """Parse HPE bulletin rows and retain CVE/CVSS/release-date relationships."""

    soup = BeautifulSoup(payload, "html.parser")
    items: list[Item] = []

    for row in soup.select("tr"):
        if not isinstance(row, Tag):
            continue
        cells = [
            clean_text(cell.get_text(" ", strip=True))
            for cell in row.find_all(["td", "th"])
        ]
        if len(cells) < 2:
            continue

        row_text = clean_text(row.get_text(" ", strip=True))
        if "HPESB" not in row_text.upper():
            continue

        published = _hpe_release_date(cells[-1]) or _hpe_release_date(row_text)
        if published is None or published < cutoff:
            continue

        title = _clean_hpe_title(cells[1])
        link = _hpe_link(row, row_text, page_url)
        if not title or not link:
            continue

        summary = cells[2] if len(cells) > 2 else row_text
        base_item = build_item(
            source=HPE_SECURITY_BULLETIN_SOURCE,
            title=title,
            summary=summary,
            link=link,
            published=published,
            cutoff=cutoff,
        )
        if base_item is None:
            continue

        cves = extract_cves(row_text)
        scores = _hpe_cvss_values(cells)
        if not cves:
            items.append(base_item)
            continue

        for index, cve in enumerate(cves):
            score = scores[index] if index < len(scores) else None
            category = (
                "Critical vulnerability"
                if score is not None and score >= 8.0
                else base_item.category
            )
            cve_item = replace(
                base_item,
                title=f"{cve} — {title}",
                cves=[cve],
                category=category,
                cvss_score=score,
                cvss_severity=_severity_from_score(score),
                action=ACTIONS.get(category, base_item.action),
                why=WHY.get(category, base_item.why),
            )
            if score is not None:
                if score >= 9.0:
                    cve_item.score += 30
                elif score >= 8.0:
                    cve_item.score += 18
                elif score >= 7.0:
                    cve_item.score += 10
            items.append(cve_item)

    return items


def fetch_hpe_security_bulletins(cutoff: datetime) -> list[Item]:
    """Collect the official HPE Security Bulletin Library with structured fields."""

    response = http_get(
        HPE_SECURITY_BULLETIN_SOURCE.url,
        timeout=60,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    response.raise_for_status()
    return parse_hpe_security_bulletins_html(
        response.text,
        cutoff,
        page_url=HPE_SECURITY_BULLETIN_SOURCE.url,
    )
