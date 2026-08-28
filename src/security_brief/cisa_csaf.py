# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Structured CISA advisory collection via the cisagov/CSAF GitHub repository.

CISA publishes every IT, OT and vulnerability-advisory (VA) bulletin as a
machine-readable CSAF 2.0 JSON document in ``github.com/cisagov/CSAF``. This
module replaces brittle HTML scraping of cisa.gov advisory listing pages with
direct, structured collection: CVE IDs, CVSS scores, vendor/product names and
tracking dates are read straight from the CSAF document rather than parsed
out of rendered HTML.

Efficient polling: rather than re-downloading every advisory file in a branch
on every run (~350+ files/year/branch), this uses the GitHub Commits API,
filtered by ``path`` and ``since``, to find only the files actually added or
modified inside the collection window, then fetches just those files' raw
JSON content.

An optional ``GITHUB_TOKEN`` environment variable raises the GitHub API rate
limit from 60/hour (unauthenticated) to 5,000/hour and is recommended for
production use, following the same optional-credential pattern used by
``NVD_API_KEY`` and ``HIBP_API_KEY`` elsewhere in this codebase. Collection
degrades gracefully (raises, caught by the caller's source-health layer) if
the unauthenticated rate limit is exhausted rather than silently returning
partial/stale data as a false negative.
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timezone

from .analysis import build_item
from .http_client import get as http_get
from .config import USER_AGENT
from .models import Item, Source
from .rules import ACTIONS, WHY

CSAF_REPO = "cisagov/CSAF"
CSAF_API_BASE = f"https://api.github.com/repos/{CSAF_REPO}"
CSAF_RAW_BASE = f"https://raw.githubusercontent.com/{CSAF_REPO}/main"

# Branch -> (Source metadata used for scoring/section placement, human label)
CSAF_BRANCHES: dict[str, "Source"] = {
    "OT": Source(
        name="CISA CSAF - OT Advisories",
        vendor="CISA",
        url=f"{CSAF_RAW_BASE}/csaf_files/OT/white/",
        source_type="api",
        base_score=42,
        section="OT, Energy and Oil & Gas",
        freshness_days=14,
    ),
    "IT": Source(
        name="CISA CSAF - IT Advisories",
        vendor="CISA",
        url=f"{CSAF_RAW_BASE}/csaf_files/IT/white/",
        source_type="api",
        base_score=38,
        section="Other Vendor Advisories",
        freshness_days=14,
    ),
    "VA": Source(
        name="CISA CSAF - Vulnerability Advisories",
        vendor="CISA",
        url=f"{CSAF_RAW_BASE}/csaf_files/VA/white/",
        source_type="api",
        base_score=36,
        section="Vulnerability Research",
        freshness_days=14,
    ),
}


def _github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _changed_json_paths(branch: str, cutoff: datetime) -> set[str]:
    """Return the set of advisory JSON paths added/modified since ``cutoff``.

    Queries the current and, if the window crosses a year boundary, the
    previous year's advisory directory, since files are organised by year.
    """

    since = cutoff.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    years = {cutoff.astimezone(timezone.utc).year, datetime.now(timezone.utc).year}

    paths: set[str] = set()
    for year in years:
        dir_path = f"csaf_files/{branch}/white/{year}"
        page = 1
        while page <= 5:  # bounded: a well-behaved window should not need more
            response = http_get(
                f"{CSAF_API_BASE}/commits",
                timeout=45,
                headers=_github_headers(),
                params={
                    "path": dir_path,
                    "since": since,
                    "per_page": 100,
                    "page": page,
                },
            )
            if response.status_code == 404:
                break  # that year's directory does not exist yet/at all
            response.raise_for_status()
            commits = response.json()
            if not commits:
                break

            for commit in commits:
                sha = commit.get("sha")
                if not sha:
                    continue
                detail = http_get(
                    f"{CSAF_API_BASE}/commits/{sha}",
                    timeout=45,
                    headers=_github_headers(),
                )
                detail.raise_for_status()
                for changed in detail.json().get("files", []):
                    filename = changed.get("filename", "")
                    if filename.startswith(dir_path) and filename.endswith(".json"):
                        paths.add(filename)

            if len(commits) < 100:
                break
            page += 1

    return paths


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


def _parse_csaf_document(
    document: dict,
    *,
    path: str,
    source: Source,
    branch: str,
    cutoff: datetime,
) -> list[Item]:
    """Convert one CSAF 2.0 JSON document into per-CVE Items."""

    tracking = document.get("document", {}).get("tracking", {})
    title = str(document.get("document", {}).get("title", "")).strip()
    tracking_id = str(tracking.get("id", "")).strip()
    if not title or not tracking_id:
        return []

    raw_date = tracking.get("current_release_date") or tracking.get("initial_release_date")
    try:
        published = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return []
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    published = published.astimezone(timezone.utc)
    if published < cutoff:
        return []

    link = (
        f"https://github.com/cisagov/CSAF/blob/main/{path}"
    )

    vulnerabilities = document.get("vulnerabilities", []) or [{}]
    items: list[Item] = []
    for vuln in vulnerabilities:
        cve = str(vuln.get("cve", "")).strip().upper()
        score = None
        for entry in vuln.get("scores", []) or []:
            metric = entry.get("cvss_v4") or entry.get("cvss_v3") or entry.get("cvss_v2")
            if metric and metric.get("baseScore") is not None:
                score = float(metric["baseScore"])
                break

        item_title = f"{cve} — {title}" if cve else f"{tracking_id} — {title}"
        summary = f"CISA {tracking_id}: structured advisory via cisagov/CSAF ({branch} branch)."

        base_item = build_item(
            source=source,
            title=item_title,
            summary=summary,
            link=link,
            published=published,
            cutoff=cutoff,
        )
        if base_item is None:
            continue

        category = (
            "Critical vulnerability"
            if score is not None and score >= 8.0
            else base_item.category
        )
        cve_item = replace(
            base_item,
            cves=[cve] if cve else [],
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


def fetch_cisa_csaf_branch(branch: str, cutoff: datetime) -> list[Item]:
    """Collect one CSAF branch (``OT``, ``IT`` or ``VA``) for the given window."""

    source = CSAF_BRANCHES[branch]
    items: list[Item] = []
    for path in sorted(_changed_json_paths(branch, cutoff)):
        response = http_get(
            f"{CSAF_RAW_BASE}/{path}",
            timeout=45,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        try:
            document = response.json()
        except ValueError:
            continue
        items.extend(
            _parse_csaf_document(
                document, path=path, source=source, branch=branch, cutoff=cutoff
            )
        )
    return items


def fetch_cisa_csaf(cutoff: datetime, branches: tuple[str, ...] = ("OT", "IT", "VA")) -> list[Item]:
    """Collect all requested CSAF branches for the given cutoff window."""

    items: list[Item] = []
    for branch in branches:
        items.extend(fetch_cisa_csaf_branch(branch, cutoff))
    return items
