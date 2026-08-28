# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""AI Security & Trustworthiness framework-update trackers.

Both MITRE ATLAS and the OWASP GenAI LLM Top 10 are maintained as GitHub
repositories with no stable HTML page structure worth scraping. This module
tracks material framework updates directly from GitHub instead:

- MITRE ATLAS (``mitre-atlas/atlas-data``) publishes a dated GitHub Release
  roughly monthly, with a structured changelog body (new/updated tactics,
  techniques, mitigations, case studies). Verified working against the live
  API.
- OWASP GenAI LLM Top 10 (``GenAI-Security-Project/GenAI-LLM-Top10``) does
  not use GitHub Releases (confirmed empty via the Releases API) - it is
  tracked via the Commits API instead, the same verified mechanism used by
  ``cisa_csaf.py``.

Release/commit body text is deliberately NOT reproduced verbatim in the
generated summary (copyright: paraphrase, don't quote) - only counts and a
link to the source are surfaced.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from .analysis import build_item
from .config import USER_AGENT
from .http_client import get as http_get
from .models import Item, Source

AI_TRACKER_API_BASE = "https://api.github.com"

MITRE_ATLAS_SOURCE = Source(
    name="MITRE ATLAS Framework Updates",
    vendor="MITRE",
    url=f"{AI_TRACKER_API_BASE}/repos/mitre-atlas/atlas-data/releases",
    source_type="api",
    base_score=26,
    section="AI Security and Trustworthiness",
    freshness_days=45,
)

OWASP_LLM_TOP10_SOURCE = Source(
    name="OWASP GenAI LLM Top 10 Updates",
    vendor="OWASP",
    url=f"{AI_TRACKER_API_BASE}/repos/GenAI-Security-Project/GenAI-LLM-Top10/commits",
    source_type="api",
    base_score=24,
    section="AI Security and Trustworthiness",
    freshness_days=60,
)


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


def _counts_from_release_body(body: str) -> str:
    """Extract the leading summary line of an ATLAS release body, if present.

    ATLAS release bodies open with a line such as "This version of ATLAS
    data contains 1 matrix, 16 tactics, 101 techniques, ...". That factual
    count line is reused verbatim-safe (it is a list of numbers, not
    original prose) rather than paraphrasing the surrounding changelog.
    """

    match = re.search(r"This version of ATLAS data contains[^.\n]*\.", body)
    return match.group(0) if match else ""


def fetch_mitre_atlas_updates(cutoff: datetime) -> list[Item]:
    """Collect MITRE ATLAS releases published since ``cutoff``."""

    response = http_get(
        MITRE_ATLAS_SOURCE.url,
        timeout=45,
        headers=_github_headers(),
        params={"per_page": 10},
    )
    response.raise_for_status()

    items: list[Item] = []
    for release in response.json():
        tag = str(release.get("tag_name", "")).strip()
        published_raw = release.get("published_at") or release.get("created_at")
        if not tag or not published_raw:
            continue
        try:
            published = datetime.fromisoformat(str(published_raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        published = published.astimezone(timezone.utc)

        counts = _counts_from_release_body(str(release.get("body", "")))
        summary = (
            f"MITRE ATLAS content release {tag}. {counts}".strip()
            or f"MITRE ATLAS content release {tag}."
        )

        item = build_item(
            source=MITRE_ATLAS_SOURCE,
            title=f"MITRE ATLAS {tag} - adversarial AI tactics/techniques update",
            summary=summary,
            link=str(release.get("html_url", MITRE_ATLAS_SOURCE.url)),
            published=published,
            cutoff=cutoff,
        )
        if item is not None:
            items.append(item)
    return items


def fetch_owasp_llm_top10_updates(cutoff: datetime) -> list[Item]:
    """Collect OWASP GenAI LLM Top 10 commit activity since ``cutoff``."""

    since = cutoff.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    response = http_get(
        OWASP_LLM_TOP10_SOURCE.url,
        timeout=45,
        headers=_github_headers(),
        params={"since": since, "per_page": 20},
    )
    response.raise_for_status()
    commits = response.json()
    if not commits:
        return []

    # A single summary Item per collection window rather than one Item per
    # commit: individual commits are typically small edits (wording, links),
    # and the OWASP list itself changes infrequently enough that a rollup is
    # more useful than a flood of near-duplicate entries.
    latest = commits[0]
    published_raw = latest.get("commit", {}).get("author", {}).get("date")
    if not published_raw:
        return []
    try:
        published = datetime.fromisoformat(str(published_raw).replace("Z", "+00:00"))
    except ValueError:
        return []
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    published = published.astimezone(timezone.utc)

    item = build_item(
        source=OWASP_LLM_TOP10_SOURCE,
        title=f"OWASP GenAI LLM Top 10 updated ({len(commits)} change(s) in window)",
        summary=(
            "The OWASP GenAI LLM Top 10 repository received "
            f"{len(commits)} commit(s) in the collection window - review for "
            "wording, ranking or new-risk changes to the published Top 10."
        ),
        link="https://genai.owasp.org/llm-top-10/",
        published=published,
        cutoff=cutoff,
    )
    return [item] if item is not None else []
