# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Corroboration and confidence labelling for material advisory claims."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Item


AUTHORITATIVE_TERMS = (
    "cisa",
    "nvd",
    "security advisory",
    "security bulletin",
    "psirt",
    "msrc",
    "cert-eu",
)


def evidence_key(item: Item) -> str:
    if item.cves:
        return "|".join(sorted(value.upper() for value in item.cves))
    return item.link.lower().rstrip("/")


def annotate_evidence(items: Iterable[Item]) -> None:
    """Annotate items with unique corroborating sources and confidence."""

    grouped: dict[str, set[str]] = defaultdict(set)
    materialised = list(items)
    for item in materialised:
        grouped[evidence_key(item)].add(item.source)

    for item in materialised:
        sources = tuple(sorted(grouped[evidence_key(item)], key=str.casefold))
        authoritative = item.kev or any(
            term in f"{item.source} {item.vendor}".lower()
            for term in AUTHORITATIVE_TERMS
        )
        item.corroborating_sources = sources
        item.corroboration_count = len(sources)
        if authoritative and len(sources) > 1:
            item.confidence = "Authoritative + corroborated"
        elif authoritative:
            item.confidence = "Authoritative source"
        elif len(sources) > 1:
            item.confidence = f"Corroborated by {len(sources)} sources"
        else:
            item.confidence = "Single-source report"
