# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Persistent cross-run duplicate suppression for the Daily report."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Item


def dedup_state_path() -> Path:
    return Path(os.getenv("DAILY_DEDUP_STATE_FILE", ".state/daily_dedup.json"))


def _fingerprint(item: Item) -> str:
    identity = "|".join(sorted(value.upper() for value in item.cves))
    if not identity:
        identity = item.link.lower().rstrip("/")
    material = {
        "identity": identity,
        "title": item.title.strip(),
        "summary": item.summary.strip(),
        "cvss": item.cvss_score,
        "kev": item.kev,
        "exploited": item.exploited,
        "zero_day": item.zero_day,
        "action": item.action.strip(),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True).encode("utf-8")
    ).hexdigest()


def suppress_recent_duplicates(
    items: list[Item],
    *,
    now: datetime | None = None,
    retention_days: int = 7,
    path: Path | None = None,
) -> tuple[list[Item], int]:
    """Return new/materially changed items and persist fingerprints atomically."""

    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=retention_days)
    target = path or dedup_state_path()
    entries: dict[str, str] = {}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            entries = {
                str(key): str(value)
                for key, value in payload.get("fingerprints", {}).items()
            }
    except (OSError, ValueError, TypeError):
        pass

    recent: dict[str, str] = {}
    for key, value in entries.items():
        try:
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            if observed >= cutoff:
                recent[key] = observed.isoformat()
        except ValueError:
            continue

    selected: list[Item] = []
    suppressed = 0
    for item in items:
        fingerprint = _fingerprint(item)
        if fingerprint in recent:
            suppressed += 1
        else:
            selected.append(item)
        recent[fingerprint] = current.isoformat()

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(
        json.dumps({"fingerprints": recent}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return selected, suppressed
