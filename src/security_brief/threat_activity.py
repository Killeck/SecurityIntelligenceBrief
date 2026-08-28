# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Persistent rolling threat-actor and campaign activity state."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


def _path() -> Path:
    return Path(os.getenv("THREAT_ACTIVITY_STATE_FILE", ".state/threat_activity.json"))


def _parse(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load(path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
    return entries if isinstance(entries, dict) else {}


def merge_activity(
    candidates: Iterable[dict[str, Any]],
    *,
    now: datetime | None = None,
    retention_days: int = 90,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Merge material observations and return the active rolling-quarter view."""

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    target = path or _path()
    records = _load(target)

    for candidate in candidates:
        key = str(candidate.get("key") or candidate.get("label") or "").strip().casefold()
        label = str(candidate.get("label") or "").strip()
        observed = _parse(candidate.get("last_seen"))
        if not key or not label or observed is None:
            continue
        previous = records.get(key)
        previous_seen = _parse(previous.get("last_seen")) if isinstance(previous, dict) else None
        if previous_seen is not None and previous_seen > observed:
            continue
        records[key] = {
            "label": label,
            "activity": str(candidate.get("activity") or "").strip(),
            "last_seen": observed.isoformat(),
            "confidence": str(candidate.get("confidence") or "Single-source report").strip(),
            "source": str(candidate.get("source") or "").strip(),
            "link": str(candidate.get("link") or "").strip(),
        }

    cutoff = now - timedelta(days=max(1, retention_days))
    records = {
        key: value
        for key, value in records.items()
        if (_parse(value.get("last_seen")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
    }

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"entries": records}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass

    values = list(records.values())
    values.sort(
        key=lambda value: _parse(value.get("last_seen")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return values
