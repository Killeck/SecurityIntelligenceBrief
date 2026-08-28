# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Persistent delivery state used to close gaps after failed Daily runs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _path() -> Path:
    return Path(os.getenv("PIPELINE_STATE_FILE", ".state/pipeline_state.json"))


def _load(path: Path | None = None) -> dict[str, Any]:
    target = path or _path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def effective_daily_cutoff(
    now: datetime,
    requested_hours: int,
    *,
    overlap_hours: int = 6,
    max_catchup_days: int = 7,
    path: Path | None = None,
) -> datetime:
    """Return the normal Daily cutoff or a bounded catch-up cutoff.

    A failed Daily run must not create a blind interval. If the last successful
    delivery predates the normal reporting window, the next run resumes from the
    previous success with a small overlap. Catch-up is bounded so a damaged or
    missing state file cannot accidentally create an unbounded historical run.
    """

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    nominal = now - timedelta(hours=requested_hours)
    state = _load(path)
    last_success = _parse_timestamp(state.get("daily_last_success"))
    if last_success is None or last_success >= nominal:
        return nominal

    requested = last_success - timedelta(hours=max(0, overlap_hours))
    floor = now - timedelta(days=max(1, max_catchup_days))
    return max(requested, floor)


def effective_lookback_hours(now: datetime, cutoff: datetime) -> int:
    """Return an integer reporting-window duration for display/logging."""

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    seconds = max(0.0, (now.astimezone(timezone.utc) - cutoff.astimezone(timezone.utc)).total_seconds())
    return max(1, int((seconds + 3599) // 3600))


def mark_daily_success(
    delivered_at: datetime,
    *,
    path: Path | None = None,
) -> None:
    """Persist a successful Daily email-delivery timestamp."""

    target = path or _path()
    if delivered_at.tzinfo is None:
        delivered_at = delivered_at.replace(tzinfo=timezone.utc)
    state = _load(target)
    state["daily_last_success"] = delivered_at.astimezone(timezone.utc).isoformat()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        # State improves continuity but must never turn a successfully delivered
        # report into a failed pipeline result.
        pass
