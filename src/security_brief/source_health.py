"""Persistent, conservative source-health evaluation for report collectors."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _path() -> Path:
    return Path(os.getenv("SOURCE_HEALTH_STATE_FILE", ".state/source_health.json"))


def _load(path: Path) -> dict[str, dict[str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload.get("sources", {}) if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}


def _timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def assess_and_persist(entry: dict[str, Any], *, freshness_days: int = 14) -> dict[str, Any]:
    """Record a source run and mark stale state without turning it into quiet.

    The state file is deliberately optional: a read-only or ephemeral runner
    still reports current-run truth.  A prior newest-seen timestamp is retained
    when the current reporting window has no qualifying item.
    """
    path = _path()
    records = _load(path)
    previous = records.get(str(entry["source"]), {})
    now = str(entry["checked_at"])
    newest = str(entry.get("newest_item") or previous.get("newest_seen", ""))
    state = str(entry["health_state"])
    # Adapters may confirm that the index was reachable while reporting an
    # incomplete expected dataset. Preserve that distinction from a clean quiet
    # result; report policy will consequently refuse a clean negative.
    if entry.get("partial") and state in {"CONTENT", "QUIET"}:
        state = "PARTIAL"
    newest_at = _timestamp(newest)
    if state in {"CONTENT", "QUIET"} and newest_at and newest_at < datetime.now(timezone.utc) - timedelta(days=freshness_days):
        state = "STALE"
    if state == "QUIET" and previous.get("health_state") in {"FAILED", "STALE"}:
        state = "PARTIAL"
    entry["health_state"] = state
    entry["previous_health_state"] = str(previous.get("health_state", ""))
    entry["health_changed"] = bool(entry["previous_health_state"] and entry["previous_health_state"] != state)
    if str(entry["status"]) == "OK":
        records[str(entry["source"])] = {"last_success": now, "newest_seen": newest, "health_state": state}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"sources": records}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass
    return entry
