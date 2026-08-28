"""Persistent, conservative source-health evaluation for report collectors."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
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
    """Record source health without confusing publication cadence with failure.

    Version 6.1.2 could mark a successfully checked but quiet source as STALE
    solely because its last qualifying article was old. That made low-frequency
    sources such as FBI, NIST, standards bodies and some PSIRTs look broken even
    when the collector worked. In 6.1.3, QUIET means the source was checked
    successfully and produced no in-window qualifying content. STALE is reserved
    for a source that *returned content* whose newest timestamp is unexpectedly
    old, or for explicit adapter metadata.
    """

    path = _path()
    records = _load(path)
    previous = records.get(str(entry["source"]), {})
    now = str(entry["checked_at"])
    current_newest = str(entry.get("newest_item") or "")
    newest = current_newest or str(previous.get("newest_seen", ""))
    state = str(entry["health_state"])

    if entry.get("partial") and state in {"CONTENT", "QUIET"}:
        state = "PARTIAL"

    # Publication age is not collector health. A successfully parsed source may
    # legitimately publish infrequently (for example FBI, NIST, ISO or a PSIRT).
    # STALE is therefore reserved for explicit adapter/source metadata rather
    # than inferred solely from the age of the newest article/advisory.

    # A source recovering from a hard failure gets one conservative PARTIAL run
    # when it is merely quiet. A subsequent successful quiet run returns to
    # QUIET. This avoids immediately converting an uncertain recovery into a
    # clean negative while also preventing permanent degradation.
    if state == "QUIET" and previous.get("health_state") in {"FAILED", "STALE"}:
        state = "PARTIAL"

    entry["health_state"] = state
    entry["previous_health_state"] = str(previous.get("health_state", ""))
    entry["health_changed"] = bool(
        entry["previous_health_state"]
        and entry["previous_health_state"] != state
    )

    if str(entry["status"]) == "OK":
        records[str(entry["source"])] = {
            "last_success": now,
            "newest_seen": newest,
            "health_state": state,
        }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"sources": records}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    return entry
