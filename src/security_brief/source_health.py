"""Persistent, conservative source-health evaluation for report collectors."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _path() -> Path:
    return Path(
        os.getenv(
            "SOURCE_HEALTH_STATE_FILE",
            ".state/source_health.json",
        )
    )


def _load(path: Path) -> dict[str, dict[str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload.get("sources", {}) if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}


def assess_and_persist(
    entry: dict[str, Any],
    *,
    freshness_days: int = 14,
) -> dict[str, Any]:
    """Persist conservative source health across collector runs.

    Source health and publication cadence are deliberately separate concepts.
    A successfully checked source may legitimately be quiet for long periods.

    Recovery policy:
    - hard failures are persisted;
    - the first successful-but-empty check after FAILED or STALE is PARTIAL;
    - a second successful quiet check returns to QUIET;
    - successful CONTENT immediately restores CONTENT;
    - explicit collector ``partial`` metadata remains PARTIAL.

    ``freshness_days`` remains in the public signature for compatibility with
    source definitions, but 6.1.3 does not infer collector failure solely from
    the age of the newest publication.
    """

    del freshness_days

    path = _path()
    records = _load(path)
    source = str(entry["source"])
    previous = records.get(source, {})

    checked_at = str(entry["checked_at"])
    status = str(entry["status"]).upper().strip()
    state = str(entry["health_state"]).upper().strip()
    previous_state = str(previous.get("health_state", "")).upper().strip()

    current_newest = str(entry.get("newest_item") or "")
    newest_seen = current_newest or str(previous.get("newest_seen", ""))

    if entry.get("partial") and state in {"CONTENT", "QUIET"}:
        state = "PARTIAL"

    # A source recovering from a hard failure gets one conservative PARTIAL
    # cycle when the recovery check is merely quiet. This prevents an
    # immediately-clean negative after a failed collection.
    if state == "QUIET" and previous_state in {"FAILED", "STALE"}:
        state = "PARTIAL"

    entry["health_state"] = state
    entry["previous_health_state"] = previous_state
    entry["health_changed"] = bool(
        previous_state and previous_state != state
    )

    # Persist BOTH successful and failed states.
    #
    # The original 6.1.3 implementation only wrote state when status == "OK".
    # Therefore a FAILED run disappeared from persistent state before the next
    # run, making the FAILED -> PARTIAL recovery rule impossible to trigger.
    record: dict[str, str] = {
        "health_state": state,
        "newest_seen": newest_seen,
    }

    last_success = str(previous.get("last_success", ""))
    last_failure = str(previous.get("last_failure", ""))

    if status == "OK":
        record["last_success"] = checked_at
        if last_failure:
            record["last_failure"] = last_failure
    else:
        if last_success:
            record["last_success"] = last_success
        record["last_failure"] = checked_at

    records[source] = record

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"sources": records},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError:
        # Source-health state is advisory and must never crash collection.
        pass

    return entry
