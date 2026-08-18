# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Persistent bounded cache for NVD enrichment responses."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .utils import integer_setting


def nvd_cache_path() -> Path:
    return Path(os.getenv("NVD_CACHE_FILE", ".state/nvd_cache.json"))


class NvdCache:
    """Read and atomically persist CVE payloads with a configurable TTL."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or nvd_cache_path()
        self.ttl = timedelta(
            hours=integer_setting(
                "NVD_CACHE_TTL_HOURS", default=24, minimum=1, maximum=720
            )
        )
        self.entries: dict[str, dict[str, Any]] = {}
        self.dirty = False
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                self.entries = {
                    str(key).upper(): value
                    for key, value in payload.get("entries", {}).items()
                    if isinstance(value, dict)
                }
        except (OSError, ValueError, TypeError):
            self.entries = {}

    def get(self, cve: str, now: datetime | None = None) -> dict[str, Any] | None:
        entry = self.entries.get(cve.upper())
        if not entry:
            return None
        try:
            stored_at = datetime.fromisoformat(str(entry["stored_at"]))
        except (KeyError, TypeError, ValueError):
            return None
        if stored_at.tzinfo is None:
            stored_at = stored_at.replace(tzinfo=timezone.utc)
        if (now or datetime.now(timezone.utc)) - stored_at > self.ttl:
            return None
        payload = entry.get("payload")
        return payload if isinstance(payload, dict) else None

    def put(
        self,
        cve: str,
        payload: dict[str, Any],
        now: datetime | None = None,
    ) -> None:
        self.entries[cve.upper()] = {
            "stored_at": (now or datetime.now(timezone.utc)).isoformat(),
            "payload": payload,
        }
        self.dirty = True

    def persist(self) -> None:
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"entries": self.entries}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)
        self.dirty = False
