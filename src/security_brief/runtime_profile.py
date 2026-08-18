# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Low-overhead stage profiling for daily and weekly pipeline runs."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Iterator


def runtime_profile_path() -> Path:
    return Path(os.getenv("RUNTIME_PROFILE_FILE", ".state/runtime_profile.json"))


class RuntimeProfiler:
    """Record named pipeline-stage durations and persist the latest profile."""

    def __init__(self, pipeline: str, path: Path | None = None) -> None:
        self.pipeline = pipeline
        self.path = path or runtime_profile_path()
        self.started = perf_counter()
        self.stages: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = perf_counter()
        try:
            yield
        finally:
            duration = perf_counter() - started
            self.stages[name] = round(duration, 3)
            print(f"Runtime stage {name}: {duration:.3f}s")

    def persist(self) -> dict[str, object]:
        profile: dict[str, object] = {
            "pipeline": self.pipeline,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_seconds": round(perf_counter() - self.started, 3),
            "stages": self.stages,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(profile, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)
        return profile
