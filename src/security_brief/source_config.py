# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Configuration overlay for frequently changed intelligence source settings."""

from __future__ import annotations

import json
import os
from dataclasses import fields, replace
from pathlib import Path
from typing import Any, Iterable

from .models import Source


def source_definitions_path() -> Path:
    return Path(os.getenv("SOURCE_DEFINITIONS_FILE", "config/sources.json"))


def load_source_overrides(path: Path | None = None) -> dict[str, dict[str, Any]]:
    target = path or source_definitions_path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError(f"Invalid source definitions file: {target}") from error
    sources = payload.get("sources", {}) if isinstance(payload, dict) else {}
    if not isinstance(sources, dict):
        raise RuntimeError(f"Invalid sources mapping in {target}")
    return {
        str(name): value
        for name, value in sources.items()
        if isinstance(value, dict)
    }


def configure_sources(
    sources: Iterable[Source],
    overrides: dict[str, dict[str, Any]],
) -> tuple[Source, ...]:
    """Apply validated field overlays and optional disable flags."""

    allowed = {field.name for field in fields(Source)} - {"name"}
    configured: list[Source] = []
    for source in sources:
        values = overrides.get(source.name, {})
        if values.get("enabled") is False:
            continue
        unexpected = set(values) - allowed - {"enabled"}
        if unexpected:
            raise RuntimeError(
                f"Unsupported source setting(s) for {source.name}: "
                + ", ".join(sorted(unexpected))
            )
        changes = {key: value for key, value in values.items() if key in allowed}
        for tuple_field in (
            "selectors",
            "include_patterns",
            "exclude_patterns",
            "topic_keywords",
        ):
            if tuple_field in changes:
                changes[tuple_field] = tuple(changes[tuple_field])
        configured.append(replace(source, **changes))
    return tuple(configured)


def configure_mapping_sources(
    sources: Iterable[dict[str, Any]],
    overrides: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Apply overlays to dictionary-backed discovery source definitions."""

    configured: list[dict[str, Any]] = []
    for source in sources:
        name = str(source["name"])
        values = overrides.get(name, {})
        if values.get("enabled") is False:
            continue
        merged = dict(source)
        merged.update({key: value for key, value in values.items() if key != "enabled"})
        for tuple_field in (
            "selectors",
            "allowed_hosts",
            "include",
            "exclude",
        ):
            if tuple_field in merged:
                merged[tuple_field] = tuple(merged[tuple_field])
        configured.append(merged)
    return tuple(configured)
