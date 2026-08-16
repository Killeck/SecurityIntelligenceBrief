"""Private, filesystem-backed report archive and lightweight trend index."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def archive_report(
    *, generated_at: datetime, html_body: str, text_body: str, summary: dict[str, Any]
) -> Path | None:
    """Persist a private report snapshot when archival is enabled.

    The archive is intentionally local-only. Set ``REPORT_ARCHIVE_DIR`` to an
    approved private path; without it, no report content is retained.
    """
    raw_directory = os.getenv("REPORT_ARCHIVE_DIR", "").strip()
    if not raw_directory:
        return None
    directory = Path(raw_directory)
    stamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"daily-{stamp}.html").write_text(html_body, encoding="utf-8")
        (directory / f"daily-{stamp}.txt").write_text(text_body, encoding="utf-8")
        (directory / f"daily-{stamp}.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return directory
    except OSError:
        return None
