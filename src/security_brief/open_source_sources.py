# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Open, structured corroboration sources kept separate from vendor advisories."""

from __future__ import annotations

from .config import GITHUB_ADVISORIES_API
from .models import Source


OPEN_VULNERABILITY_SOURCES = (
    Source(
        name="GitHub Advisory Database",
        vendor="GitHub",
        url=GITHUB_ADVISORIES_API,
        source_type="github_advisories",
        base_score=20,
        section="Vulnerability Research",
        freshness_days=2,
    ),
)
