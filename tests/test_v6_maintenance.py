# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for the 6.0.0 maintenance boundaries.

The component checks ensure Overall Threat remains singular and the restored
Enterprise DEFCON guide remains text-only.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_brief.analysis import deduplicate
from security_brief.dedup_state import suppress_recent_duplicates
from security_brief.models import Item, Source
from security_brief.nvd_cache import NvdCache
from security_brief.rendering_components import (
    render_defcon_text_guide,
    render_overall_threat_status,
)
from security_brief.config import DEFCON_LEVELS
from security_brief.runtime_profile import RuntimeProfiler
from security_brief.source_config import configure_sources, load_source_overrides


def sample_item(**changes: object) -> Item:
    item = Item(
        title="Example remote code execution vulnerability",
        summary="An unauthenticated attacker can execute arbitrary code.",
        link="https://example.invalid/CVE-2026-12345",
        published=datetime(2026, 8, 18, tzinfo=timezone.utc),
        source="Vendor Security Advisory",
        vendor="Example",
        section="Other Vendor Advisories",
        category="Vulnerability",
        score=50,
        cves=["CVE-2026-12345"],
        action="Patch affected systems.",
    )
    return replace(item, **changes)


class VersionSixMaintenanceTests(unittest.TestCase):
    def test_runtime_profiler_persists_stage_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            profiler = RuntimeProfiler("test", path)
            with profiler.stage("collection"):
                pass
            profile = profiler.persist()
            stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(profile["pipeline"], "test")
        self.assertIn("collection", stored["stages"])

    def test_nvd_cache_persists_and_expires_entries(self) -> None:
        now = datetime(2026, 8, 18, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nvd.json"
            cache = NvdCache(path)
            cache.put("CVE-2026-12345", {"vulnerabilities": []}, now=now)
            cache.persist()
            restored = NvdCache(path)
            self.assertIsNotNone(restored.get("CVE-2026-12345", now=now))
            self.assertIsNone(
                restored.get("CVE-2026-12345", now=now + timedelta(days=2))
            )

    def test_persistent_dedup_keeps_material_changes(self) -> None:
        now = datetime(2026, 8, 18, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedup.json"
            first, suppressed = suppress_recent_duplicates(
                [sample_item()], now=now, path=path
            )
            repeated, repeated_count = suppress_recent_duplicates(
                [sample_item()], now=now + timedelta(hours=1), path=path
            )
            changed, changed_count = suppress_recent_duplicates(
                [sample_item(exploited=True)],
                now=now + timedelta(hours=2),
                path=path,
            )
        self.assertEqual((len(first), suppressed), (1, 0))
        self.assertEqual((len(repeated), repeated_count), (0, 1))
        self.assertEqual((len(changed), changed_count), (1, 0))

    def test_source_overrides_update_and_disable_definitions(self) -> None:
        sources = (
            Source("One", "Vendor", "https://one.invalid", "rss", 10, "News"),
            Source("Two", "Vendor", "https://two.invalid", "rss", 10, "News"),
        )
        configured = configure_sources(
            sources,
            {"One": {"base_score": 25}, "Two": {"enabled": False}},
        )
        self.assertEqual([(value.name, value.base_score) for value in configured], [("One", 25)])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            path.write_text('{"sources":{"One":{"enabled":false}}}', encoding="utf-8")
            self.assertFalse(load_source_overrides(path)["One"]["enabled"])

    def test_deduplication_exposes_corroboration_and_confidence(self) -> None:
        primary = sample_item(source="Vendor Security Advisory", score=50)
        corroborating = sample_item(source="Independent Research", score=40)
        result = deduplicate([primary, corroborating])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].corroboration_count, 2)
        self.assertEqual(
            result[0].corroborating_sources,
            ("Independent Research", "Vendor Security Advisory"),
        )
        self.assertEqual(result[0].confidence, "Authoritative + corroborated")

    def test_overall_threat_status_is_a_single_component(self) -> None:
        rendered = render_overall_threat_status(
            level=3,
            label="Elevated",
            colour="#F9A825",
            text_colour="#111111",
            border_colour="#0D4650",
        )
        self.assertIn("Overall Threat", rendered)
        self.assertIn("3 — Elevated", rendered)
        self.assertNotIn("DEFCON 1", rendered)
        self.assertEqual(rendered.count('width="100%"'), 2)

    def test_defcon_guide_is_text_only(self) -> None:
        rendered = render_defcon_text_guide(
            current_level=3,
            definitions=DEFCON_LEVELS,
            text_colour="#EEF3F8",
            muted_colour="#9CB6BA",
        )
        self.assertIn("Current DEFCON 3 — Elevated", rendered)
        self.assertIn("DEFCON 1 Critical", rendered)
        self.assertIn("DEFCON 5 Low", rendered)
        self.assertNotIn("<table", rendered)
        self.assertNotIn("background:", rendered)


if __name__ == "__main__":
    unittest.main()
