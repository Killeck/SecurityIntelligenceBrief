# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for the 6.x maintenance boundaries."""

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
from security_brief.rendering_components import render_overall_threat_status
from security_brief.runtime_profile import RuntimeProfiler
from security_brief.source_config import configure_sources, load_source_overrides
from security_brief.vendor_coverage import VENDOR_COVERAGE, coverage_for


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
            self.assertIsNone(restored.get("CVE-2026-12345", now=now + timedelta(days=2)))

    def test_persistent_dedup_keeps_material_changes(self) -> None:
        now = datetime(2026, 8, 18, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedup.json"
            first, suppressed = suppress_recent_duplicates([sample_item()], now=now, path=path)
            repeated, repeated_count = suppress_recent_duplicates([sample_item()], now=now + timedelta(hours=1), path=path)
            changed, changed_count = suppress_recent_duplicates([sample_item(exploited=True)], now=now + timedelta(hours=2), path=path)
        self.assertEqual((len(first), suppressed), (1, 0))
        self.assertEqual((len(repeated), repeated_count), (0, 1))
        self.assertEqual((len(changed), changed_count), (1, 0))

    def test_source_overrides_update_and_disable_definitions(self) -> None:
        sources = (
            Source("One", "Vendor", "https://one.invalid", "rss", 10, "News"),
            Source("Two", "Vendor", "https://two.invalid", "rss", 10, "News"),
        )
        configured = configure_sources(sources, {"One": {"base_score": 25}, "Two": {"enabled": False}})
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
        self.assertEqual(result[0].corroborating_sources, ("Independent Research", "Vendor Security Advisory"))
        self.assertEqual(result[0].confidence, "Authoritative + corroborated")

    def test_overall_threat_status_restores_text_only_defcon_legend(self) -> None:
        rendered = render_overall_threat_status(
            level=3,
            label="Elevated",
            colour="#F9A825",
            text_colour="#111111",
            border_colour="#0D4650",
        )
        self.assertIn("Overall Threat", rendered)
        self.assertIn("3 — Elevated", rendered)
        for level in range(1, 6):
            self.assertIn(f"DEFCON {level}", rendered)
        self.assertIn("Immediate action for exceptional verified threat.", rendered)
        self.assertIn("Urgent action for relevant active exploitation.", rendered)
        self.assertIn("Increased risk requiring enhanced attention. (current level)", rendered)
        self.assertIn("Meaningful developments; no direct exposure.", rendered)
        self.assertIn("Routine activity and normal monitoring.", rendered)
        self.assertIn('width="20%" valign="bottom"', rendered)
        self.assertIn('width="80%" align="right" valign="bottom"', rendered)
        self.assertIn('width="400"', rendered)
        self.assertIn("max-width:400px", rendered)
        self.assertNotIn("Enterprise DEFCON Legend", rendered)
        self.assertEqual(rendered.count("Overall Threat"), 2)
        self.assertEqual(rendered.count(" (current level)"), 1)

    def test_vendor_coverage_keeps_crowdstrike_supporting_only_and_splits_hpe_aruba(self) -> None:
        crowdstrike = coverage_for("CrowdStrike")
        self.assertIsNotNone(crowdstrike)
        self.assertFalse(crowdstrike.has_public_authoritative_path)
        self.assertIn("CrowdStrike Blog", crowdstrike.supporting_sources)
        self.assertEqual(len(VENDOR_COVERAGE), 11)
        self.assertIsNotNone(coverage_for("HPE"))
        self.assertIsNotNone(coverage_for("Aruba"))
        self.assertIsNone(coverage_for("HPE / Aruba"))


if __name__ == "__main__":
    unittest.main()
