# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for AI Security & Trustworthiness framework trackers."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from security_brief.ai_security_trackers import (
    fetch_mitre_atlas_updates,
    fetch_owasp_llm_top10_updates,
)


class MitreAtlasTrackerTests(unittest.TestCase):
    def test_recent_release_within_cutoff_produces_item(self) -> None:
        cutoff = datetime(2026, 7, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = [
            {
                "tag_name": "v2026.07",
                "published_at": "2026-08-07T00:20:00Z",
                "html_url": "https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.07",
                "body": (
                    "##### Content v2026.07\n\n"
                    "This version of ATLAS data contains 1 matrix, 16 tactics, "
                    "101 techniques, 77 sub-techniques, 37 mitigations, and 68 "
                    "case studies.\n\n###### Techniques\n- Added new techniques"
                ),
            }
        ]
        with patch("security_brief.ai_security_trackers.http_get", return_value=response):
            items = fetch_mitre_atlas_updates(cutoff)
        self.assertEqual(len(items), 1)
        self.assertIn("v2026.07", items[0].title)
        self.assertIn("101 techniques", items[0].summary)
        self.assertEqual(items[0].section, "AI Security and Trustworthiness")

    def test_release_before_cutoff_is_dropped(self) -> None:
        cutoff = datetime(2026, 8, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = [
            {
                "tag_name": "v2026.06",
                "published_at": "2026-06-30T23:20:45Z",
                "html_url": "https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.06",
                "body": "This version of ATLAS data contains 16 tactics.",
            }
        ]
        with patch("security_brief.ai_security_trackers.http_get", return_value=response):
            items = fetch_mitre_atlas_updates(cutoff)
        self.assertEqual(items, [])

    def test_release_missing_tag_is_skipped(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = [{"published_at": "2026-08-07T00:20:00Z", "body": ""}]
        with patch("security_brief.ai_security_trackers.http_get", return_value=response):
            items = fetch_mitre_atlas_updates(cutoff)
        self.assertEqual(items, [])


class OwaspLlmTop10TrackerTests(unittest.TestCase):
    def test_commits_in_window_produce_single_rollup_item(self) -> None:
        cutoff = datetime(2026, 8, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = [
            {"commit": {"author": {"date": "2026-08-15T10:00:00Z"}}},
            {"commit": {"author": {"date": "2026-08-10T09:00:00Z"}}},
        ]
        with patch("security_brief.ai_security_trackers.http_get", return_value=response):
            items = fetch_owasp_llm_top10_updates(cutoff)
        self.assertEqual(len(items), 1)
        self.assertIn("2 change(s)", items[0].title)
        self.assertEqual(items[0].section, "AI Security and Trustworthiness")

    def test_no_commits_returns_empty(self) -> None:
        cutoff = datetime(2026, 8, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = []
        with patch("security_brief.ai_security_trackers.http_get", return_value=response):
            items = fetch_owasp_llm_top10_updates(cutoff)
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
