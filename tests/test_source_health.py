"""Regression coverage for cross-run source-health truth."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from security_brief.source_health import assess_and_persist


class SourceHealthTests(unittest.TestCase):
    def test_stale_success_is_not_reported_as_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_file = f"{directory}/health.json"
            previous = datetime.now(timezone.utc) - timedelta(days=30)
            os.environ["SOURCE_HEALTH_STATE_FILE"] = state_file
            result = assess_and_persist({"source": "Example", "status": "OK", "health_state": "CONTENT", "items": 1, "checked_at": datetime.now(timezone.utc).isoformat(), "newest_item": previous.isoformat()})
            self.assertEqual(result["health_state"], "STALE")
            follow_up = assess_and_persist({"source": "Example", "status": "OK", "health_state": "QUIET", "items": 0, "checked_at": datetime.now(timezone.utc).isoformat(), "newest_item": ""})
            self.assertEqual(follow_up["health_state"], "STALE")
            self.assertFalse(follow_up["health_changed"])
        os.environ.pop("SOURCE_HEALTH_STATE_FILE", None)

    def test_source_specific_freshness_threshold_is_honoured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            result = assess_and_persist({"source": "Fast feed", "status": "OK", "health_state": "CONTENT", "items": 1, "checked_at": datetime.now(timezone.utc).isoformat(), "newest_item": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()}, freshness_days=1)
            self.assertEqual(result["health_state"], "STALE")
        os.environ.pop("SOURCE_HEALTH_STATE_FILE", None)

    def test_confirmed_partial_collection_is_not_reported_as_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            result = assess_and_persist({
                "source": "Structured source",
                "status": "OK",
                "health_state": "QUIET",
                "partial": True,
                "items": 0,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "newest_item": "",
            })
            self.assertEqual(result["health_state"], "PARTIAL")
        os.environ.pop("SOURCE_HEALTH_STATE_FILE", None)
