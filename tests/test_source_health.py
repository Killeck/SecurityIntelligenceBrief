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
