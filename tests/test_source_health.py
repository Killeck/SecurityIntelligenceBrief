"""Regression coverage for cross-run source-health truth."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_brief.source_health import assess_and_persist


class SourceHealthTests(unittest.TestCase):
    def tearDown(self) -> None:
        os.environ.pop("SOURCE_HEALTH_STATE_FILE", None)

    def test_old_publication_date_does_not_make_successful_collector_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            old_publication = datetime.now(timezone.utc) - timedelta(days=30)

            result = assess_and_persist(
                {
                    "source": "Low-frequency source",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 1,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "newest_item": old_publication.isoformat(),
                }
            )
            self.assertEqual(result["health_state"], "CONTENT")

            follow_up = assess_and_persist(
                {
                    "source": "Low-frequency source",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "newest_item": "",
                }
            )
            self.assertEqual(follow_up["health_state"], "QUIET")
            self.assertTrue(follow_up["health_changed"])

    def test_publication_cadence_is_separate_from_source_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"

            result = assess_and_persist(
                {
                    "source": "Fast feed",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 1,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "newest_item": (
                        datetime.now(timezone.utc) - timedelta(days=2)
                    ).isoformat(),
                },
                freshness_days=1,
            )

            self.assertEqual(result["health_state"], "CONTENT")

    def test_confirmed_partial_collection_is_not_reported_as_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"

            result = assess_and_persist(
                {
                    "source": "Structured source",
                    "status": "OK",
                    "health_state": "QUIET",
                    "partial": True,
                    "items": 0,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "newest_item": "",
                }
            )

            self.assertEqual(result["health_state"], "PARTIAL")

    def test_hard_failure_is_persisted_for_next_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "health.json"
            os.environ["SOURCE_HEALTH_STATE_FILE"] = str(state_file)
            now = datetime.now(timezone.utc)

            failed = assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                    "checked_at": now.isoformat(),
                    "newest_item": "",
                }
            )

            stored = json.loads(state_file.read_text(encoding="utf-8"))
            record = stored["sources"]["Recovering source"]

            self.assertEqual(failed["health_state"], "FAILED")
            self.assertEqual(record["health_state"], "FAILED")
            self.assertEqual(record["last_failure"], now.isoformat())

    def test_first_quiet_run_after_hard_failure_remains_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            now = datetime.now(timezone.utc)

            assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                    "checked_at": now.isoformat(),
                    "newest_item": "",
                }
            )

            recovered = assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                    "checked_at": (now + timedelta(minutes=5)).isoformat(),
                    "newest_item": "",
                }
            )

            self.assertEqual(recovered["previous_health_state"], "FAILED")
            self.assertEqual(recovered["health_state"], "PARTIAL")

    def test_second_quiet_run_after_failure_returns_to_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            now = datetime.now(timezone.utc)

            assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                    "checked_at": now.isoformat(),
                    "newest_item": "",
                }
            )

            first_recovery = assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                    "checked_at": (now + timedelta(minutes=5)).isoformat(),
                    "newest_item": "",
                }
            )

            second_recovery = assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                    "checked_at": (now + timedelta(minutes=10)).isoformat(),
                    "newest_item": "",
                }
            )

            self.assertEqual(first_recovery["health_state"], "PARTIAL")
            self.assertEqual(
                second_recovery["previous_health_state"],
                "PARTIAL",
            )
            self.assertEqual(second_recovery["health_state"], "QUIET")

    def test_content_recovery_after_failure_immediately_returns_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SOURCE_HEALTH_STATE_FILE"] = f"{directory}/health.json"
            now = datetime.now(timezone.utc)

            assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                    "checked_at": now.isoformat(),
                    "newest_item": "",
                }
            )

            recovered = assess_and_persist(
                {
                    "source": "Recovering source",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 2,
                    "checked_at": (now + timedelta(minutes=5)).isoformat(),
                    "newest_item": (now + timedelta(minutes=4)).isoformat(),
                }
            )

            self.assertEqual(recovered["previous_health_state"], "FAILED")
            self.assertEqual(recovered["health_state"], "CONTENT")


if __name__ == "__main__":
    unittest.main()
