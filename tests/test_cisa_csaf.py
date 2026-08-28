# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for the structured CISA CSAF collector."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from security_brief.cisa_csaf import (
    CSAF_BRANCHES,
    _parse_csaf_document,
    fetch_cisa_csaf_branch,
)


def _sample_document(*, cve: str = "CVE-2026-18164", score: float = 8.1) -> dict:
    return {
        "document": {
            "title": "Example Vendor Widget",
            "tracking": {
                "id": "ICSA-26-225-01",
                "initial_release_date": "2026-08-13T06:00:00.000000Z",
                "current_release_date": "2026-08-13T06:00:00.000000Z",
            },
        },
        "vulnerabilities": [
            {
                "cve": cve,
                "scores": [
                    {
                        "cvss_v3": {"baseScore": score, "baseSeverity": "HIGH"},
                        "products": ["CSAFPID-0001"],
                    }
                ],
            }
        ],
    }


class CisaCsafParsingTests(unittest.TestCase):
    def test_parses_cve_cvss_and_branch_label(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        items = _parse_csaf_document(
            _sample_document(),
            path="csaf_files/OT/white/2026/icsa-26-225-01.json",
            source=CSAF_BRANCHES["OT"],
            branch="OT",
            cutoff=cutoff,
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.cves, ["CVE-2026-18164"])
        self.assertEqual(item.cvss_score, 8.1)
        self.assertIn("OT branch", item.summary)
        self.assertIn("ICSA-26-225-01", item.summary)
        self.assertTrue(item.link.endswith("csaf_files/OT/white/2026/icsa-26-225-01.json"))

    def test_high_cvss_is_classified_as_critical_vulnerability(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        items = _parse_csaf_document(
            _sample_document(score=9.4),
            path="x",
            source=CSAF_BRANCHES["OT"],
            branch="OT",
            cutoff=cutoff,
        )
        self.assertEqual(items[0].category, "Critical vulnerability")

    def test_items_before_cutoff_are_dropped(self) -> None:
        cutoff = datetime(2027, 1, 1, tzinfo=timezone.utc)
        items = _parse_csaf_document(
            _sample_document(),
            path="x",
            source=CSAF_BRANCHES["OT"],
            branch="OT",
            cutoff=cutoff,
        )
        self.assertEqual(items, [])

    def test_missing_tracking_id_or_title_is_skipped(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        document = _sample_document()
        document["document"]["tracking"]["id"] = ""
        items = _parse_csaf_document(
            document, path="x", source=CSAF_BRANCHES["OT"], branch="OT", cutoff=cutoff
        )
        self.assertEqual(items, [])

    def test_multiple_vulnerabilities_produce_multiple_items(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        document = _sample_document()
        document["vulnerabilities"].append(
            {
                "cve": "CVE-2026-18165",
                "scores": [{"cvss_v3": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}],
            }
        )
        items = _parse_csaf_document(
            document, path="x", source=CSAF_BRANCHES["OT"], branch="OT", cutoff=cutoff
        )
        self.assertEqual(sorted(i.cves[0] for i in items), ["CVE-2026-18164", "CVE-2026-18165"])


class CisaCsafFetchTests(unittest.TestCase):
    def test_fetch_branch_uses_changed_paths_and_skips_404_raw_files(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)

        raw_response = MagicMock()
        raw_response.status_code = 200
        raw_response.json.return_value = _sample_document()
        raw_response.raise_for_status.return_value = None

        missing_response = MagicMock()
        missing_response.status_code = 404

        def fake_get(url, **kwargs):
            if "raw.githubusercontent.com" in url:
                if url.endswith("missing.json"):
                    return missing_response
                return raw_response
            raise AssertionError(f"Unexpected GET to {url}")

        with patch(
            "security_brief.cisa_csaf._changed_json_paths",
            return_value={
                "csaf_files/OT/white/2026/icsa-26-225-01.json",
                "csaf_files/OT/white/2026/missing.json",
            },
        ), patch("security_brief.cisa_csaf.http_get", side_effect=fake_get):
            items = fetch_cisa_csaf_branch("OT", cutoff)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].cves, ["CVE-2026-18164"])

    def test_rate_limit_error_propagates_rather_than_returning_empty(self) -> None:
        """A 403/rate-limit failure must surface as an error, not a silent

        empty/clean result — an empty list here would be indistinguishable
        from "no new CISA advisories" and would falsely report collector
        health as clean.
        """

        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)

        forbidden_response = MagicMock()
        forbidden_response.status_code = 403
        forbidden_response.raise_for_status.side_effect = Exception("403 rate limited")

        with patch("security_brief.cisa_csaf.http_get", return_value=forbidden_response):
            with self.assertRaises(Exception):
                fetch_cisa_csaf_branch("OT", cutoff)


if __name__ == "__main__":
    unittest.main()
