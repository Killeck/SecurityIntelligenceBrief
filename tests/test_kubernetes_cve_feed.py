# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for the Kubernetes CVE JSON Feed collector."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from security_brief.kubernetes_cve_feed import (
    _extract_cvss_score,
    fetch_kubernetes_cve_feed,
)


def _sample_payload(**overrides) -> dict:
    item = {
        "id": "CVE-2026-3865",
        "summary": "CSI Driver for SMB path traversal via subDir may delete unintended directories",
        "date_published": "2026-04-10T17:54:42Z",
        "external_url": "https://www.cve.org/cverecord?id=CVE-2026-3865",
        "url": "https://github.com/kubernetes/kubernetes/issues/138319",
        "status": "fixed",
        "content_text": "**CVSS Rating:**  \nCVSS:3.1/... — **Medium (6.5)**\n\nA vulnerability was discovered...",
    }
    item.update(overrides)
    return {
        "description": "Auto-refreshing official CVE feed for Kubernetes repository",
        "feed_url": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
        "items": [item],
    }


class CvssScoreExtractionTests(unittest.TestCase):
    def test_extracts_score_from_bold_rating_format(self) -> None:
        text = "**CVSS Rating:**  \nCVSS:3.1/AV:N/... — **Medium (6.5)**\n\nDetails"
        self.assertEqual(_extract_cvss_score(text), 6.5)

    def test_extracts_score_from_score_prefixed_format(self) -> None:
        text = "CVSS Rating: 8.8 (Medium) CVSS:3.1/AV:N/..."
        self.assertEqual(_extract_cvss_score(text), 8.8)

    def test_extracts_score_from_dash_high_format(self) -> None:
        text = "CVSS Rating: CVSS:3.1/AV:N/... - HIGH (8.8)"
        self.assertEqual(_extract_cvss_score(text), 8.8)

    def test_ambiguous_score_before_bare_severity_word_returns_none(self) -> None:
        # "8.8 (Medium)" with no parens around the score itself is
        # deliberately not matched - safer to return None than risk
        # colliding with a CVSS vector's bare version number elsewhere
        # in the same document.
        text = "CVSS Rating: 8.8 - Medium, CVSS:3.1/AV:N/AC:L/..."
        self.assertIsNone(_extract_cvss_score(text))

    def test_no_confident_match_returns_none_not_zero(self) -> None:
        self.assertIsNone(_extract_cvss_score("No CVSS information available here."))


class KubernetesCveFeedFetchTests(unittest.TestCase):
    def test_recent_entry_within_cutoff_produces_item_with_clean_cve_id(self) -> None:
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = _sample_payload()
        with patch("security_brief.kubernetes_cve_feed.http_get", return_value=response):
            items = fetch_kubernetes_cve_feed(cutoff)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].cves, ["CVE-2026-3865"])
        self.assertEqual(items[0].cvss_score, 6.5)
        self.assertEqual(items[0].cvss_severity, "Medium")
        self.assertIn("CVE-2026-3865", items[0].title)
        self.assertEqual(items[0].section, "Cloud and Identity")

    def test_entry_before_cutoff_is_dropped(self) -> None:
        cutoff = datetime(2026, 8, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = _sample_payload()  # dated 2026-04-10
        with patch("security_brief.kubernetes_cve_feed.http_get", return_value=response):
            items = fetch_kubernetes_cve_feed(cutoff)
        self.assertEqual(items, [])

    def test_entry_missing_required_field_is_skipped(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = _sample_payload(id="")
        with patch("security_brief.kubernetes_cve_feed.http_get", return_value=response):
            items = fetch_kubernetes_cve_feed(cutoff)
        self.assertEqual(items, [])

    def test_no_cvss_in_body_yields_not_available_severity_not_a_fabricated_score(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = _sample_payload(content_text="No score published yet.")
        with patch("security_brief.kubernetes_cve_feed.http_get", return_value=response):
            items = fetch_kubernetes_cve_feed(cutoff)
        self.assertEqual(len(items), 1)
        self.assertIsNone(items[0].cvss_score)
        self.assertEqual(items[0].cvss_severity, "Not available")

    def test_multiple_items_all_collected(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        payload = _sample_payload()
        payload["items"].append(
            {
                "id": "CVE-2026-4342",
                "summary": "ingress-nginx comment-based nginx configuration injection",
                "date_published": "2026-03-19T14:32:54Z",
                "external_url": "https://www.cve.org/cverecord?id=CVE-2026-4342",
                "url": "https://github.com/kubernetes/kubernetes/issues/137893",
                "status": "fixed",
                "content_text": "CVSS Rating: 8.8 (Medium) CVSS:3.1/...",
            }
        )
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = payload
        with patch("security_brief.kubernetes_cve_feed.http_get", return_value=response):
            items = fetch_kubernetes_cve_feed(cutoff)
        self.assertEqual(sorted(i.cves[0] for i in items), ["CVE-2026-3865", "CVE-2026-4342"])


if __name__ == "__main__":
    unittest.main()
