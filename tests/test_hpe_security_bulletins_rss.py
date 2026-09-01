# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for the HPE Security Bulletin RSS collector."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from security_brief.hpe_security_bulletins_rss import (
    _extract_cvss,
    fetch_hpe_security_bulletins_rss,
)

_SAMPLE_RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>HPE Security Bulletins</title>
<item>
  <title>HPESBHF04958 - HPE ProLiant DL380 - CVSS 9.8 (Critical)</title>
  <link>https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbhf04958en_us</link>
  <description>A vulnerability rated Critical was found in HPE ProLiant firmware.</description>
  <pubDate>{pubdate}</pubDate>
</item>
<item>
  <title>HPESBNW04957 - Aruba Switch Advisory - Severity: High</title>
  <link>https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us</link>
  <description>No numeric score published, severity word only.</description>
  <pubDate>{pubdate}</pubDate>
</item>
</channel></rss>"""


def _rss(pubdate: str) -> bytes:
    return _SAMPLE_RSS.format(pubdate=pubdate).encode("utf-8")


class CvssExtractionTests(unittest.TestCase):
    def test_extracts_numeric_score_and_severity(self) -> None:
        score, severity = _extract_cvss("HPESBHF04958 - CVSS 9.8 (Critical)")
        self.assertEqual(score, 9.8)
        self.assertEqual(severity, "Critical")

    def test_falls_back_to_bare_severity_word(self) -> None:
        score, severity = _extract_cvss("Aruba Switch Advisory - Severity: High")
        self.assertIsNone(score)
        self.assertEqual(severity, "High")

    def test_no_match_returns_not_available_not_fabricated(self) -> None:
        score, severity = _extract_cvss("Routine maintenance notice, no vulnerability.")
        self.assertIsNone(score)
        self.assertEqual(severity, "Not available")


class HpeRssFetchTests(unittest.TestCase):
    def test_recent_entries_within_cutoff_are_collected(self) -> None:
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.content = _rss("Wed, 27 Aug 2026 10:00:00 GMT")
        with patch("security_brief.hpe_security_bulletins_rss.http_get", return_value=response):
            items = fetch_hpe_security_bulletins_rss(cutoff)
        self.assertEqual(len(items), 2)
        critical = next(i for i in items if "HPESBHF04958" in i.title)
        self.assertEqual(critical.cvss_score, 9.8)
        self.assertEqual(critical.cvss_severity, "Critical")
        high = next(i for i in items if "HPESBNW04957" in i.title)
        self.assertIsNone(high.cvss_score)
        self.assertEqual(high.cvss_severity, "High")

    def test_entries_before_cutoff_are_dropped(self) -> None:
        cutoff = datetime(2026, 12, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.content = _rss("Wed, 27 Aug 2026 10:00:00 GMT")
        with patch("security_brief.hpe_security_bulletins_rss.http_get", return_value=response):
            items = fetch_hpe_security_bulletins_rss(cutoff)
        self.assertEqual(items, [])

    def test_empty_feed_raises_rather_than_silently_returning_ok(self) -> None:
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.content = b'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title></channel></rss>'
        with patch("security_brief.hpe_security_bulletins_rss.http_get", return_value=response):
            with self.assertRaises(RuntimeError):
                fetch_hpe_security_bulletins_rss(cutoff)


if __name__ == "__main__":
    unittest.main()
