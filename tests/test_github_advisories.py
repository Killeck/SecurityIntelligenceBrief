# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for GitHub Advisory Database collection improvements.

Covers Priority 3 MAINTENANCE.md items: pagination, updated_at-based
freshness, package/ecosystem/alias enrichment, withdrawn-advisory
exclusion, and PARTIAL health signalling when pagination is truncated.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from security_brief import collectors
from security_brief.models import PartialItemList, Source


class MockPagedResponse:
    """Minimal requests-compatible response supporting a Link header."""

    def __init__(self, payload, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _advisory(**overrides):
    base = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2026-11111",
        "summary": "Example package vulnerability",
        "description": "A remote code execution vulnerability affects the package.",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "cvss": {"score": 9.8},
        "vulnerabilities": [
            {"package": {"name": "example-pkg", "ecosystem": "pip"}},
        ],
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"},
            {"type": "CVE", "value": "CVE-2026-11111"},
        ],
    }
    base.update(overrides)
    return base


class GhsaUpdatedAtTests(unittest.TestCase):
    def test_updated_at_used_over_stale_published_at(self) -> None:
        """An advisory published long ago but recently updated must still
        surface - published_at alone would incorrectly filter it out."""

        source = Source("GitHub Advisory Database", "GitHub", "https://example.invalid", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        cutoff = now - timedelta(days=2)
        advisory = _advisory(
            published_at="2024-01-01T00:00:00Z",  # old - would fail cutoff alone
            updated_at="2026-08-28T00:00:00Z",  # recent - materially revised
        )
        response = MockPagedResponse([advisory])
        with patch.object(collectors, "http_get", return_value=response):
            items = collectors.fetch_github_advisories(source, cutoff)
        self.assertEqual(len(items), 1)


class GhsaWithdrawnTests(unittest.TestCase):
    def test_withdrawn_advisory_is_excluded(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://example.invalid", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        advisory = _advisory(withdrawn_at="2026-08-15T00:00:00Z")
        response = MockPagedResponse([advisory])
        with patch.object(collectors, "http_get", return_value=response):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=30))
        self.assertEqual(items, [])


class GhsaEnrichmentTests(unittest.TestCase):
    def test_package_ecosystem_appears_in_summary(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://example.invalid", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        advisory = _advisory(
            updated_at=now.isoformat(),
            vulnerabilities=[{"package": {"name": "lodash", "ecosystem": "npm"}}],
        )
        response = MockPagedResponse([advisory])
        with patch.object(collectors, "http_get", return_value=response):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=1))
        self.assertIn("lodash (npm)", items[0].summary)

    def test_cve_alias_from_identifiers_is_included(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://example.invalid", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        # cve_id omitted entirely - only discoverable via identifiers
        advisory = _advisory(cve_id=None, updated_at=now.isoformat())
        response = MockPagedResponse([advisory])
        with patch.object(collectors, "http_get", return_value=response):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=1))
        self.assertIn("CVE-2026-11111", items[0].cves)


class GhsaPaginationTests(unittest.TestCase):
    def test_follows_link_header_across_pages(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://api.github.com/advisories", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        page1 = MockPagedResponse(
            [_advisory(ghsa_id="GHSA-page1", cve_id="CVE-2026-00001", updated_at=now.isoformat())],
            headers={"Link": '<https://api.github.com/advisories?page=2>; rel="next"'},
        )
        page2 = MockPagedResponse(
            [_advisory(ghsa_id="GHSA-page2", cve_id="CVE-2026-00002", updated_at=now.isoformat())],
            headers={},  # no further pages
        )
        with patch.object(collectors, "http_get", side_effect=[page1, page2]):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=1))
        self.assertEqual(sorted(i.cves[0] for i in items), ["CVE-2026-00001", "CVE-2026-00002"])

    def test_truncation_at_page_bound_returns_partial_item_list(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://api.github.com/advisories", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)

        def _page(n):
            return MockPagedResponse(
                [_advisory(ghsa_id=f"GHSA-p{n}", cve_id=f"CVE-2026-{n:05d}", updated_at=now.isoformat())],
                headers={"Link": f'<https://api.github.com/advisories?page={n + 1}>; rel="next"'},
            )

        # 11 pages always claiming a "next" link - exceeds the 10-page bound
        responses = [_page(n) for n in range(1, 12)]
        with patch.object(collectors, "http_get", side_effect=responses):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=1))
        self.assertIsInstance(items, PartialItemList)
        self.assertEqual(len(items), 10)  # fetched exactly the bound, not 11

    def test_no_next_link_is_not_marked_partial(self) -> None:
        source = Source("GitHub Advisory Database", "GitHub", "https://api.github.com/advisories", "github_advisories", 20, "Vulnerability Research")
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        response = MockPagedResponse(
            [_advisory(updated_at=now.isoformat())], headers={}
        )
        with patch.object(collectors, "http_get", return_value=response):
            items = collectors.fetch_github_advisories(source, now - timedelta(days=1))
        self.assertNotIsInstance(items, PartialItemList)


if __name__ == "__main__":
    unittest.main()
