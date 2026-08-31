# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for previously-untested custom/resilient adapters.

Addresses the Priority 3 MAINTENANCE.md item: "Add source-specific fixture
tests for every custom/resilient adapter." Three functions had zero
dedicated test coverage prior to this file: fetch_resilient_html,
fetch_authoritative_vendor_rss, fetch_priority_vendor_nvd.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from security_brief.models import Item, Source
from security_brief.priority_vendor_sources import (
    fetch_authoritative_vendor_rss,
    fetch_priority_vendor_nvd,
)
from security_brief.source_resilience import fetch_resilient_html


class MockHtmlResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


_SEMANTIC_HTML = """
<html><body><main>
<article><h2><a href="https://example.invalid/news/one">First Article</a></h2></article>
</main></body></html>
"""

_WEBFLOW_STYLE_HTML = """
<html><body>
<div class="blog-item"><a href="https://example.invalid/news/two" class="card">
<div class="title">Second Article</div></a></div>
</body></html>
"""

_NO_LINKS_HTML = "<html><body><p>Nothing to see here.</p></body></html>"


def _resilient_source(**overrides) -> Source:
    base = dict(
        name="Test Resilient Source",
        vendor="Test",
        url="https://example.invalid/news",
        source_type="html",
        base_score=20,
        section="Threat Intelligence",
        selectors=("main h2 a[href]",),
        include_patterns=("example.invalid/news",),
        max_candidates=20,
    )
    base.update(overrides)
    return Source(**base)


class FetchResilientHtmlTests(unittest.TestCase):
    def test_tier1_success_does_not_invoke_fallback_tiers(self) -> None:
        """When the primary selector works, no fallback fetch should occur -
        verified by only ever mocking a single response."""

        source = _resilient_source()
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        with patch(
            "security_brief.source_resilience.fetch_html"
        ) as mock_fetch:
            mock_fetch.return_value = [MagicMock(spec=Item)]
            result = fetch_resilient_html(source, cutoff)
        self.assertEqual(mock_fetch.call_count, 1)
        self.assertEqual(len(result), 1)

    def test_tier1_selector_failure_falls_back_to_tier2(self) -> None:
        source = _resilient_source()
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        tier1_error = RuntimeError("Selector health check found no usable article candidates")
        with patch(
            "security_brief.source_resilience.fetch_html",
            side_effect=[tier1_error, [MagicMock(spec=Item)]],
        ) as mock_fetch:
            result = fetch_resilient_html(source, cutoff)
        self.assertEqual(mock_fetch.call_count, 2)
        self.assertEqual(len(result), 1)
        # tier2 call used the broader semantic-tag selector set
        tier2_source = mock_fetch.call_args_list[1][0][0]
        self.assertIn("article a[href]", tier2_source.selectors)

    def test_tier1_and_tier2_both_fail_falls_back_to_tier3_structure_agnostic(self) -> None:
        """This is the case the original Nozomi Blog bug hit: a Webflow-style
        site where even the semantic-tag fallback (tier2) cannot find
        candidates, requiring the fully structure-agnostic a[href] tier."""

        source = _resilient_source()
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        selector_error = RuntimeError("Selector health check found no usable article candidates")
        with patch(
            "security_brief.source_resilience.fetch_html",
            side_effect=[selector_error, selector_error, [MagicMock(spec=Item)]],
        ) as mock_fetch:
            result = fetch_resilient_html(source, cutoff)
        self.assertEqual(mock_fetch.call_count, 3)
        self.assertEqual(len(result), 1)
        tier3_source = mock_fetch.call_args_list[2][0][0]
        self.assertEqual(tier3_source.selectors, ("a[href]",))

    def test_non_selector_error_propagates_without_any_fallback(self) -> None:
        """A network/HTTP failure is not a selector problem - must not
        trigger fallback tiers, and must propagate to mark the source
        FAILED rather than silently retrying with different selectors."""

        source = _resilient_source()
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        network_error = RuntimeError("HTTP 503")
        with patch(
            "security_brief.source_resilience.fetch_html",
            side_effect=network_error,
        ) as mock_fetch:
            with self.assertRaises(RuntimeError):
                fetch_resilient_html(source, cutoff)
        self.assertEqual(mock_fetch.call_count, 1)


class FetchAuthoritativeVendorRssTests(unittest.TestCase):
    def test_applies_explicit_feed_cvss_to_each_item(self) -> None:
        source = Source(
            name="Test Vendor PSIRT",
            vendor="Test Vendor",
            url="https://example.invalid/rss.xml",
            source_type="rss",
            base_score=30,
            section="Other Vendor Advisories",
        )
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        item = Item(
            title="CVE-2026-1: Example",
            summary="A critical CVSS 9.8 vulnerability was disclosed.",
            link="https://example.invalid/advisory/1",
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source="Test Vendor PSIRT",
            vendor="Test Vendor",
            section="Other Vendor Advisories",
            category="Vendor advisory",
            score=10,
        )
        with patch(
            "security_brief.priority_vendor_sources.fetch_rss",
            return_value=[item],
        ):
            items = fetch_authoritative_vendor_rss(source, cutoff)
        self.assertEqual(len(items), 1)
        # _apply_explicit_feed_cvss should have picked up the inline 9.8
        self.assertEqual(items[0].cvss_score, 9.8)

    def test_empty_feed_returns_empty_list_not_error(self) -> None:
        source = Source(
            name="Test Vendor PSIRT",
            vendor="Test Vendor",
            url="https://example.invalid/rss.xml",
            source_type="rss",
            base_score=30,
            section="Other Vendor Advisories",
        )
        cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
        with patch(
            "security_brief.priority_vendor_sources.fetch_rss",
            return_value=[],
        ):
            items = fetch_authoritative_vendor_rss(source, cutoff)
        self.assertEqual(items, [])


class FetchPriorityVendorNvdTests(unittest.TestCase):
    def _response(self, vulnerabilities: list[dict]) -> MagicMock:
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"vulnerabilities": vulnerabilities}
        return response

    def test_matched_priority_vendor_produces_item_with_correct_section(self) -> None:
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        cutoff = now - timedelta(days=2)
        payload = [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "published": now.isoformat(),
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A vulnerability in Fortinet FortiOS allows remote attackers to bypass authentication.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                        ]
                    },
                }
            }
        ]
        with patch(
            "security_brief.priority_vendor_sources.http_get",
            return_value=self._response(payload),
        ):
            items = fetch_priority_vendor_nvd(cutoff)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].vendor, "Fortinet")
        self.assertEqual(items[0].cves, ["CVE-2026-9999"])
        self.assertEqual(items[0].category, "Critical vulnerability")

    def test_unmatched_vendor_description_is_excluded(self) -> None:
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        cutoff = now - timedelta(days=2)
        payload = [
            {
                "cve": {
                    "id": "CVE-2026-8888",
                    "published": now.isoformat(),
                    "descriptions": [
                        {"lang": "en", "value": "A generic vulnerability in an unrelated hobbyist project."}
                    ],
                }
            }
        ]
        with patch(
            "security_brief.priority_vendor_sources.http_get",
            return_value=self._response(payload),
        ):
            items = fetch_priority_vendor_nvd(cutoff)
        self.assertEqual(items, [])

    def test_missing_description_is_skipped_not_crashed(self) -> None:
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        cutoff = now - timedelta(days=2)
        payload = [{"cve": {"id": "CVE-2026-7777", "published": now.isoformat(), "descriptions": []}}]
        with patch(
            "security_brief.priority_vendor_sources.http_get",
            return_value=self._response(payload),
        ):
            items = fetch_priority_vendor_nvd(cutoff)
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
