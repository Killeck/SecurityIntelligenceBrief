# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Focused regression coverage for the 6.1.3 intelligence-quality release."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from security_brief.models import Item
from security_brief.analysis import build_sector_impacts, classify, executive_news_relevance, route_section
from security_brief.models import Source
from security_brief.pipeline_state import effective_daily_cutoff, mark_daily_success
from security_brief.report_policy import (
    _normalise_tldr,
    render_watch_next,
    vendor_statuses,
)
from security_brief.source_config import load_source_overrides
from security_brief.source_health import assess_and_persist
from security_brief.source_resilience import fetch_claroty_team82_disclosures
from security_brief.threat_activity import merge_activity


def item(**changes: object) -> Item:
    value = Item(
        title="CVE-2026-12345 — Example security issue",
        summary="An unauthenticated remote attacker can execute code.",
        link="https://example.invalid/advisory",
        published=datetime(2026, 8, 20, 8, 0, tzinfo=timezone.utc),
        source="Palo Alto Networks Security Advisories",
        vendor="Palo Alto Networks",
        section="Other Vendor Advisories",
        category="Critical vulnerability",
        score=70,
        cves=["CVE-2026-12345"],
        cvss_score=9.1,
        cvss_severity="CRITICAL",
        affected="PAN-OS internet-facing gateways.",
        action="Patch or mitigate affected gateways.",
        why="Remote exploitation can affect perimeter security controls.",
    )
    for name, changed in changes.items():
        setattr(value, name, changed)
    return value


class IntelligenceQuality613Tests(unittest.TestCase):
    def test_failed_daily_run_expands_next_collection_window(self) -> None:
        now = datetime(2026, 8, 21, 6, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipeline.json"
            mark_daily_success(now - timedelta(hours=50), path=path)
            cutoff = effective_daily_cutoff(now, 36, path=path)
        self.assertEqual(cutoff, now - timedelta(hours=56))

    def test_recent_success_keeps_normal_daily_window(self) -> None:
        now = datetime(2026, 8, 21, 6, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipeline.json"
            mark_daily_success(now - timedelta(hours=20), path=path)
            cutoff = effective_daily_cutoff(now, 36, path=path)
        self.assertEqual(cutoff, now - timedelta(hours=36))

    def test_quiet_source_is_not_stale_only_because_previous_content_is_old(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source_health.json"
            path.write_text(
                json.dumps(
                    {
                        "sources": {
                            "FBI Cyber News": {
                                "last_success": (now - timedelta(days=1)).isoformat(),
                                "newest_seen": (now - timedelta(days=45)).isoformat(),
                                "health_state": "CONTENT",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"SOURCE_HEALTH_STATE_FILE": str(path)}):
                result = assess_and_persist(
                    {
                        "source": "FBI Cyber News",
                        "status": "OK",
                        "health_state": "QUIET",
                        "items": 0,
                        "checked_at": now.isoformat(),
                        "newest_item": "",
                    },
                    freshness_days=14,
                )
        self.assertEqual(result["health_state"], "QUIET")

    def test_tldr_normalisation_removes_markdown_and_hash_artifacts(self) -> None:
        sample = item()
        with patch(
            "security_brief.report_policy.base._short_tldr",
            return_value="### **Critical** [remote code execution](https://example.invalid) ## affecting gateways...",
        ):
            cleaned = _normalise_tldr(sample)
        self.assertNotIn("#", cleaned)
        self.assertNotIn("**", cleaned)
        self.assertNotIn("](", cleaned)
        self.assertIn("remote code execution", cleaned)

    def test_vendor_status_shows_latest_material_context_instead_of_no_material_update(self) -> None:
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        previous = item(published=now - timedelta(days=5))
        statuses = vendor_statuses(
            [previous],
            [
                {
                    "source": "Palo Alto Networks Security Advisories",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 1,
                }
            ],
            lookback_hours=36,
            now=now,
        )
        palo_alto = next(value for value in statuses if value.label == "Palo Alto")
        self.assertIn("No new priority advisory in reporting window", palo_alto.status)
        self.assertIn("CVE-2026-12345", palo_alto.status)
        self.assertIn("5 day(s) ago", palo_alto.status)
        self.assertNotIn("no material update", palo_alto.status.lower())

    def test_hpe_and_aruba_have_separate_vendor_status_cards(self) -> None:
        statuses = vendor_statuses(
            [],
            [
                {
                    "source": "HPE Security Bulletin Library",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                }
            ],
            lookback_hours=36,
        )
        labels = {value.label for value in statuses}
        self.assertIn("HPE", labels)
        self.assertIn("Aruba", labels)
        self.assertNotIn("HPE / Aruba", labels)

    def test_threat_activity_older_mentions_do_not_reset_last_seen(self) -> None:
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threat.json"
            merge_activity(
                [
                    {
                        "key": "actor one",
                        "label": "Actor One",
                        "activity": "Targeted exploitation confirmed.",
                        "last_seen": (now - timedelta(days=2)).isoformat(),
                        "confidence": "High",
                        "source": "Primary Research",
                        "link": "https://example.invalid/new",
                    }
                ],
                now=now,
                path=path,
            )
            result = merge_activity(
                [
                    {
                        "key": "actor one",
                        "label": "Actor One",
                        "activity": "Older retrospective mention.",
                        "last_seen": (now - timedelta(days=20)).isoformat(),
                        "confidence": "Medium",
                        "source": "News",
                        "link": "https://example.invalid/old",
                    }
                ],
                now=now,
                path=path,
            )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["activity"], "Targeted exploitation confirmed.")
        self.assertEqual(result[0]["source"], "Primary Research")

    def test_nordic_relevance_is_sticky_across_later_non_nordic_updates(self) -> None:
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threat.json"
            merge_activity(
                [
                    {
                        "key": "actor two",
                        "label": "Actor Two",
                        "activity": "Confirmed targeting of a Norwegian energy operator.",
                        "last_seen": (now - timedelta(days=5)).isoformat(),
                        "confidence": "High",
                        "source": "Primary Research",
                        "link": "https://example.invalid/nordic",
                        "nordic_relevant": True,
                    }
                ],
                now=now,
                path=path,
            )
            result = merge_activity(
                [
                    {
                        "key": "actor two",
                        "label": "Actor Two",
                        "activity": "Broader campaign update, no region named.",
                        "last_seen": now.isoformat(),
                        "confidence": "High",
                        "source": "Primary Research",
                        "link": "https://example.invalid/global",
                        "nordic_relevant": False,
                    }
                ],
                now=now,
                path=path,
            )
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["nordic_relevant"])

    def test_nordic_relevant_entries_sort_before_more_recent_global_entries(self) -> None:
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threat.json"
            result = merge_activity(
                [
                    {
                        "key": "global actor",
                        "label": "Global Actor",
                        "activity": "Most recent, no Nordic mention.",
                        "last_seen": now.isoformat(),
                        "confidence": "High",
                        "source": "Primary Research",
                        "link": "https://example.invalid/global",
                        "nordic_relevant": False,
                    },
                    {
                        "key": "nordic actor",
                        "label": "Nordic Actor",
                        "activity": "Older, targets a Swedish financial institution.",
                        "last_seen": (now - timedelta(days=10)).isoformat(),
                        "confidence": "High",
                        "source": "Primary Research",
                        "link": "https://example.invalid/nordic",
                        "nordic_relevant": True,
                    },
                ],
                now=now,
                path=path,
            )
        self.assertEqual([value["label"] for value in result], ["Nordic Actor", "Global Actor"])

    def test_watch_next_uses_decision_oriented_24_72_structure(self) -> None:
        html = render_watch_next([item(exploited=True)], [], limit=4)
        self.assertIn("Next 24h — action & verification", html)
        for heading in (
            "Development:",
            "Evidence:",
            "Enterprise relevance:",
            "Sector relevance:",
            "What to watch next:",
            "Recommended action:",
        ):
            self.assertIn(heading, html)

    def test_bankinfosecurity_uses_first_party_rss_override(self) -> None:
        overrides = load_source_overrides(Path("config/sources.json"))
        bank = overrides["BankInfoSecurity"]
        self.assertEqual(
            bank["url"],
            "https://www.bankinfosecurity.com/rssFeeds.php?type=main",
        )

    def test_claroty_disclosure_dashboard_parser_extracts_cve_vendor_product(self) -> None:
        payload = """
        <html><body><table><tr>
          <td>08-20-2026</td>
          <td><a href="/team82/disclosure/CVE-2026-55555">CVE-2026-55555</a></td>
          <td>Siemens</td><td>S7 Controller</td>
        </tr></table></body></html>
        """

        class Response:
            text = payload

            @staticmethod
            def raise_for_status() -> None:
                return None

        with patch("security_brief.source_resilience.http_get", return_value=Response()):
            values = fetch_claroty_team82_disclosures(
                datetime(2026, 8, 19, tzinfo=timezone.utc)
            )
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0].cves, ["CVE-2026-55555"])
        self.assertEqual(values[0].vendor, "Siemens")
        self.assertIn("S7 Controller", values[0].affected)

    def test_aruba_advisory_does_not_duplicate_into_generic_hpe_card(self) -> None:
        aruba = item(
            vendor="HPE",
            title="CVE-2026-44444 — HPE Aruba Networking AOS-CX",
            summary="A vulnerability affects Aruba AOS-CX switches.",
            affected="HPE Aruba Networking AOS-CX",
            cves=["CVE-2026-44444"],
            cvss_score=8.8,
            published=datetime(2026, 8, 21, 8, 0, tzinfo=timezone.utc),
        )
        statuses = vendor_statuses(
            [aruba],
            [
                {
                    "source": "HPE Security Bulletin Library",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 1,
                }
            ],
            lookback_hours=36,
            now=datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        )
        hpe = next(value for value in statuses if value.label == "HPE")
        aruba_status = next(value for value in statuses if value.label == "Aruba")
        self.assertEqual(hpe.count, 0)
        self.assertEqual(aruba_status.count, 1)


class AiUsedOrAbusedRoutingTests(unittest.TestCase):
    def test_ai_used_as_attack_tool_routes_to_ai_security_section(self) -> None:
        generic_source = Source(
            name="Generic News",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        combined = (
            "Criminals used a deepfake voice clone to impersonate a CFO in an "
            "ai-powered scam targeting a European bank."
        )
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "AI Security and Trustworthiness",
        )

    def test_ai_used_defensively_also_routes_to_ai_security_section(self) -> None:
        generic_source = Source(
            name="Generic News",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="SOC and Detection Engineering",
        )
        combined = "The SOC deployed ai-powered detection to triage the incident faster."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "AI Security and Trustworthiness",
        )

    def test_unrelated_content_keeps_source_default_section(self) -> None:
        generic_source = Source(
            name="Generic News",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        combined = "A ransomware group claimed a new victim on its leak site."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "Threat Intelligence",
        )


class AiSecurityCategoryTests(unittest.TestCase):
    def test_ai_content_gets_dedicated_category_not_general_security(self) -> None:
        generic_source = Source(
            name="Generic News",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        text = "Attackers used a deepfake voice clone in an ai-powered scam against a bank."
        category, weight = classify(text, generic_source)
        self.assertEqual(category, "AI security and abuse")
        self.assertGreater(weight, 0)

    def test_active_exploitation_still_takes_precedence_over_ai_labeling(self) -> None:
        """Operational urgency (active exploitation) must not be masked by
        topical AI labeling - exploitation-level guidance is more actionable
        than generic AI-security guidance."""

        generic_source = Source(
            name="Generic News",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        text = (
            "CISA confirms this jailbreak-as-a-service vulnerability affecting an AI "
            "agent platform is being actively exploited in the wild."
        )
        category, _ = classify(text, generic_source)
        self.assertEqual(category, "Active exploitation")

    def test_ai_category_has_matching_actions_why_and_detection_entries(self) -> None:
        from security_brief.rules import ACTIONS, DETECTION_TEMPLATES, WHY

        self.assertIn("AI security and abuse", WHY)
        self.assertIn("AI security and abuse", ACTIONS)
        self.assertIn("AI security and abuse", DETECTION_TEMPLATES)
        # None of these should silently fall back to generic placeholder text
        self.assertNotEqual(WHY["AI security and abuse"], WHY["General security"])
        self.assertNotEqual(ACTIONS["AI security and abuse"], ACTIONS["General security"])


class AiRegulatoryAvailabilityRoutingTests(unittest.TestCase):
    """Covers: 'Priority 2 is also intended to capture information such as
    Anthropic update blocked for Europe and similar news about the biggest
    and most prominent AIs on the market.'"""

    def test_vendor_plus_regulatory_term_routes_to_ai_section(self) -> None:
        generic_source = Source(
            name="Generic Tech Press",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        combined = "Anthropic pauses the rollout of a new Claude feature in Europe amid regulatory scrutiny."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "AI Security and Trustworthiness",
        )

    def test_bare_regulatory_term_without_ai_vendor_does_not_route_to_ai_section(self) -> None:
        """The precision guard: 'antitrust investigation' alone (e.g. about
        an unrelated telecom company) must NOT get pulled into AI Security
        just because the phrase happens to also appear in AI_REGULATORY_
        AVAILABILITY_TERMS - it needs vendor co-occurrence."""

        generic_source = Source(
            name="Generic Tech Press",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        combined = "Regulators opened an antitrust investigation into the telecom merger."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "Threat Intelligence",
        )

    def test_gdpr_fine_without_ai_context_does_not_route_to_ai_section(self) -> None:
        generic_source = Source(
            name="Generic Tech Press",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Compliance",
        )
        combined = "A retailer faces a regulatory fine after a data protection authority found GDPR violations."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "Compliance",
        )

    def test_openai_geo_blocking_story_routes_correctly(self) -> None:
        generic_source = Source(
            name="Politico Tech",
            vendor="Generic",
            url="https://example.invalid/",
            source_type="rss",
            base_score=10,
            section="Threat Intelligence",
        )
        combined = "OpenAI's newest ChatGPT feature is geo-blocked in the EU pending an AI Act compliance review."
        self.assertEqual(
            route_section("General security", generic_source, combined),
            "AI Security and Trustworthiness",
        )


class SalmonFarmingSectorTests(unittest.TestCase):
    def test_relevance_tags_include_salmon_farming(self) -> None:
        _, tags = executive_news_relevance(
            title="SalMar reports ransomware attack disrupting feeding systems",
            summary="The salmon farming operator confirmed pen-control SCADA systems were affected.",
            base_score=10,
        )
        self.assertIn("Salmon Farming/Aquaculture", tags)

    def test_sector_impact_surfaces_salmon_farming_with_ot_implication(self) -> None:
        item = Item(
            title="Nordlaks confirms OT network intrusion at aquaculture site",
            summary="Attackers gained access to fish pen monitoring and feeding automation systems.",
            link="https://example.invalid/nordlaks-incident",
            published=datetime(2026, 8, 20, tzinfo=timezone.utc),
            source="Test Source",
            vendor="Test Vendor",
            section="OT, Energy and Oil & Gas",
            category="OT and ICS security",
            score=40,
        )
        impacts = build_sector_impacts([item], [])
        salmon = next(
            (i for i in impacts if i.sector == "Salmon Farming and Aquaculture"), None
        )
        self.assertIsNotNone(salmon)
        self.assertIn("SCADA", salmon.implication)


if __name__ == "__main__":
    unittest.main()
