# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.
# Last modified: v6.1.6

from __future__ import annotations

import unittest
from datetime import date, datetime, timedelta, timezone

from security_brief.models import Item
from security_brief.vulnerability_reporting import (
    VulnerabilityRecord,
    weekly_display_records,
)
from security_brief.weekly_rendering import (
    iso_week_label,
    render_weekly_vulnerability_report,
)


def record(cve: str = "CVE-2026-12345") -> VulnerabilityRecord:
    return VulnerabilityRecord(
        cve=cve,
        title=f"{cve} — test",
        vendor="Fortinet",
        product="FortiOS",
        category="Network / Security Appliances",
        source="Fortinet PSIRT RSS",
        source_tier="A — Authoritative",
        link="https://www.fortiguard.com/psirt/example",
        published=datetime(2026, 8, 12, tzinfo=timezone.utc),
        cvss=9.8,
        epss=0.61,
        kev=True,
        exploited=True,
        ransomware=False,
        zero_day=False,
        priority_score=92,
        remediation_band="Patch immediately",
        action="Patch immediately.",
        affected="Affected versions.",
        summary="An unauthenticated remote attacker can execute code on the appliance.",
    )


class WeeklyPresentationTests(unittest.TestCase):
    def test_display_policy_keeps_zero_days_first_and_filters_low_cvss(self) -> None:
        zero_day = record("CVE-2026-00001")
        zero_day.zero_day = True
        zero_day.cvss = None
        cvss_ten = record("CVE-2026-00002")
        cvss_ten.cvss = 10.0
        unscored = record("CVE-2026-00003")
        unscored.cvss = None
        critical = record("CVE-2026-00004")
        critical.cvss = 9.8
        medium = record("CVE-2026-00005")
        medium.cvss = 6.2
        low = record("CVE-2026-00006")
        low.cvss = 3.9

        displayed = weekly_display_records(
            [medium, low, critical, unscored, cvss_ten, zero_day]
        )

        self.assertEqual(
            [value.cve for value in displayed],
            [
                "CVE-2026-00001",
                "CVE-2026-00002",
                "CVE-2026-00003",
                "CVE-2026-00004",
                "CVE-2026-00005",
            ],
        )

    def test_iso_week_is_shown(self) -> None:
        self.assertEqual(iso_week_label(date(2026, 8, 13)), "Week 33 / 2026")

    def test_raw_priority_number_is_not_displayed(self) -> None:
        text, html = render_weekly_vulnerability_report(
            [record()],
            [],
            [record()],
            [("2026-08", 1)],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )
        self.assertNotIn("<th>Priority</th>", html)
        self.assertNotIn(">92<", html)
        self.assertIn("Week 33 / 2026", html)
        self.assertIn("Week 33 / 2026", text)

    def test_zero_days_metric_precedes_critical(self) -> None:
        _, html = render_weekly_vulnerability_report(
            [record()], [], [], [], date(2026, 8, 7), date(2026, 8, 13), []
        )
        self.assertLess(html.index(">Zero-days<"), html.index(">Critical<"))

    def test_headers_and_cells_use_explicit_alignment(self) -> None:
        _, html = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )
        for width in ("14%", "32%", "11%", "7%", "8%"):
            self.assertIn(f'width="{width}"', html)
        self.assertIn("Vulnerability details", html)
        self.assertIn(
            "An unauthenticated remote attacker can execute code on the appliance.",
            html,
        )
        self.assertIn("Affected scope: Affected versions.", html)
        self.assertIn("table-layout:fixed", html)
        self.assertIn('align="center"', html)
        self.assertIn('align="left"', html)

    def test_every_weekly_cve_location_links_directly_to_nvd(self) -> None:
        cve = "CVE-2026-12345"
        _, html = render_weekly_vulnerability_report(
            [record(cve)],
            [f"{cve}: newly added to CISA KEV"],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )
        target = f"https://nvd.nist.gov/vuln/detail/{cve}"
        self.assertGreaterEqual(html.count(f'href="{target}"'), 3)

    def test_source_health_exposes_quiet_and_failed_states(self) -> None:
        _, html = render_weekly_vulnerability_report(
            [],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [
                {
                    "source": "Fortinet PSIRT RSS",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                },
                {
                    "source": "AWS Security Bulletins",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                },
            ],
        )
        self.assertIn("Checked — no qualifying update", html)
        self.assertIn("Source unavailable — status unknown", html)

    def test_weekly_report_adds_top_vulnerabilities_section(self) -> None:
        normal = record("CVE-2026-10001")
        normal.priority_score = 99
        normal.cvss = 10.0
        urgent = record("CVE-2026-10002")
        urgent.priority_score = 70
        urgent.cvss = 8.8
        urgent.zero_day = True

        text, html = render_weekly_vulnerability_report(
            [normal, urgent],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )

        self.assertIn("Top Vulnerabilities of the Week", text)
        self.assertIn("Top Vulnerabilities of the Week", html)
        self.assertLess(
            html.index("CVE-2026-10002"),
            html.index("CVE-2026-10001"),
        )
        self.assertEqual(html.count('data-top-week-entry="1"'), 2)

    def test_month_in_rearview_is_limited_to_twenty_entries(self) -> None:
        month_records = []
        for index in range(25):
            value = record(f"CVE-2026-{20000 + index}")
            value.priority_score = 100 - index
            value.cvss = 10.0 - min(index, 6) * 0.1
            month_records.append(value)

        text, html = render_weekly_vulnerability_report(
            [record()],
            [],
            month_records,
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )

        self.assertIn("A month in the Rearview", text)
        self.assertIn("A month in the Rearview", html)
        self.assertEqual(html.count('data-rearview-entry="1"'), 20)
        self.assertIn("limited to 20", html)
        self.assertIn("CVE-2026-20019", html)
        self.assertNotIn("CVE-2026-20024", html)

    def test_lifecycle_changes_are_grouped_by_vendor_and_vulnerability_class(self) -> None:
        value = record("CVE-2026-30001")
        value.vendor = "Cisco"
        value.summary = "Remote code execution allows an unauthenticated attacker to execute code."
        text_body, html = render_weekly_vulnerability_report(
            [value],
            ["CVE-2026-30001: newly added to CISA KEV"],
            [value],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )
        self.assertIn("3. Exploitation, KEV & EPSS Changes", text_body)
        self.assertIn("Cisco", html)
        self.assertIn("Remote code execution", html)

    def test_remediation_priority_lists_vendor_then_cves(self) -> None:
        first = record("CVE-2026-31001")
        first.vendor = "Fortinet"
        first.remediation_band = "Patch immediately"
        second = record("CVE-2026-31002")
        second.vendor = "Cisco"
        second.remediation_band = "Validate exposure"
        text_body, html = render_weekly_vulnerability_report(
            [first, second],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
        )
        self.assertIn("4. Remediation Priority", text_body)
        self.assertIn("Patch immediately", html)
        self.assertIn("Fortinet", html)
        self.assertIn("CVE-2026-31001", html)
        self.assertIn("Validate exposure", html)
        self.assertIn("Cisco", html)
        self.assertIn("CVE-2026-31002", html)

    def test_quarterly_trend_panel_contains_four_severity_series(self) -> None:
        trend = {
            "weeks": [
                {
                    "week_start": f"2026-06-{1 + index:02d}",
                    "label": f"W{20 + index:02d}",
                    "Zero-Day": index % 2,
                    "Critical": index,
                    "High": index + 1,
                    "Medium": index + 2,
                }
                for index in range(13)
            ],
            "totals": {"Zero-Day": 6, "Critical": 78, "High": 91, "Medium": 104},
            "latest_four": {"Zero-Day": 2, "Critical": 42, "High": 46, "Medium": 50},
            "previous_four": {"Zero-Day": 1, "Critical": 26, "High": 30, "Medium": 34},
            "direction": "increasing",
            "peak_week": "W32",
            "peak_count": 40,
            "concentrations": [
                {"vendor": "Microsoft", "category": "Operating Systems", "count": 12}
            ],
            "counting_note": "Each CVE is counted once.",
        }
        text_body, html = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            quarterly_trend=trend,
        )
        self.assertIn("Quarterly Vulnerability Trend — rolling 13 weeks", text_body)
        self.assertIn("Quarterly Vulnerability Trend — Rolling 13 Weeks", html)
        for label in ("Zero-Day", "Critical", "High", "Medium"):
            self.assertIn(label, html)
        self.assertIn("latest 4 weeks", html)
        self.assertIn("Microsoft / Operating Systems", html)


def _ai_item(
    title: str = "OpenAI discloses prompt-injection mitigation research",
    summary: str = "New research on mitigating indirect prompt injection in agentic workflows.",
    link: str = "https://openai.com/news/example",
    source: str = "OpenAI News",
    published: datetime = datetime(2026, 8, 12, tzinfo=timezone.utc),
) -> Item:
    return Item(
        title=title,
        summary=summary,
        link=link,
        published=published,
        source=source,
        vendor=source,
        section="AI Security and Trustworthiness",
        category="AI security and abuse",
        score=20,
    )


class WeeklyAiDigestTests(unittest.TestCase):
    def test_ai_digest_section_appears_with_entries(self) -> None:
        text_body, html = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            ai_digest=[_ai_item()],
        )
        self.assertIn("AI Security and AI Development", text_body)
        self.assertIn("OpenAI discloses prompt-injection mitigation research", text_body)
        self.assertIn("https://openai.com/news/example", text_body)
        self.assertIn("AI Security and AI Development", html)
        self.assertIn("OpenAI discloses prompt-injection mitigation research", html)
        self.assertIn("prompt injection in agentic workflows", html)

    def test_ai_digest_section_handles_empty_list_gracefully(self) -> None:
        text_body, html = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            ai_digest=[],
        )
        self.assertIn("No qualifying AI security or AI development items this week.", text_body)
        self.assertIn("No qualifying AI security or AI development items this week.", html)

    def test_ai_digest_defaults_to_none_without_error(self) -> None:
        """Backward compatibility: existing call sites that don't pass
        ai_digest at all must still work (keyword-only, default None)."""

        text_body, html = render_weekly_vulnerability_report(
            [record()], [], [], [], date(2026, 8, 7), date(2026, 8, 13), []
        )
        self.assertIn("AI Security and AI Development", text_body)
        self.assertIn("No qualifying AI security or AI development items this week.", text_body)

    def test_ai_digest_deduplicates_by_link(self) -> None:
        duplicate = _ai_item(published=datetime(2026, 8, 10, tzinfo=timezone.utc))
        newer_duplicate = _ai_item(published=datetime(2026, 8, 13, tzinfo=timezone.utc))
        text_body, _ = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            ai_digest=[duplicate, newer_duplicate],
        )
        self.assertEqual(
            text_body.count("OpenAI discloses prompt-injection mitigation research"), 1
        )

    def test_ai_digest_sorted_most_recent_first(self) -> None:
        older = _ai_item(
            title="Older AI story",
            link="https://example.invalid/older",
            published=datetime(2026, 8, 8, tzinfo=timezone.utc),
        )
        newer = _ai_item(
            title="Newer AI story",
            link="https://example.invalid/newer",
            published=datetime(2026, 8, 13, tzinfo=timezone.utc),
        )
        text_body, _ = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            ai_digest=[older, newer],
        )
        self.assertLess(text_body.index("Newer AI story"), text_body.index("Older AI story"))

    def test_ai_digest_respects_limit_of_twelve(self) -> None:
        items = [
            _ai_item(
                title=f"AI story number {n:02d} zz",
                link=f"https://example.invalid/story-{n}",
                published=datetime(2026, 8, 1, tzinfo=timezone.utc) + timedelta(hours=n),
            )
            for n in range(20)
        ]
        text_body, _ = render_weekly_vulnerability_report(
            [record()],
            [],
            [],
            [],
            date(2026, 8, 7),
            date(2026, 8, 13),
            [],
            ai_digest=items,
        )
        included = sum(1 for n in range(20) if f"AI story number {n:02d} zz" in text_body)
        self.assertEqual(included, 12)
        # And it should be the 12 MOST RECENT (n=8..19), not an arbitrary 12.
        for n in range(8, 20):
            self.assertIn(f"AI story number {n:02d} zz", text_body)


if __name__ == "__main__":
    unittest.main()
