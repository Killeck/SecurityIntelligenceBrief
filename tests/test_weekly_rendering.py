# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

from __future__ import annotations

import unittest
from datetime import date, datetime, timezone

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

        displayed = weekly_display_records([medium, low, critical, unscored, cvss_ten, zero_day])

        self.assertEqual(
            [value.cve for value in displayed],
            ["CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003", "CVE-2026-00004", "CVE-2026-00005"],
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
        for width in ("17%", "20%", "8%", "9%", "10%", "28%"):
            self.assertIn(f'width="{width}"', html)
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


if __name__ == "__main__":
    unittest.main()
