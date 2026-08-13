# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

from __future__ import annotations

import unittest
from datetime import date, datetime, timezone

from security_brief.vulnerability_reporting import VulnerabilityRecord
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
