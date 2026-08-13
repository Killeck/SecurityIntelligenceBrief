# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from security_brief.models import Item
from security_brief.report_policy import (
    critical_vulnerability_items,
    ensure_mandatory_vulnerabilities,
    vendor_statuses,
)


def make_item(
    cve: str,
    *,
    vendor: str = "Fortinet",
    cvss: float | None = None,
    zero_day: bool = False,
    exploited: bool = False,
    kev: bool = False,
    epss: str = "",
    score: int = 50,
) -> Item:
    return Item(
        title=f"{cve} — test",
        summary="Test vulnerability",
        link=f"https://example.test/{cve}",
        published=datetime(2026, 8, 13, tzinfo=timezone.utc),
        source="Unit test",
        vendor=vendor,
        section="Other Vendor Advisories",
        category="Critical vulnerability",
        score=score,
        cves=[cve],
        zero_day=zero_day,
        exploited=exploited,
        kev=kev,
        cvss_score=cvss,
        cvss_severity="CRITICAL" if (cvss or 0) >= 9 else "HIGH",
        why=(f"EPSS: {epss} probability." if epss else ""),
    )


class ReportPolicyTests(unittest.TestCase):
    def test_cisco_clean_negative_requires_psirt_success(self) -> None:
        statuses = vendor_statuses(
            [],
            [{"source": "Cisco Security Advisories", "status": "OK", "items": 0}],
        )
        cisco = next(status for status in statuses if status.label == "Cisco")
        self.assertEqual(cisco.status, "Checked — no material update")

    def test_critical_order_is_evidence_then_cvss_then_epss(self) -> None:
        values = [
            make_item("CVE-2026-10001", cvss=10.0, epss="80.0%"),
            make_item("CVE-2026-10002", cvss=9.8, exploited=True),
            make_item("CVE-2026-10003", cvss=7.5, zero_day=True),
            make_item("CVE-2026-10004", cvss=9.8, epss="40.0%"),
            make_item("CVE-2026-10005", cvss=9.8, epss="70.0%"),
        ]
        ordered = critical_vulnerability_items(values)
        self.assertEqual(
            [value.cves[0] for value in ordered],
            [
                "CVE-2026-10003",
                "CVE-2026-10002",
                "CVE-2026-10001",
                "CVE-2026-10005",
                "CVE-2026-10004",
            ],
        )

    def test_mandatory_records_survive_normal_selection_limit(self) -> None:
        selected = [make_item("CVE-2026-20001", cvss=8.0)]
        result = ensure_mandatory_vulnerabilities(
            selected,
            selected
            + [
                make_item("CVE-2026-20002", cvss=9.8),
                make_item("CVE-2026-20003", cvss=7.8, exploited=True),
            ],
        )
        self.assertEqual(len(result), 3)

    def test_clean_negative_requires_authoritative_success(self) -> None:
        statuses = vendor_statuses(
            [],
            [
                {
                    "source": "Fortinet PSIRT RSS",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                }
            ],
        )
        fortinet = next(value for value in statuses if value.label == "Fortinet")
        self.assertEqual(fortinet.status, "Checked — no material update")

    def test_failure_never_becomes_clean_negative(self) -> None:
        statuses = vendor_statuses(
            [],
            [
                {
                    "source": "Fortinet PSIRT RSS",
                    "status": "FAILED",
                    "health_state": "FAILED",
                    "items": 0,
                }
            ],
        )
        fortinet = next(value for value in statuses if value.label == "Fortinet")
        self.assertEqual(
            fortinet.status,
            "Source unavailable — status unknown",
        )

    def test_material_status_uses_all_collected_items(self) -> None:
        statuses = vendor_statuses(
            [make_item("CVE-2026-30001", cvss=8.8)],
            [
                {
                    "source": "Fortinet PSIRT RSS",
                    "status": "OK",
                    "health_state": "CONTENT",
                    "items": 1,
                }
            ],
        )
        fortinet = next(value for value in statuses if value.label == "Fortinet")
        self.assertEqual((fortinet.count, fortinet.status), (1, "1 material update(s)"))

    def test_supporting_only_vendor_does_not_claim_clean_negative(self) -> None:
        statuses = vendor_statuses(
            [],
            [
                {
                    "source": "NVD priority-vendor CVEs",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                },
                {
                    "source": "CrowdStrike Blog",
                    "status": "OK",
                    "health_state": "QUIET",
                    "items": 0,
                },
            ],
        )
        crowdstrike = next(value for value in statuses if value.label == "CrowdStrike")
        self.assertIn("authoritative status unknown", crowdstrike.status)


if __name__ == "__main__":
    unittest.main()
