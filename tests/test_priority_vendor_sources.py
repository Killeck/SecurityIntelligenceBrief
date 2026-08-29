# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression coverage for authoritative priority-vendor sources.

Moved to the top-level tests directory in 6.1.3 so the repository's standard
``python -m unittest discover -s tests -v`` command actually executes it.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from security_brief.app import primary_tasks
from security_brief.priority_vendor_sources import (
    AUTHORITATIVE_VENDOR_RSS_SOURCES,
    REPLACED_GENERIC_HTML_SOURCES,
    match_priority_vendor,
    parse_hpe_security_bulletins_html,
)


class PriorityVendorSourceTests(unittest.TestCase):
    def test_official_vendor_feeds_are_configured(self) -> None:
        configured = {
            source.name: source.url
            for source in AUTHORITATIVE_VENDOR_RSS_SOURCES
        }
        expected = {
            "Cisco Security Advisories": (
                "https://sec.cloudapps.cisco.com/security/center/"
                "psirtrss20/CiscoSecurityAdvisory.xml"
            ),
            "Fortinet PSIRT RSS": "https://fortiguard.fortinet.com/rss/ir.xml",
            "AWS Security Bulletins": (
                "https://aws.amazon.com/security/security-bulletins/rss/feed/"
            ),
            "Google Cloud Security Bulletins": (
                "https://cloud.google.com/feeds/"
                "google-cloud-security-bulletins.xml"
            ),
            "Google Chrome Releases": (
                "https://chromereleases.googleblog.com/feeds/posts/"
                "default?alt=rss"
            ),
            "Palo Alto Networks Security Advisories": (
                "https://security.paloaltonetworks.com/rss.xml"
            ),
            "Okta Security Advisories": (
                "https://trust.okta.com/security-advisories.xml"
            ),
        }
        self.assertEqual(configured, expected)

    def test_generic_collectors_replaced_by_authoritative_adapters(self) -> None:
        self.assertEqual(
            REPLACED_GENERIC_HTML_SOURCES,
            {
                "Fortinet PSIRT",
                "HPE Security Bulletin Library",
                "Okta Security",
                "CISA ICS Advisories",
            },
        )

    def test_priority_vendor_nvd_attribution_is_specific(self) -> None:
        cases = (
            ("A vulnerability in Fortinet FortiOS allows...", "Fortinet"),
            ("HPE Aruba Networking AOS-CX is affected...", "HPE"),
            ("Palo Alto Networks PAN-OS vulnerability...", "Palo Alto Networks"),
            ("Cisco Secure Firewall vulnerability...", "Cisco"),
            ("Amazon Web Services AWS SDK issue...", "AWS"),
            ("Google Chrome Chromium use-after-free...", "Google"),
            ("Google Cloud Looker vulnerability...", "Google"),
            ("Okta Verify privilege escalation...", "Okta"),
            ("Apple macOS vulnerability...", "Apple"),
            ("CrowdStrike Falcon Sensor vulnerability...", "CrowdStrike"),
            ("Microsoft Azure vulnerability...", "Microsoft"),
        )
        for description, expected in cases:
            with self.subTest(expected=expected):
                match = match_priority_vendor(description)
                self.assertIsNotNone(match)
                self.assertEqual(match[0], expected)

    def test_hpe_parser_emits_per_cve_cvss_records(self) -> None:
        now = datetime.now(timezone.utc)
        published = now.strftime("%b %d, %Y")
        payload = f"""
        <table>
          <tr>
            <td>High</td>
            <td>
              <a href="/hpesc/public/docDisplay?docId=hpesbnw05081en_us">
                HPESBNW05081 rev.1 - Multiple Vulnerabilities in HPE Aruba Networking AOS-CX
              </a>
            </td>
            <td>Remote compromise of system integrity.</td>
            <td>Public</td>
            <td>CVE-2026-44880 CVE-2026-63453 CVE-2026-63454</td>
            <td>8.8 7.2 7.2</td>
            <td>{published}</td>
          </tr>
        </table>
        """
        items = parse_hpe_security_bulletins_html(
            payload,
            now - timedelta(hours=48),
        )
        self.assertEqual(len(items), 3)
        self.assertEqual(
            [item.cves[0] for item in items],
            ["CVE-2026-44880", "CVE-2026-63453", "CVE-2026-63454"],
        )
        self.assertEqual(
            [item.cvss_score for item in items],
            [8.8, 7.2, 7.2],
        )
        self.assertTrue(all(item.vendor == "HPE" for item in items))
        self.assertTrue(all(item.section == "HPE and Aruba" for item in items))

    def test_hpe_parser_rejects_out_of_window_rows(self) -> None:
        cutoff = datetime(2026, 8, 10, tzinfo=timezone.utc)
        payload = """
        <table><tr>
          <td>Critical</td>
          <td>HPESBNW04992 rev.4 - HPE Aruba Networking issue</td>
          <td>Old vulnerability.</td><td>Public</td>
          <td>CVE-2025-37184</td><td>9.8</td><td>Jun 25, 2026</td>
        </tr></table>
        """
        self.assertEqual(parse_hpe_security_bulletins_html(payload, cutoff), [])

    def test_primary_tasks_include_authoritative_sources(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
        names = {task.name for task in primary_tasks(cutoff, 3)}
        expected = {
            "CISA KEV",
            "NVD priority-vendor CVEs",
            "Cisco Security Advisories",
            "Fortinet PSIRT RSS",
            "AWS Security Bulletins",
            "Google Cloud Security Bulletins",
            "Google Chrome Releases",
            "Palo Alto Networks Security Advisories",
            "Okta Security Advisories",
            "HPE Security Bulletin Library",
        }
        self.assertTrue(expected <= names)
        self.assertNotIn("Fortinet PSIRT", names)
        self.assertNotIn("Okta Security", names)


if __name__ == "__main__":
    unittest.main()
