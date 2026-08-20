# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Declarative vendor-coverage policy used by report truth evaluation.

This keeps vendor-specific source knowledge out of generic rendering and
collection orchestration.  A vendor may have an authoritative public advisory
path, supporting-only public coverage, or both.  Supporting coverage must never
produce a clean negative status.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VendorCoverage:
    """Describe evidence sources and matching terms for one vendor status card."""

    label: str
    terms: tuple[str, ...]
    authoritative_sources: tuple[str, ...] = ()
    supporting_sources: tuple[str, ...] = ()

    @property
    def has_public_authoritative_path(self) -> bool:
        """Return whether a clean negative can be established publicly."""

        return bool(self.authoritative_sources)


VENDOR_COVERAGE: tuple[VendorCoverage, ...] = (
    VendorCoverage("Microsoft", ("microsoft",), ("Microsoft Security Response Center",)),
    VendorCoverage("Fortinet", ("fortinet", "fortios", "fortigate"), ("Fortinet PSIRT RSS",)),
    VendorCoverage("Palo Alto", ("palo alto", "pan-os", "globalprotect", "prisma", "cortex"), ("Palo Alto Networks Security Advisories",)),
    VendorCoverage("Cisco", ("cisco",), ("Cisco Security Advisories",)),
    VendorCoverage("Google", ("google", "chrome", "chromium"), ("Google Cloud Security Bulletins", "Google Chrome Releases")),
    VendorCoverage("Apple", ("apple", "macos", "ios", "ipados", "safari"), ("Apple Security Releases",)),
    VendorCoverage("AWS", ("aws", "amazon web services", "amazon linux"), ("AWS Security Bulletins",)),
    VendorCoverage("Okta", ("okta",), ("Okta Security Advisories",)),
    # CrowdStrike's detailed product notices remain customer-portal material.
    # Public NVD correlation and the official blog are useful supporting signals,
    # but cannot establish an authoritative clean negative.
    VendorCoverage("CrowdStrike", ("crowdstrike", "falcon sensor"), (), ("NVD priority-vendor CVEs", "CrowdStrike Blog")),
    VendorCoverage("HPE / Aruba", ("hpe", "hewlett packard enterprise", "aruba", "aos-cx"), ("HPE Security Bulletin Library",)),
)

CISA_KEV_COVERAGE = VendorCoverage(
    "CISA KEV",
    ("cisa kev",),
    ("CISA KEV",),
)


def coverage_for(label: str) -> VendorCoverage | None:
    """Return a coverage record by display label."""

    return next((coverage for coverage in VENDOR_COVERAGE if coverage.label == label), None)
