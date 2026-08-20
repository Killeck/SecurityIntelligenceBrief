<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Maintenance Backlog

`MAINTENANCE.md` contains **open work only**. Completed work is removed from this file when released and recorded in `CHANGELOG.md`.

## Documentation ownership

- `README.md` — current system behaviour, architecture, operation and setup.
- `CHANGELOG.md` — completed and released changes only.
- `MAINTENANCE.md` — open defects, improvements and planned work only.
- `docs/operations/WEEKLY_VULNERABILITY_REPORT.md` — current weekly-report operating reference.
- `docs/architecture/OPTIMISATION.md` — current architecture and optimisation rationale.

## Release discipline

Every functional or presentation release must increment `VERSION`, update the changelog and current-state documentation, remove completed backlog items, update tests, record actual validation, and use commit format `<VERSION> - <short comment>`.

## Forward Release Direction

The 6.1.0 source-architecture baseline introduces declarative vendor coverage,
explicit partial-source health and GitHub Advisory Database corroboration. The
next experimental enrichment branch should evaluate:

- Make corroboration and confidence explicit for every material claim.
- Add asset and technology relevance so prioritisation reflects the operating environment.
- Add a concise SOC action line per top item, including detection idea, log source or next step.
- Distinguish what is new, changed and repeated from previous reporting.
- Represent uncertainty clearly, especially where exploitation or attribution is reported but not confirmed.

## Priority 1 — Source-health truth, phase 2

The current baseline includes selector-health detection, source-specific freshness thresholds, persistent `STALE` / `PARTIAL` handling, declarative vendor coverage and authoritative Cisco Security Advisories. Remaining work:

- Add a stronger authoritative CrowdStrike product/security-advisory path if a stable public source is available.
- Apply `PARTIAL` collection metadata to adapters that can verify incomplete upstream datasets.
- Add OSV asset-inventory enrichment once an approved package/SBOM inventory input is available.

## Priority 2 — GRC & Standards redesign

- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative coverage for the EU, Norway, Sweden, Finland and Denmark.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Convert the forward look into a persistent governance horizon.




## Priority 3 — Reliability and security

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Track first-seen and last-seen timestamps.

## Priority 4 — Maintainability

- Continue moving source-specific collection definitions from generic modules into focused source catalogues.
- Fold the 5.6.5 report-policy compatibility layer into the main renderer during its next structural refactor.
- Continue extracting self-contained presentation components from the Daily renderer where this materially improves testability.

## Priority 5 — Historical capability

- Extend the private report archive with historical comparison and daily/weekly/monthly trend analysis.
- Avoid paid infrastructure unless operationally justified.

## Priority 6 — Threat-intelligence enrichment

- Continue adding trusted deep-dive links.
- Improve source trust tiers and corroboration rules.
- Correlate vendor advisories, NVD, KEV and primary research into one logical development.
