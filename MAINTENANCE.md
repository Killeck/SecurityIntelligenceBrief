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
- `WEEKLY_VULNERABILITY_REPORT.md` — current weekly-report operating reference.
- `OPTIMISATION.md` — current architecture and optimisation rationale.

## Release discipline

Every functional or presentation release must increment `VERSION`, update the changelog and current-state documentation, remove completed backlog items, update tests, record actual validation, and use commit format `<VERSION> - <short comment>`.

## Forward Release Direction

Version 6.0 is reserved for code optimisation, maintainability and structural cleanup rather than major new report features.

## Priority 1 — Source-health truth, phase 2

Version 5.6.5 establishes explicit `CONTENT`, `QUIET` and `FAILED` collection states, records check/newest-item timestamps, and makes KEV / priority-vendor status depend on the expected authoritative source path. Remaining work:

- Detect selectors that return structurally valid pages but no longer match publisher content.
- Introduce source-specific freshness thresholds.
- Add `DEGRADED`, `STALE` and `PARTIAL` states directly at collection time.
- Add dedicated authoritative Cisco security-advisory coverage.
- Add a stronger authoritative CrowdStrike product/security-advisory path if a stable public source is available.
- Keep source failure from being confused with a clean negative in every future report component.

## Priority 2 — GRC & Standards redesign

- Rename `5. Standards / Compliance / Governance` to `5. GRC & Standards`.
- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative coverage for the EU, Norway, Sweden, Finland and Denmark.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Convert the forward look into a persistent governance horizon.

## Priority 3 — Enterprise DEFCON legend

- Remove the secondary embedded DEFCON PNG and render the layered triangle in email-safe HTML/tables.
- Increase legend title and descriptive text by approximately two font sizes.
- Preserve compact sizing and current-level emphasis.
- Re-test Outlook rendering and deliverability.

## Priority 4 — Operational Intelligence & Impact divider

- Add a full-width visual break after `5. GRC & Standards` and `6. Recommended Actions Today`.
- Proposed heading: `Operational Intelligence & Impact`.
- Use it to introduce Customer & Sector Impact, SOC & Detection Engineering, Threat Intelligence, Security Advisory & CISO Watch Next, and Source Coverage.

## Priority 5 — Source Coverage compact layout

- Render Daily Source Coverage as two balanced columns.
- Group by health state/colour first and alphabetically within each group.
- Green: qualifying content; Blue: checked/quiet; Amber: degraded/stale/partial; Red: failed/unavailable.

## Priority 6 — Reliability and security

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Add persistent state and cross-run deduplication to the daily report.
- Prevent repeated advisories across overlapping windows and retain meaningful updates.
- Track first-seen and last-seen timestamps.

## Priority 7 — Maintainability

- Externalise frequently changed source definitions, URLs, selectors, keywords, vendor priorities, sector mappings and source limits.
- Reduce source-specific logic inside generic modules.
- Fold the 5.6.5 report-policy compatibility layer into the main renderer during its next structural refactor.

## Priority 8 — Historical capability

- Add private report archiving and historical comparison.
- Store generated HTML or structured JSON and compare daily/weekly/monthly trends.
- Avoid paid infrastructure unless operationally justified.

## Priority 9 — Threat-intelligence enrichment

- Continue adding trusted deep-dive links.
- Improve source trust tiers and corroboration rules.
- Correlate vendor advisories, NVD, KEV and primary research into one logical development.
