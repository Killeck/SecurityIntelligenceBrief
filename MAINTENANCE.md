<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Maintenance Backlog

`MAINTENANCE.md` contains **open work only**. Completed work is removed from this
file when released and recorded in `CHANGELOG.md`.

## Documentation ownership

- `README.md` — current system behaviour, architecture, operation and setup.
- `CHANGELOG.md` — completed and released changes only.
- `MAINTENANCE.md` — open defects, improvements and planned work only.
- `WEEKLY_VULNERABILITY_REPORT.md` — current weekly-report operating reference.
- `OPTIMISATION.md` — current architecture and optimisation rationale.

Do not duplicate completed release notes in this file.

## Release discipline

Every functional or presentation release must, where applicable:

- increment `VERSION` using semantic-style versioning;
- add a dated release entry to `CHANGELOG.md`;
- update `README.md` when current behaviour, architecture, setup or source
  coverage changes;
- update this backlog by removing completed items and retaining follow-up work;
- update focused operating documentation where behaviour changes;
- add or update regression tests;
- record actual validation performed in `CHANGELOG.md`;
- use commit format `<VERSION> - <short comment>`;
- commit implementation, tests, version and documentation together.

## Priority 1 — Source-health truth and vendor-status correctness

- Replace ambiguous `No material update` wording with explicit states:
  - `Material update(s)`
  - `Checked — no material update`
  - `Degraded / stale / partial`
  - `Source unavailable — status unknown`
- Make KEV & Priority Vendor Status depend on authoritative-source health as well
  as selected report items.
- Detect successful HTTP responses that yield no usable records.
- Detect stale feeds and broken HTML selectors.
- Record per-source last-success time and newest-item timestamp.
- Report source-health changes between runs.
- Ensure a source failure can never be represented as a clean negative result.

## Priority 2 — Critical Vulnerabilities / Zero-Days ordering

- Sort every current zero-day first, irrespective of CVSS.
- Follow with confirmed exploitation and CISA KEV records.
- List remaining `No evidence` vulnerabilities by CVSS descending.
- Use EPSS descending as the tie-breaker for equal CVSS scores.
- Preserve critical items even when the normal report item limit is reached.

## Priority 3 — GRC & Standards redesign

- Rename `5. Standards / Compliance / Governance` to `5. GRC & Standards`.
- Add a direct source/deep-dive link for every current change and forward-look
  milestone where a trusted source exists.
- Expand authoritative forward-looking coverage for:
  - European Union
  - Norway
  - Sweden
  - Finland
  - Denmark
- Strengthen coverage of NIS2, DORA, EU AI Act, Cyber Resilience Act, relevant
  privacy/security legislation and national implementations.
- Expand ISO/IEC coverage to relevant security, risk, privacy, resilience and
  management-system standards.
- Convert the forward look into a persistent governance horizon instead of
  relying mainly on dates found inside the current 36/72-hour collection window.

## Priority 4 — Enterprise DEFCON legend

- Remove the secondary embedded DEFCON PNG and render the layered triangle using
  email-safe HTML/table structures.
- Increase the legend title by approximately two font sizes.
- Increase the descriptive text by approximately two font sizes.
- Preserve compact sizing and current-level emphasis.
- Re-test Outlook rendering and deliverability after the MIME image is removed.

## Priority 5 — Operational Intelligence & Impact divider

- Add a full-width visual break after `5. GRC & Standards` and
  `6. Recommended Actions Today`.
- Proposed heading: `Operational Intelligence & Impact`.
- Use it to introduce:
  - Customer & Sector Impact
  - SOC & Detection Engineering
  - Threat Intelligence
  - Security Advisory & CISO Watch Next
  - Source Coverage

## Priority 6 — Source Coverage compact layout

- Render Source Coverage as two balanced columns.
- Group by health state/colour first and alphabetically inside each group.
- Green: qualifying content collected.
- Blue: checked successfully with no qualifying content.
- Amber: degraded, stale or partial.
- Red: failed/unavailable.

## Priority 7 — Reliability and security

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Add persistent state and cross-run deduplication to the daily report.
- Prevent repeated advisories across overlapping reporting windows.
- Retain meaningful updates to previously reported developments.
- Track first-seen and last-seen timestamps.

## Priority 8 — Maintainability

- Externalise frequently changed source definitions and relevance rules.
- Externalise source URLs, selectors, keywords, vendor priorities, sector
  mappings and source limits.
- Reduce source-specific logic inside large generic modules where a dedicated
  adapter provides clearer ownership.

## Priority 9 — Historical capability

- Add private report archiving and historical comparison.
- Store generated HTML or structured JSON.
- Compare daily, weekly and monthly trends.
- Avoid paid infrastructure unless there is a clear operational need.

## Priority 10 — Threat-intelligence enrichment

- Continue adding trusted deep-dive links.
- Improve source trust tiers and corroboration rules.
- Correlate vendor advisories, NVD, KEV and primary research into one logical
  development where they describe the same underlying vulnerability or event.
