<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Changelog

This file records **completed releases only**. Planned and incomplete work is
maintained exclusively in `MAINTENANCE.md`.

The project used working milestones before the formal v4/v5 release line. From
v5 onward this changelog is intentionally release-oriented; detailed prototype
history remains available in Git history.

---

## 6.0.0 - 2026-08-18

### Major update

- Advanced the product baseline from 5.7.0 to 6.0.0.
- Simplified the Daily Security Brief threat header by removing the five-box DEFCON scale and duplicate legend presentation while retaining one colour-coded Overall Threat status.
- Expanded the Weekly Vulnerability Report with a dedicated Vulnerability details column explaining the advisory, vulnerability behaviour and affected scope for every displayed CVE.
- Preserved advisory summaries in weekly lifecycle history, including automatic migration of existing SQLite history databases.
- Added stage-level runtime profiling for collection, enrichment, lifecycle, rendering and delivery.
- Added persistent NVD enrichment caching with a configurable TTL and GitHub Actions state restoration.
- Added configurable per-source HTML detail-fetch limits to bound network expansion.
- Added `config/sources.json` overlays for source URLs, selectors, limits, scoring, freshness and enable/disable state.
- Added persistent cross-run Daily duplicate suppression that retains materially changed advisories.
- Added explicit confidence and corroborating-source counts for material Daily and Weekly vulnerability claims.

### Changed

- Rebalanced the weekly CVE table widths to give explanatory text more room while retaining explicit Outlook-safe alignment.
- Kept direct NVD deep links and vendor-advisory links alongside the expanded vulnerability explanation.
- Removed the obsolete daily DEFCON-scale renderer and its no-longer-relevant regression test.
- Extracted the Overall Threat component and maintenance services into focused modules with boundary tests.
- Updated current-state, operational, architecture and release documentation for the 6.0.0 baseline.

### Validation

- Local offline regression suite: **73/73 tests passed**.
- GitHub Python 3.12 regression suite: **passed** on the v6.0.0 branch before release-metadata normalisation.
- Final repository CI and live Gmail delivery remain production gates after the complete 6.0.0 release commit is pushed.

## 5.7.0 - 2026-08-18

### Added

- Added authoritative Cisco Security Advisories / PSIRT coverage to the priority-vendor vulnerability layer.
- Added source-specific freshness thresholds for authoritative and general intelligence sources.
- Added selector-health failure detection when configured HTML selectors return no usable article candidates.
- Added optional private report archiving through `REPORT_ARCHIVE_DIR`, storing HTML, plain-text and JSON report snapshots without retaining reports by default.
- Added persistent `STALE` and `PARTIAL` source-health handling in addition to existing content, quiet and failure states.
- Added an independent GitHub Actions CI workflow for regression validation on release branches, pull requests and `main`.

### Changed

- Renamed `5. Standards / Compliance / Governance` to `5. GRC & Standards`.
- Reworked Source Coverage into a two-column health-aware presentation ordered by health state and source name.
- Added the `Operational Intelligence & Impact` divider before customer, SOC and threat-intelligence content.
- Cisco clean-negative status now requires successful collection from the authoritative Cisco Security Advisories source.
- Source-health assessment now honours per-source freshness expectations rather than one global freshness period.
- Release documentation paths were normalised under `docs/architecture`, `docs/operations` and `docs/releases`.

### Reliability

- A structurally valid publisher page with broken configured selectors is no longer silently interpreted as a clean source with no qualifying content.
- A source recovering from a previous failed or stale state can be represented conservatively as `PARTIAL` rather than immediately implying full source confidence.
- Private report archiving remains explicitly opt-in and fails closed without interrupting report delivery.

### Validation

- Baseline repository regression suite: 67/67 tests passed under the 5.7.0 merged code before release normalisation.
- Production-release regression and compile validation are rerun as part of the 5.7.0 release-normalisation process.
- Live Gmail API delivery remains separately validated through the manual Test Daily Security Brief workflow before production certification.

## 5.6.8 - 2026-08-13

### Changed

- Restored the full five-colour, equal-box DEFCON scale while retaining email-safe HTML and readable descriptions.
- Weekly vulnerability display now orders zero-days, CVSS 10.0, unscored CVEs, then CVSS 9.9 through 4.0; lower CVSS entries are omitted.
- Moved the Zero-days metric before Critical in the Weekly report's top summary row.

---

## 5.6.7 - 2026-08-13

### Added

- Added persistent optional per-source health state with last-success and newest-seen timestamps.
- Added conservative stale-feed detection and cross-run health-change metadata.

---

## 5.6.6 - 2026-08-13

### Fixed

- Added an explicit Gmail-secret preflight to the Daily Security Brief and Weekly Vulnerability Report workflows.
- Added safe delivery-path logging for OAuth refresh and Gmail API acceptance; no credential material is logged.
- Replaced the secondary inline DEFCON PNG with an Outlook-safe HTML/table legend and highlighted the current level.

### Changed

- Scheduled the Daily Security Brief for 06:17 Europe/Oslo and the Weekly Vulnerability Report for Monday 07:23 Europe/Oslo, providing delivery buffer while avoiding the top of the hour.
- Increased DEFCON legend title and explanatory text sizes.
- Moved release notes and manifests to `docs/releases/`.

### Validation

- Full offline regression suite to be recorded after the release changes are applied.

---

## 5.6.5 - 2026-08-13

### Added

- Added `CONTENT`, `QUIET` and `FAILED` source-health metadata with check and newest selected-item timestamps.
- Added a daily report policy layer that derives KEV / priority-vendor status from all collected intelligence and expected authoritative source health.
- Added ISO week number/year to the Weekly Vulnerability Report title, plain text, subject and run summary.
- Added an Outlook-safe weekly presentation layer with explicit matching header/body widths and alignment.
- Added direct NVD links whenever a full CVE identifier is displayed in the weekly main table, lifecycle-change section or remediation lists.

### Changed

- Replaced ambiguous vendor `No material update` output with health-aware clean, degraded, unavailable and unknown states.
- Vendors without a configured authoritative advisory channel no longer receive an authoritative clean-negative claim from supporting/research sources alone.
- Critical vulnerability presentation now orders current zero-days first, then confirmed exploitation / CISA KEV, then remaining entries by CVSS descending with EPSS as the equal-CVSS tie-breaker.
- Zero-day, exploited, KEV and CVSS 9+ records are retained past the normal report item cap.
- Removed the raw 0–100 internal priority score from the Weekly Vulnerability Report; the score remains internal for ordering and remediation-band calculation.
- Weekly vulnerability columns are now CVE, Vendor, CVSS, EPSS, KEV, Exploited and Action with explicit widths/alignment.

### Documentation

- Updated `README.md`, `WEEKLY_VULNERABILITY_REPORT.md` and `OPTIMISATION.md`.
- Removed the completed former Maintenance Priority 2 vulnerability-ordering work and re-numbered the remaining open backlog.

### Validation

- Syntax-compiled all Python files supplied in the 5.6.5 release package.
- Added focused tests for vendor/source truth, critical ordering, mandatory retention, ISO week numbering, weekly alignment, hidden raw priority scores and CVE hyperlinking.
- Full repository regression and live-source validation must run after overlaying the release onto v5.6.4.

## 5.6.4 - 2026-08-13

### Added

- Added `priority_vendor_sources.py` as the authoritative priority-vendor
  vulnerability collection layer.
- Added official security bulletin feeds for:
  - Fortinet PSIRT
  - AWS Security Bulletins
  - Google Cloud Security Bulletins
  - Google Chrome Releases
  - Palo Alto Networks Security Advisories
  - Okta Security Advisories
- Added a structured HPE Security Bulletin Library adapter that retains release
  date, CVE and per-CVE CVSS values from the official HPE result table.
- Added vendor-specific NVD priority coverage for Microsoft, Fortinet, HPE/Aruba,
  Palo Alto Networks, Cisco, AWS, Google/Chrome, Okta, Apple and CrowdStrike.
- Added focused regression coverage for source registration, NVD vendor
  attribution, HPE parsing and primary-task integration.

### Changed

- Replaced the generic Fortinet PSIRT HTML collector with Fortinet's official
  PSIRT RSS feed.
- Replaced the generic HPE bulletin collector with the structured HPE adapter.
- Replaced the general Okta security-article collector in the primary advisory
  path with Okta's official security-advisory feed.
- Retained Unit 42, FortiGuard Labs, AWS Security Blog, Google Security Blog and
  other research sources as complementary intelligence rather than authoritative
  vulnerability status sources.
- Replaced broad NVD labels such as `Microsoft / cloud identity` and
  `Other priority vendors` with specific vendor attribution in the new
  priority-vendor NVD path.
- The Weekly Vulnerability Report inherits the same authoritative vendor sources
  through the shared `primary_tasks()` pipeline.

### Documentation

- Updated `README.md`, `WEEKLY_VULNERABILITY_REPORT.md` and `OPTIMISATION.md` for
  the new source architecture and Gmail API delivery.
- Cleaned documentation ownership: `CHANGELOG.md` now contains released work;
  `MAINTENANCE.md` contains open work only.
- Removed completed-release duplication from `MAINTENANCE.md` and restructured
  the remaining backlog by priority.

### Validation

- Syntax-compiled all Python files supplied in the 5.6.4 release package.
- Added offline regression tests designed to run with the repository's existing
  test suite before email delivery.
- Live source retrieval is intentionally validated by the GitHub Actions manual
  test because the release-build environment has no direct repository network
  execution path.

---

## 5.6.3 - 2026-08-11

### Fixed

- Fixed the displayed DEFCON pyramid height at 91 pixels and aligned its five
  descriptions using matching fixed 18-pixel rows.
- Prevented legend-description wrapping so each line remains aligned with its
  corresponding pyramid layer.

### Validation

- Added regression coverage for pyramid height and description alignment.
- Passed 50 offline regression tests under Python 3.12.

---

## 5.6.2 - 2026-08-11

### Changed

- Reduced the Enterprise DEFCON Legend panel to 400 pixels.
- Moved reporting-window, source-count and version metadata to the top-right.
- Standardised release commit messages as `<VERSION> - <short comment>`.

### Validation

- Passed 50 offline regression tests under Python 3.12.

---

## 5.6.1 - 2026-08-11

### Changed

- Rebuilt the executive header around the compact layered DEFCON pyramid.
- Moved Overall Threat to the bottom-left of the legend row and simplified its
  presentation to numeric level plus status.

### Fixed

- Isolated Overall Threat and the five supporting metrics into separate
  email-safe tables to prevent Outlook column collapse.

### Validation

- Passed 50 offline regression tests across the daily and weekly reporting
  family.

---

## 5.6.0 - 2026-08-11

### Added

- Added the Weekly Vulnerability Report.
- Added CVE-centred remediation prioritisation using CVSS, EPSS, KEV,
  exploitation evidence, ransomware association, exposure relevance and age.
- Added SQLite lifecycle history and month-to-date vulnerability overview.
- Added ranked KEV and priority-vendor status cards with deep-dive links.

### Changed

- Added the compact layered DEFCON legend and revised metric layout.
- Expanded the Critical Vulnerabilities panel to full width.
- Scheduled the weekly report for Monday at 08:00 Europe/Oslo.

### Fixed

- Corrected weekly NVD limits and lifecycle-cache handling.

---

## 5.5.3 - 2026-08-11

### Changed

- Synchronised the repository version following the preceding daily-brief
  update.

---

## 5.5.2 - 2026-07-26

### Changed

- Introduced the darker green/black dashboard palette.

---

## 5.5.1 - 2026-07-25

### Changed

- Added the report logo and removed the version suffix from the visible title.

---

## 5.5.0 - 2026-07-17

### Fixed

- Repaired Rapid7, Shadowserver and Cyber Security News source configurations.
- Removed Reuters from unattended discovery after repeated collection failure.
- Enforced CVSS severity floors and corrected Critical/High rendering.
- Restricted the critical-vulnerability section to zero-days and CVSS 9.0–10.0.
- Prevented unrelated exposure reporting from over-escalating Overall Threat.

### Changed

- Expanded Active Exploitation / Threat Actor Activity to full width.
- Added threat-actor attribution with confidence labels.
- Added EU AI Act 2 August 2026 milestones to the governance forward look.
- Extended the governance horizon to one year.

---

## 5.4.0 - 2026-07-17

### Fixed

- Made MSRC collection tolerate `CurrentReleaseDate` without
  `InitialReleaseDate` while retaining replay protection.

### Changed

- Added full-width Recommended Actions rows and deeper vendor/governance links.
- Expanded governance presentation to a one-year forward look.

---

## 5.3.1 - 2026-07-17

### Fixed

- Prevented research articles from becoming false active-exploitation or breach
  signals.
- Recalibrated Overall Threat and limited revised historical MSRC replay.
- Restored a simpler outbound envelope after corporate-mail filtering issues.

---

## 5.3.0 - 2026-07-16

### Changed

- Introduced weighted evidence/impact threat scoring.
- Changed the outbound subject to `Security Intelligence Brief`.
- Reduced prominence of unverified ransomware aggregation claims.

### Security

- Withheld risky unverified-claim links from outbound email while retaining the
  intelligence and confidence labels.

---

## 5.2.0 - 2026-07-16

### Added

- Added MSRC Security Update Guide, CERT-EU, Google Threat Intelligence,
  Rapid7, Shadowserver and FIRST EPSS enrichment.
- Added Ransomware.live as explicitly unverified secondary discovery data.

---

## 5.1.0 - 2026-07-15

### Changed

- Added clickable cross-links and multi-row vendor presentation.
- Corrected Vendor Alerts versus Vendor Updates calculations.

---

## 5.0.0 - 2026-07-15

### Summary

- Promoted the dashboard redesign to the formal v5 release line.
- Made `VERSION` the runtime source of truth.
- Added repository ownership/licensing documentation and regression coverage.

---

## Earlier history

Versions before 5.0 cover the original Gmail transport proof of concept, CISA
KEV collector, NVD/CVSS enrichment, governance horizon, broad vendor and threat
research collection, modular v4.2 refactor, dark-web/exposure intelligence and
the first dashboard renderer. Detailed milestone notes remain available in Git
history through the v5.6.3 repository state.
