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

## 6.1.4 - 2026-08-28

### Nordics and IT/OT source integrity

- Migrated NSM/NCSC to its confirmed RSS feed (`varsler-fra-ncsc/rss/`) with
  `freshness_days=45` reflecting its true ~monthly publishing cadence,
  replacing brittle HTML scraping.
- Split Nozomi Networks into two sources: a confirmed-working PSIRT RSS
  feed (own-product advisories) and a retained "Nozomi Networks Labs Blog"
  HTML source, correctly renamed and re-threaded through the historical
  context and resilient-fallback source sets.
- Added the CISA CSAF structured-advisory collector (`cisa_csaf.py`),
  covering OT, IT and VA branches directly from `cisagov/CSAF` via the
  GitHub Commits API (efficient path/since-filtered polling rather than
  brute-force downloads), replacing the brittle "CISA ICS Advisories" HTML
  scrape and adding IT-side CISA coverage that was previously absent.
- Researched Norwegian sector-CERT coverage (HelseCERT, KraftCERT,
  FinansCERT/NFCERT): confirmed all three are closed sector-ISAC models with
  no public feed; documented as structurally blocked rather than a gap in
  collection logic.

### Sector relevance (Priority 4)

- Split "Energy/Oil & Gas" into separate Energy and Oil & Gas
  classifications across both `RELEVANCE_RULES` and `SECTOR_IMPACT_RULES`.
- Split "Retail/Hospitality/Property" into Retail, Hospitality/Property, and
  a new dedicated Housing Estates/BoligByggerlag classification with
  Norwegian housing-cooperative-specific keywords and guidance.

### Nordic-focused threat activity

- Added sticky Nordic-relevance tagging to the rolling 90-day
  threat-actor/campaign view: an entry flagged Nordic-relevant from any
  qualifying observation stays flagged even after later non-Nordic updates.
- Nordic-relevant entries now sort ahead of more-recent non-Nordic entries
  in the rolling view, with a visual "NORDIC" badge in the rendered table.

### AI Security & Trustworthiness (Priority 2)

- Added "AI Security and Trustworthiness" as a first-class dedicated Daily
  report section (not a tag) via a content-based routing override that
  takes precedence over vendor-specific routing, so material AI-security
  content is surfaced regardless of source.
- Added OpenAI News and Google DeepMind Blog (RSS) and Anthropic News
  (HTML) as topic-filtered sources; Microsoft AI-security content already
  flows through the existing Microsoft Security Blog source via the new
  routing.
- Added MITRE ATLAS (GitHub Releases API) and OWASP GenAI LLM Top 10
  (GitHub Commits API rollup) framework-update trackers
  (`ai_security_trackers.py`).
- Expanded `AI_SECURITY_TERMS` beyond AI's-own-security language to cover
  real-world AI use and abuse: deepfakes, voice cloning, synthetic media,
  AI-generated phishing/malware, AI-powered scams, jailbreak-as-a-service,
  named malicious-LLM tooling, disinformation campaigns, and defensive use
  (AI-powered detection, agentic SOC).

### Monitored-stack coverage

- Cross-checked source coverage against the organisation's actual security
  vendor stack. Added SentinelOne Blog, Trend Micro Research and the
  Kubernetes Official CVE Feed (all confirmed-working RSS). Added Salesforce
  Security Blog (HTML; the Trust-site RSS was retired in 2023 and the
  advisories page is a client-rendered SPA that cannot be scraped).
  Symantec/Broadcom remains uncovered: advisories are login-gated on the
  Broadcom Support Portal with no public feed.

### Code security and maintenance

- Fixed a Bandit B608 (SQL construction) false positive in
  `vulnerability_reporting.py` with a justified `# nosec` and a cleaner
  parameterised query builder.
- Removed the dead `src/Archive/` directory (unreferenced legacy scripts;
  source of the only remaining `urlopen()` findings).
- Promoted `tests/tests/test_priority_vendor_sources.py` to
  `tests/test_priority_vendor_sources.py` so it is actually discovered by
  `python -m unittest discover -s tests`; fixed a stale assertion the
  promotion surfaced (missing Cisco Security Advisories in expected
  sources — the implementation was correct, the test was stale).



### Daily intelligence quality

- Completed the former Priority 1 Daily backlog.
- Normalises Critical Vulnerability / Zero-Day TL;DR text before rendering,
  removing Markdown/heading artefacts while preserving meaningful numeric hash references.
- Added persistent rolling 90-day Active Exploitation / Threat Actor Activity
  state with actor/campaign, activity, last observed, days ago, confidence and evidence.
- Reworked Security Advisory & CISO Watch Next into separate 24-hour and 72-hour
  decision horizons with Development, Evidence, Enterprise relevance, Sector
  relevance, What to watch next and Recommended action.

### Source truth and continuity

- Added persistent last-success delivery state so a failed Daily run expands the
  next collection window with overlap rather than losing advisories between runs.
- Separated reader-facing Daily content from a 90-day priority-vendor context window.
- Replaced generic `No material update` semantics with explicit current-window,
  latest-material, incomplete, unavailable and unknown states.
- Split HPE and Aruba into separate vendor status cards.
- Stopped treating an old newest publication as proof that a successfully checked
  low-frequency source is stale.
- Added resilient handling/configuration for BankInfoSecurity, Claroty Team82,
  Dragos, FBI Cyber News, ISACA News and Trends, ISO News, NIST CSRC News,
  Nozomi Networks Labs and Splunk Security Blog.
- Added structured Claroty Team82 disclosure-dashboard collection.
- Added BankInfoSecurity first-party RSS override.

### Weekly Vulnerability Report

- Added **Top Vulnerabilities of the Week**.
- Reworked **3. Exploitation, KEV & EPSS Changes** to group lifecycle changes by
  vendor and vulnerability class/type.
- Reworked **4. Remediation Priority** around the four established bands:
  Patch immediately, Patch within 7 days, Validate exposure and Monitor; within
  each band the report lists vendor first and CVEs underneath.
- Added **Quarterly Vulnerability Trend — Rolling 13 Weeks**, covering Zero-Day,
  Critical, High and Medium only, using first-observed lifecycle history.
- Added trend interpretation comparing the latest four weeks with the preceding
  four, quarter totals, peak week and material vendor/technology concentration.
- Added **A Month in the Rearview**, ranking the 20 most prominent month-to-date
  vulnerability entities.

### CI integrity

- Relocated priority-vendor regression coverage to `tests/test_priority_vendor_sources.py`
  so the standard unittest discovery command executes it.
- Added focused regression coverage for Daily catch-up, source health, TL;DR
  cleanup, vendor context, threat activity, decision-oriented watch sections,
  Weekly ranking/grouping and quarterly trend calculations.

### Validation

- All supplied Python files syntax-compile in the 6.1.3 build package.
- Focused pure trend-engine validation passes locally.
- Full Repository CI and live Daily/Weekly Gmail delivery remain production gates.

## 6.1.2 - 2026-08-20

### Fixed

- Restored the approved Daily executive threat-header layout with a compact
  colour-coded Overall Threat box on the left and a text-only DEFCON 1–5 legend
  on the right on the same row.
- Restored all five explanatory DEFCON descriptions and marks the current level
  once in the legend.
- Preserved the five operational metric cards on the full-width row below.
- Kept the legend explanatory only; the obsolete five-box active DEFCON scale is
  not reintroduced.

### Changed

- Kept the implementation isolated in `rendering_components.py` so the large
  Daily renderer and metric-card structure remain unchanged.
- Updated regression coverage from the 6.0.0 "legend absent" expectation to the
  approved 6.1.2 hierarchy.
- Removed the completed DEFCON restoration from the open maintenance backlog.

### Validation

- Changed Python files syntax-compile successfully in the build package.
- Isolated DEFCON component functional/layout test: **passed**.
- Full Repository CI and manual Daily Gmail visual validation remain release gates.

## 6.1.1 - 2026-08-20

### Documentation / maintenance

- Reconciled `MAINTENANCE.md` against capabilities already delivered in 6.0.0
  and 6.1.0.
- Updated `docs/operations/CONTINUITY.md` from the stale 6.0.0 continuation
  point to the 6.1.x development line.
- Recorded the Daily Brief intelligence-quality backlog covering DEFCON
  presentation, TL;DR cleanup, rolling threat-actor history, AI Security &
  Trustworthiness, vendor/source truth, sector relevance and CISO 24/72-hour
  grouping.
- No production Python behaviour was intentionally changed.

## 6.1.0 - 2026-08-20

### Added

- Added the public GitHub Advisory Database as structured open-source vulnerability corroboration.
- Added a dedicated vendor-coverage registry, separating vendor evidence policy from generic report policy.
- Added explicit `PARTIAL` source-health handling for successful but incomplete source collection.

### Changed

- CrowdStrike public coverage is now formally supporting-only: its public blog and NVD correlation cannot establish a clean vendor negative while detailed product notices remain customer-portal material.
- Began the source-architecture refactor for the 6.1.0 release line.

### Validation

- Local offline regression suite: **76/76 tests passed**.
- Python compilation passed locally.
- Repository CI and live Daily/Weekly delivery remain production gates.

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

- Added `priority_vendor_sources.py` as the authoritative priority-vendor vulnerability collection layer.
- Added official security bulletin feeds for:
  - Fortinet PSIRT
  - AWS Security Bulletins
  - Google Cloud Security Bulletins
  - Google Chrome Releases
  - Palo Alto Networks Security Advisories
  - Okta Security Advisories
- Added a structured HPE Security Bulletin Library adapter that retains release date, CVE and per-CVE CVSS values from the official HPE result table.
- Added vendor-specific NVD priority coverage for Microsoft, Fortinet, HPE/Aruba, Palo Alto Networks, Cisco, AWS, Google/Chrome, Okta, Apple and CrowdStrike.
- Added focused regression coverage for source registration, NVD vendor attribution, HPE parsing and primary-task integration.

### Changed

- Replaced the generic Fortinet PSIRT HTML collector with Fortinet's official PSIRT RSS feed.
- Replaced the generic HPE bulletin collector with the structured HPE adapter.
- Replaced the general Okta security-article collector in the primary advisory path with Okta's official security-advisory feed.
- Retained Unit 42, FortiGuard Labs, AWS Security Blog, Google Security Blog and other research sources as complementary intelligence rather than authoritative vulnerability status sources.
- Replaced broad NVD labels such as `Microsoft / cloud identity` and `Other priority vendors` with specific vendor attribution in the new priority-vendor NVD path.
- The Weekly Vulnerability Report inherits the same authoritative vendor sources through the shared `primary_tasks()` pipeline.

### Documentation

- Updated `README.md`, `WEEKLY_VULNERABILITY_REPORT.md` and `OPTIMISATION.md` for the new source architecture and Gmail API delivery.
- Cleaned documentation ownership: `CHANGELOG.md` now contains released work; `MAINTENANCE.md` contains open work only.
- Removed completed-release duplication from `MAINTENANCE.md` and restructured the remaining backlog by priority.

### Validation

- Syntax-compiled all Python files supplied in the 5.6.4 release package.
- Added offline regression tests designed to run with the repository's existing test suite before email delivery.
- Live source retrieval is intentionally validated by the GitHub Actions manual test because the release-build environment has no direct repository network execution path.

---

## 5.6.3 - 2026-08-11

### Fixed

- Fixed the displayed DEFCON pyramid height at 91 pixels and aligned its five descriptions using matching fixed 18-pixel rows.
- Prevented legend-description wrapping so each line remains aligned with its corresponding pyramid layer.

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
- Moved Overall Threat to the bottom-left of the legend row and simplified its presentation to numeric level plus status.

### Fixed

- Isolated Overall Threat and the five supporting metrics into separate email-safe tables to prevent Outlook column collapse.

### Validation

- Passed 50 offline regression tests across the daily and weekly reporting family.

---

## 5.6.0 - 2026-08-11

### Added

- Added the Weekly Vulnerability Report.
- Added CVE-centred remediation prioritisation using CVSS, EPSS, KEV, exploitation evidence, ransomware association, exposure relevance and age.
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

- Synchronised the repository version following the preceding daily-brief update.

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

- Made MSRC collection tolerate `CurrentReleaseDate` without `InitialReleaseDate` while retaining replay protection.

### Changed

- Added full-width Recommended Actions rows and deeper vendor/governance links.
- Expanded governance presentation to a one-year forward look.

---

## 5.3.1 - 2026-07-17

### Fixed

- Prevented research articles from becoming false active-exploitation or breach signals.
- Recalibrated Overall Threat and limited revised historical MSRC replay.
- Restored a simpler outbound envelope after corporate-mail filtering issues.

---

## 5.3.0 - 2026-07-16

### Changed

- Introduced weighted evidence/impact threat scoring.
- Changed the outbound subject to `Security Intelligence Brief`.
- Reduced prominence of unverified ransomware aggregation claims.

### Security

- Withheld risky unverified-claim links from outbound email while retaining the intelligence and confidence labels.

---

## 5.2.0 - 2026-07-16

### Added

- Added MSRC Security Update Guide, CERT-EU, Google Threat Intelligence, Rapid7, Shadowserver and FIRST EPSS enrichment.
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
