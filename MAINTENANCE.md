<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Maintenance Backlog

`MAINTENANCE.md` contains **open work only**. Completed work is recorded in
`CHANGELOG.md` and the corresponding release note.

## Documentation ownership

- `README.md` — current system behaviour, architecture, operation and setup.
- `CHANGELOG.md` — completed release changes.
- `MAINTENANCE.md` — open defects, improvements and planned work only.
- `docs/operations/CONTINUITY.md` — durable development handoff.
- `docs/operations/WEEKLY_VULNERABILITY_REPORT.md` — Weekly report operating reference.
- `docs/architecture/OPTIMISATION.md` — architecture and optimisation rationale.

## Current baseline

Version **6.1.4** is the current validation candidate.

The former Priority 1 Daily intelligence-quality work, source-truth correction,
failed-run catch-up, Weekly Top Vulnerabilities, vendor/class lifecycle grouping,
vendor-first remediation grouping, A Month in the Rearview and rolling-quarter
severity trend are implemented in 6.1.3 and therefore removed from this open
backlog.

## Priority 1 — AI Security & Trustworthiness

Implemented in 6.1.4: dedicated "AI Security and Trustworthiness" first-class
Daily section via content-based routing (takes precedence over vendor
routing); OpenAI/DeepMind/Anthropic sources; MITRE ATLAS and OWASP GenAI LLM
Top 10 framework-update trackers; expanded term coverage for real-world AI
use/abuse (deepfakes, voice cloning, AI-generated phishing/malware, scams,
jailbreak-as-a-service, disinformation) alongside AI's-own-security and
governance language.

Open follow-on:

- Weekly report currently has no equivalent AI Security tagging/section —
  decide whether it needs one or stays Daily-only.
- Consider a dedicated ACTIONS/WHY category (rather than reusing whatever
  the general classifier assigned) so AI Security items get tailored
  remediation guidance text instead of generic "General security" defaults.
- Revisit whether Anthropic News (HTML scrape, unverified selectors) needs
  live-DOM validation before full trust.

## Priority 2 — Source architecture follow-on

- Add GitHub Advisory Database pagination and explicit completeness/rate-limit handling.
- Use GHSA `updated_at` when a materially changed advisory would otherwise be
  missed by its original publication date.
- Enrich GHSA records with package/ecosystem, aliases and withdrawn state.
- Mark GHSA collection `PARTIAL` when the available result set is known to be
  truncated or incomplete.
- Add a stronger authoritative CrowdStrike path if a stable public source becomes available.
- Continue replacing fragile generic HTML parsing with structured vendor,
  government, RSS, API or disclosure feeds where available.
- Add source-specific fixture tests for every custom/resilient adapter.
- Evaluate public GuidePoint Security GRIT research as Tier-B supporting threat intelligence.
- Do not introduce paid/licensed dependencies solely for source enrichment.
- **Operational requirement**: `cisa_csaf.py` and the AI framework trackers
  (`ai_security_trackers.py`) call the GitHub REST API. Unauthenticated
  rate limit is 60/hour, which is too low for daily+catch-up windows. Add
  `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` (auto-provided per-run, no new
  secret to create) to the env of `daily-security-brief.yml` and
  `weekly-vulnerability-report.yml`.
- Norwegian sector-CERT coverage confirmed structurally blocked for
  HelseCERT, KraftCERT and FinansCERT/NFCERT (closed sector-ISAC models, no
  public feed) — not revisitable without direct membership access.
- Symantec/Broadcom vendor coverage remains blocked: advisories are
  login-gated on the Broadcom Support Portal with no public feed.
- [DONE 6.1.5] Trend Micro Research feed URL fixed (http, not https - the
  https variant does not resolve, was causing "temporarily unavailable").
- [DONE 6.1.5] Nozomi Networks Labs Blog selectors fixed: the site is
  Webflow-built (no semantic h2/h3/article wrapper tags), so the original
  selectors matched zero elements. Replaced with href-pattern selectors
  matching the site's actual /blog/{slug} link convention.
- Nozomi Networks Vulnerability Advisories page (nozominetworks.com/vulnerability-advisories)
  identified as high-value (third-party OT/ICS/IoT CVE disclosures from
  Nozomi Labs, openly available, no login) but structurally unsuited to the
  generic link-based HTML collector: content is duplicated in the DOM
  (table + card responsive layouts render the same rows twice) and most
  rows have no reliable per-item link to Nozomi's own domain (the
  "Details" link is a dead `#` on most rows; "Notification" links point
  to third-party vendor PDFs, GitHub, or CISA advisories, not a Nozomi
  page). Needs a dedicated row-based table parser (like
  `parse_hpe_security_bulletins_html`), keyed on the CVE-ID text itself,
  not a `Source(selectors=...)` config. Building this blind carries a real
  risk of silent duplication (not just clean failure) given the doubled
  DOM - get real page HTML (view-source/curl from a machine with access)
  before implementing.
- Nozomi Networks Threat Intelligence Feed (STIX 2.0/2.1 over a hosted
  TAXII server) identified as the proper structured alternative to scraping
  entirely: official, documented REST protocol (TAXII 2.x), IOCs
  (IPs/domains/URLs/hashes) plus YARA/Sigma/packet detection rules and
  vulnerability descriptions. Marketed explicitly for IT+OT ingestion
  (Splunk, QRadar, Azure Sentinel are Nozomi's own example targets, not
  just OT sensors). Sold standalone, independent of owning Guardian/Vantage
  sensors, via AWS Marketplace or a reseller (e.g. BAKOTECH). To pursue:
  (1) purchase the subscription - business/procurement decision, not
  technical; (2) Nozomi provisions TAXII server credentials on purchase;
  (3) build a TAXII 2.x client collector against Nozomi's published
  "Threat Intelligence Feed - Configuration Guide" once credentials exist.
  Scope caveat: this is tactical IOC/detection-rule content, not the
  narrative CVE write-ups from the Vulnerability Advisories page above -
  complementary, not a replacement.
- Two lower-cost paths worth trying before any purchase decision: (a)
  email Nozomi PSIRT/Labs directly (prodsec@nozominetworks.com) to ask
  whether structured API access to the Vulnerability Advisories dataset
  specifically exists for legitimate aggregation/research use, independent
  of the commercial TI feed; (b) if NetNordic does not already have a
  Nozomi partner relationship, explore whether one would open up better
  data access as a side benefit.
- Salesforce Security Blog is HTML-scraped with best-effort selectors,
  unverified against live DOM — same caveat as Anthropic News above.
- [DONE 6.1.5] HPE Security Bulletin Library switched from custom HTML
  table scrape to HPE's official RSS feed. CVSS/severity extraction from
  the feed's item description is best-effort and unverified against real
  feed content in this environment — confirm on the next real run whether
  severity data is actually present, and whether it's as complete as the
  old parser's direct table-column extraction. Old parser code kept as
  fallback (`priority_vendor_sources.fetch_hpe_security_bulletins`), not
  wired into any task.
- BankInfoSecurity has a real, confirmed-active official RSS feed
  (bankinfosecurity.com/rss-feeds shows genuine current article content),
  but the exact `.xml`/feed endpoint wasn't pinned down — worth switching
  from the current HTML scrape once confirmed, given BankInfoSecurity is
  one of the pre-existing historically-fragile sources.
- Apple Security Releases: Apple itself has no official RSS/feed at all
  (confirmed). SOFA (sofa.macadmins.io, MacAdmins community project) is
  the right replacement — JSON feed, updated every 6h via GitHub Actions,
  and critically flags `ActivelyExploitedCVEs` directly, which the current
  scraper has no equivalent for. Do NOT implement from search results
  alone: multiple sources gave conflicting URLs (`sofa.macadmins.io/v2/...`
  vs `sofafeed.macadmins.io/v1/...` vs a 2024 migration notice) - confirm
  the live, current URL via a real fetch before building, same lesson as
  the Trend Micro http/https mistake.

## Priority 3 — Sector relevance

Implemented in 6.1.4: Retail, Housing Estates/BoligByggerlag, and Energy
(split from Oil & Gas) across both `RELEVANCE_RULES` and
`SECTOR_IMPACT_RULES`.

## Priority 4 — GRC & Standards redesign

- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative EU, Norway, Sweden, Finland and Denmark coverage.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Maintain a persistent governance horizon with verified dates and primary sources.

## Priority 5 — Reliability, security and CI integrity

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Review `main` branch protection and require Repository CI before merge.
- Review repository visibility against the proprietary/confidential project posture.
- Add parser-fixture tests for source pages that have historically changed templates.
- Consider a controlled source-health canary that checks parser structure without
  treating publication cadence as collector failure.

## Priority 6 — Maintainability

- Fold the report-policy compatibility/monkey-patch layer into the main renderer
  during the next structural refactor.
- Continue extracting self-contained Daily presentation components where this
  improves testability.
- Keep source policy, evidence policy, presentation and orchestration boundaries explicit.

## Priority 7 — Historical capability

- Extend the optional private report archive with daily/weekly/monthly comparison.
- Reuse historical state for meaningful change detection rather than repeating unchanged intelligence.
- Consider backfilling the Weekly 13-week trend database from trusted historical
  advisory data so a new installation does not need 13 weeks to reach full depth.
- Avoid paid infrastructure unless operationally justified.
