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

## Priority 2 — AI Security & Trustworthiness

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

## Priority 3 — Source architecture follow-on

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
- Salesforce Security Blog is HTML-scraped with best-effort selectors,
  unverified against live DOM — same caveat as Anthropic News above.

## Priority 4 — Sector relevance

Implemented in 6.1.4: Retail, Housing Estates/BoligByggerlag, and Energy
(split from Oil & Gas) across both `RELEVANCE_RULES` and
`SECTOR_IMPACT_RULES`.

## Priority 5 — GRC & Standards redesign

- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative EU, Norway, Sweden, Finland and Denmark coverage.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Maintain a persistent governance horizon with verified dates and primary sources.

## Priority 6 — Reliability, security and CI integrity

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Review `main` branch protection and require Repository CI before merge.
- Review repository visibility against the proprietary/confidential project posture.
- Add parser-fixture tests for source pages that have historically changed templates.
- Consider a controlled source-health canary that checks parser structure without
  treating publication cadence as collector failure.

## Priority 7 — Maintainability

- Fold the report-policy compatibility/monkey-patch layer into the main renderer
  during the next structural refactor.
- Continue extracting self-contained Daily presentation components where this
  improves testability.
- Keep source policy, evidence policy, presentation and orchestration boundaries explicit.

## Priority 8 — Historical capability

- Extend the optional private report archive with daily/weekly/monthly comparison.
- Reuse historical state for meaningful change detection rather than repeating unchanged intelligence.
- Consider backfilling the Weekly 13-week trend database from trusted historical
  advisory data so a new installation does not need 13 weeks to reach full depth.
- Avoid paid infrastructure unless operationally justified.

## 6.1.3 validation gates

Before promoting 6.1.3:

1. Run the complete discoverable regression suite, including the relocated
   priority-vendor tests.
2. Confirm Repository CI passes.
3. Run and receive the Daily Security Brief.
4. Run and receive the Weekly Vulnerability Report.
5. Confirm the Daily vendor cards distinguish source health, current-window
   findings and latest material advisory context.
6. Confirm the Daily rolling 90-day threat-actor/campaign view and grouped 24/72h
   watch sections render correctly.
7. Confirm Weekly sections:
   - Top Vulnerabilities of the Week;
   - Exploitation, KEV & EPSS Changes grouped by vendor and vulnerability class;
   - Remediation Priority grouped by the four bands, then vendor, then CVE;
   - Quarterly Vulnerability Trend — Rolling 13 Weeks;
   - A Month in the Rearview, limited to 20 entries.
