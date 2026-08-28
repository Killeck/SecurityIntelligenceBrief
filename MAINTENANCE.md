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

Version **6.1.3** is the current validation candidate.

The former Priority 1 Daily intelligence-quality work, source-truth correction,
failed-run catch-up, Weekly Top Vulnerabilities, vendor/class lifecycle grouping,
vendor-first remediation grouping, A Month in the Rearview and rolling-quarter
severity trend are implemented in 6.1.3 and therefore removed from this open
backlog.

## Priority 2 — AI Security & Trustworthiness

Create a dedicated first-class reporting point for material AI developments,
including developments that show AI as a threat, security limitation, imposed
boundary/control, trustworthiness issue or material governance constraint.

### Security and operational risk

Include high-signal developments involving:

- AI-assisted attacks;
- autonomous/agent abuse;
- model vulnerabilities;
- prompt injection;
- data leakage;
- insecure copilots and agents;
- AI development / model supply-chain compromise;
- identity and permissions for autonomous agents;
- compromised AI pipelines and integrations.

### Trustworthiness and governance

Track material developments affecting:

- security;
- privacy;
- resilience;
- provenance;
- transparency and accountability;
- human oversight;
- regulatory or provider changes with operational security consequence.

Relevant ecosystems include Microsoft, OpenAI, Google, AWS, Anthropic and major
open-source platforms. Exclude generic model launches and marketing unless there
is a concrete security, trust, regulatory or operational consequence.

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

## Priority 4 — Sector relevance

Split broad customer-impact buckets into:

### Retail
- ecommerce/webshops;
- POS/payment environments;
- logistics dependencies;
- loyalty/customer platforms;
- store and warehouse operational technology where relevant.

### Housing Estates / BoligByggerlag
- housing associations/cooperatives;
- property-management platforms;
- access-control/building systems;
- resident/customer portals;
- payment/finance integrations;
- managed infrastructure and supplier dependencies.

### Energy
Treat Energy separately from Oil & Gas where useful:
- electricity and grid;
- renewables;
- energy services;
- energy trading;
- OT/ICS/industrial systems;
- supporting digital infrastructure;
- Nordic energy-service organisations.

Retain dedicated Oil & Gas classification where sector-specific operational risk warrants it.

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
