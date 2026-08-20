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
- `docs/operations/CONTINUITY.md` — durable development handoff and current continuation point.
- `docs/operations/WEEKLY_VULNERABILITY_REPORT.md` — current weekly-report operating reference.
- `docs/architecture/OPTIMISATION.md` — current architecture and optimisation rationale.

## Release discipline

Every functional or presentation release must increment `VERSION`, update the changelog and current-state documentation, remove completed backlog items, update tests, record actual validation, and use commit format `<VERSION> - <short comment>`.

## Current baseline

Version 6.1.0 established the source-architecture baseline:

- declarative priority-vendor coverage;
- authoritative-versus-supporting evidence separation;
- GitHub Advisory Database corroboration;
- persistent source-health semantics including `CONTENT`, `QUIET`, `PARTIAL`, `STALE`, `DEGRADED` and `FAILED`;
- explicit confidence and corroborating-source counts for material vulnerability claims;
- persistent NVD caching, configurable source overlays, bounded detail collection and Daily duplicate suppression from 6.0.0.

The backlog below therefore contains only work that remains incomplete after 6.0.0 and 6.1.0.

## Priority 1 — Daily Brief intelligence quality

### 1.1 DEFCON presentation

- Restore the **text-only DEFCON 1–5 legend** on the same horizontal row as `Overall Threat`, aligned to the right.
- Keep only one active colour-coded Overall Threat indicator.
- Do not reintroduce a second set of coloured DEFCON status boxes.

### 1.2 Critical Vulnerabilities / Zero-days TL;DR cleanup

- Remove stray Markdown/source artefacts such as repeated `#` characters from TL;DR text.
- Normalise TL;DR content before HTML rendering rather than masking artefacts with presentation-only CSS.
- Keep each TL;DR concise and decision-useful: vulnerability mechanism, affected technology and material impact.

### 1.3 Active Exploitation / Threat Actor Activity

- Replace the effectively empty short-window view with a **rolling 90-day activity view**.
- Preserve normal 36/72-hour freshness for the rest of the Daily Brief.
- Track each material actor/campaign with:
  - actor or campaign;
  - activity / targeting summary;
  - last observed date;
  - `days ago`;
  - confidence;
  - evidence / primary source.
- Update `last_seen` only when new evidence demonstrates actual activity, targeting, exploitation, infrastructure activity, malware operation, incident attribution or equivalent material observation.
- Do not reset `last_seen` because an article merely mentions an actor.
- Drop entries after 90 days without qualifying activity.
- Persist state across Daily runs.

### 1.4 CISO Watch Next / Security Advisory redesign

- Rework the 24/72-hour sections into grouped, correlated developments rather than independent story repetition.
- Use a decision-oriented structure:
  - Development
  - Evidence
  - Enterprise relevance
  - Sector relevance
  - What to watch next
  - Recommended action
- Correlate vendor advisory, CISA KEV, NVD and trusted research into one logical development when they describe the same issue.
- Separate:
  - **Next 24h** — active exposure, verification and immediate action.
  - **Next 72h** — emerging developments, vendor updates, exploitation confirmation and monitoring.
- Prefer thematic grouping where useful: vulnerabilities/exposure; identity/cloud; threat actors/ransomware; AI security/trust; governance/regulation; sector/business impact.

## Priority 2 — AI Security & Trustworthiness

Create a dedicated first-class reporting point for material AI developments.

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

Relevant ecosystems include Microsoft, OpenAI, Google, AWS, Anthropic and major open-source platforms, but generic model releases and marketing must be excluded unless they have a concrete security, trustworthiness, regulatory or operational consequence.

## Priority 3 — Vendor and source truth

### 3.1 Clean-negative semantics

Replace `No material update` as a generic outcome with explicit states:

- `No priority advisory in reporting window` — authoritative source checked successfully and coverage complete.
- `No qualifying items found` — source checked, but content did not meet reporting criteria.
- `Coverage incomplete` — partial/truncated/parse-limited dataset.
- `Source stale`.
- `Source unavailable`.
- `Status unknown`.

A clean negative may be shown only when collection succeeded, expected content parsed, freshness is acceptable and coverage is complete.

### 3.2 Fortinet / Palo Alto / priority-vendor verification

- Verify whether current Fortinet, Palo Alto and other priority-vendor clean states represent genuine absence of qualifying advisories or a collection/mapping/health problem.
- Add regression coverage for authoritative-source naming, vendor mapping and status rendering.
- Maintain CrowdStrike as supporting-only until a stable public authoritative product/security-advisory path exists.

### 3.3 Partial-source propagation

- Apply `PARTIAL` metadata to collectors that can detect truncation or incomplete upstream datasets.
- Propagate incompleteness into vendor status and source-coverage presentation.

## Priority 4 — Sector relevance

Split broad sector buckets into more useful customer-impact categories.

### Retail

Cover:

- retailers;
- ecommerce/webshops;
- POS/payment environments;
- logistics dependencies;
- loyalty/customer platforms;
- store and warehouse operational technology where relevant.

### Housing Estates / BoligByggerlag

Cover:

- housing associations / cooperatives;
- property-management platforms;
- access-control/building systems;
- resident/customer portals;
- payment/finance integrations;
- managed infrastructure and third-party service dependencies.

### Energy

Treat Energy separately from Oil & Gas where useful. Include:

- electricity;
- grid;
- renewables;
- energy services;
- energy trading;
- OT/ICS/industrial systems;
- supporting digital infrastructure;
- Nordic energy-service organisations such as Veni Energy and comparable companies.

Retain dedicated Oil & Gas classification where sector-specific operational risk warrants it.

## Priority 5 — Source architecture phase 2

- Add GitHub Advisory Database pagination and explicit completeness/rate-limit handling.
- Use advisory `updated_at` semantics when a materially changed advisory would otherwise be missed by its original publication date.
- Enrich GHSA records with package/ecosystem, aliases and withdrawn state where useful.
- Mark GHSA collection `PARTIAL` when the available result set is known to be truncated or incomplete.
- Add a stronger authoritative CrowdStrike path if a stable public source becomes available.
- Add OSV asset-inventory enrichment once an approved package/SBOM inventory input exists.
- Continue moving source-specific definitions out of generic modules into focused source catalogues.

## Priority 6 — GRC & Standards redesign

- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative coverage for the EU, Norway, Sweden, Finland and Denmark.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Maintain a persistent governance horizon with verified dates and primary sources.

## Priority 7 — Reliability, security and CI integrity

- Fix regression-test discovery so `tests/tests/test_priority_vendor_sources.py` is executed by the standard `python -m unittest discover -s tests -v` CI command.
- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Add general first-seen / last-seen timestamps where they improve lifecycle analysis beyond the dedicated threat-actor state.
- Review `main` branch protection and require Repository CI before merge.
- Review repository visibility against the proprietary/confidential project posture.

## Priority 8 — Maintainability

- Fold the 5.6.5 report-policy compatibility layer into the main renderer during the next structural refactor.
- Continue extracting self-contained Daily presentation components where this materially improves testability.
- Keep source policy, evidence policy, presentation and orchestration boundaries explicit.

## Priority 9 — Historical capability

- Extend the opt-in private report archive with historical comparison and daily/weekly/monthly trend analysis.
- Reuse historical state for meaningful change detection rather than repeating unchanged intelligence.
- Avoid paid infrastructure unless operationally justified.

## Priority 10 — Threat-intelligence enrichment

- Continue adding trusted primary/deep-dive links.
- Strengthen source trust tiers and corroboration rules for attribution and exploitation claims.
- Correlate vendor advisories, NVD, KEV and primary research into one logical development.
- Represent uncertainty explicitly where exploitation or attribution is reported but not confirmed.

## 6.1.1 maintenance completion criteria

Version 6.1.1 is a maintenance-alignment release only. It is complete when:

- this backlog contains only genuinely open work;
- `docs/operations/CONTINUITY.md` reflects the 6.1.0 baseline and the 6.1.1 continuation point;
- stale 6.0.0 / proposed 6.0.1 continuation language is removed;
- no production Python behaviour is changed;
- repository compilation and regression tests pass unchanged;
- release documentation records the actual validation result.

The functional items above become implementation scope for the next version after 6.1.1 is validated.
