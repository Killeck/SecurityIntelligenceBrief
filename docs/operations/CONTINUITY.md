<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# SecurityIntelligenceBrief — Continuity Brief

**Prepared:** 20 August 2026 (Europe/Oslo)
**Authoritative repository:** <https://github.com/Killeck/SecurityIntelligenceBrief>
**Baseline on `main`:** `d437565` — release `6.0.0` (18 August 2026)

## Purpose and evidence

This document is the durable development handoff for the
SecurityIntelligenceBrief work. The repository, its documentation, open pull
request and GitHub Actions history are its evidence base. Update it whenever a
material project decision would otherwise exist only in a chat.

## Product purpose and non-negotiable boundaries

SecurityIntelligenceBrief is a Python and GitHub Actions intelligence pipeline
that emails two reports to security advisors, SOC functions, security
architects and CISOs:

- **Daily Security Brief:** time-sensitive developments, exposure and actions.
- **Weekly Vulnerability Report:** CVE-led remediation priority, lifecycle
  changes and month-to-date vulnerability reporting.

It intentionally uses only public and authorised sources. It must **not** be
extended to collect from onion services, criminal forums, ransomware leak sites,
stolen-data repositories or illicit marketplaces. Runtime intelligence is
deterministic; no LLM is required.

## Architecture and boundaries

```text
Authoritative advisories + vendor bulletins + research/news/discovery
                              |
                    bounded parallel collection
                              |
            normalisation, deduplication and source health
                              |
             NVD CVSS / FIRST EPSS + persistent NVD cache
                              |
           deterministic analysis, policy and correlation
                    /                         \\
        Daily Security Brief       Weekly Vulnerability Report
                    \                         /
                       Gmail API OAuth delivery
```

The primary orchestration is in `src/security_brief/app.py` (`primary_tasks()`
is shared); `src/security_brief/weekly_app.py` builds the weekly report.

- Collection: `collectors.py`, `sources.py`, `priority_vendor_sources.py`.
- State/configuration: `source_config.py`, `source_health.py`, `nvd_cache.py`,
  `dedup_state.py`, `runtime_profile.py`.
- Analysis/policy: `analysis.py`, `evidence.py`, `report_policy.py`, `rules.py`.
- Presentation/delivery: `rendering.py`, `rendering_components.py`,
  `weekly_rendering.py`, `delivery.py`.
- Weekly prioritisation/history: `vulnerability_reporting.py` and SQLite.

## Source, evidence and health policy

Authoritative priority-vendor coverage includes CISA KEV; Microsoft MSRC;
Fortinet PSIRT; AWS Security Bulletins; Google Cloud Security Bulletins; Chrome
Releases; Palo Alto Networks Security Advisories; HPE/Aruba's structured
bulletin adapter; Okta Security Advisories; Apple Security Releases; Cisco
Security Advisories; and vendor-specific NVD corroboration/fallback. Research
and news sources provide context rather than authoritative vulnerability facts.

- Tier A: government catalogues, vendor PSIRT/security bulletins and
  standards/regulatory authorities.
- Tier B: recognised primary research.
- Tier C: trusted reporting, for discovery/corroboration only.
- Tier D: discovery signals, visibly labelled and unable to establish a
  confirmed organisational incident independently.

Health states are `CONTENT`, `QUIET`, `DEGRADED`, `STALE`, `PARTIAL` and
`FAILED`. An unavailable, stale or partial authoritative source must never be
shown as a clean “no material update”. Source-specific freshness and persistent
cross-run health state are deliberate safeguards.

## Report behaviour that must be retained

### Daily report

- Scheduled 06:17 Europe/Oslo; Monday window is 72 hours, otherwise 36 hours.
- Continues through individual-source failure.
- Separates primary advisories from secondary discovery reporting.
- Cross-run duplicate suppression is seven days by default; material changes in
  severity, exploitation, summary or action remain reportable.
- Uses conservative enterprise DEFCON-style logic. The header has one
  colour-coded Overall Threat status and a **text-only** DEFCON 1–5 guide; do
  not reintroduce duplicate coloured DEFCON boxes/legends.
- Displays explicit confidence and corroborating-source count for material
  claims.
- Customer-impact mappings include finance, healthcare, public sector, retail,
  hospitality, research, managed services and dedicated **BoligByggerlag**,
  **Energy**, **Oppdrett** and **Transportation** segments.

### Weekly report

- Scheduled Monday 07:23 Europe/Oslo; title/subject use ISO week and year.
- Uses the shared primary collection pipeline, then ranks CVEs using an internal
  0–100 score combining CVSS, exploitation, KEV, EPSS, exposure/vendor
  relevance, ransomware association and age.
- The internal priority number is not user-facing. Display CVSS, EPSS, KEV,
  exploitation state and remediation band instead.
- Order: zero-days, CVSS 10.0, unscored CVEs, then remaining findings by CVSS;
  omit CVSS below 4.0. Critical/exploited records survive normal item caps.
- Every full CVE identifier links directly to NVD; retain vendor-advisory links.
- The Outlook-safe main table uses widths: CVE 13%, vulnerability details 34%,
  vendor 10%, CVSS 7%, EPSS 7%, KEV 7%, exploited 8%, action 14%.
- Details remain concise: `Nature`, `Impact area`, `Evidence`. Lifecycle
  changes also carry short nature/impact context.
- SQLite lifecycle history at `data/vulnerability_history.sqlite3` preserves
  descriptive summary, confidence and corroboration count, and is restored via
  Actions cache.

## Operations and configuration

GitHub Actions are the production runtime:

- `daily-security-brief.yml` and `weekly-vulnerability-report.yml` run tests
  before sending and persist `.state`; daily state includes deduplication and
  NVD cache, while weekly state also includes SQLite history.
- `repository-ci.yml` compiles and runs the Python 3.12 regression suite for
  `main`, `agent/**` and pull requests.
- `test-security-brief.yml` is the manual Daily live-delivery workflow.

Required secrets: `GMAIL_USERNAME`, `GMAIL_CLIENT_ID`,
`GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN`, `EMAIL_TO`. Optional secrets:
`NVD_API_KEY`, `HIBP_API_KEY`, `MONITORED_DOMAINS`, `MONITORED_BRANDS`.
Delivery is Gmail API OAuth only; old SMTP/app-password paths are not required.
Workflows must log only safe OAuth-refresh/API-acceptance milestones.

`VERSION` is the single runtime version source. `config/sources.json` supports
validated source overlays. `config/upcoming_governance.json` is the persistent
forward-governance horizon; keep only verified primary-source dates.

## Immediate continuation point — draft PR #5

**PR:** [#5 — 6.0.0 - rebalance reports and customer segments](https://github.com/Killeck/SecurityIntelligenceBrief/pull/5)
**Branch:** `agent/v6-0-0-report-balance` → `main`
**Status at assessment:** Draft, mergeable, no open issues, and both Repository
CI checks passed on 20 August 2026. Manual Daily and Weekly runs on that branch
also succeeded.

This PR is not yet part of `main`. It restores the Daily text-only Enterprise
DEFCON guide; makes Weekly vulnerability prose more compact and lifecycle
changes more contextual; adds BoligByggerlag, Energy, Oppdrett and
Transportation customer-impact mappings; and updates the 6.0.0 release
documentation and manifest. It reports 75/75 local regression tests passed.

Before merge, conduct the intended quality review and inspect live reports if
presentation approval is needed. Mark the PR ready and merge only with explicit
approval. Reconcile release status after production verification rather than
claiming completion prematurely.

## Open backlog, in priority order

1. **Source-health phase 2:** establish a stable public authoritative
   CrowdStrike advisory source if available; preserve conservative semantics for
   incomplete coverage.
2. **GRC & Standards redesign:** direct deep links, expanded EU/Nordic
   authority coverage, NIS2/DORA/EU AI Act/Cyber Resilience Act/national
   implementation coverage, broader relevant ISO/IEC coverage, and a durable
   governance horizon.
3. **Reliability/security:** dependency hashes, CycloneDX or SPDX SBOM,
   first-seen and last-seen timestamps.
4. **Maintainability:** reduce source-specific generic-module logic, fold the
   5.6.5 compatibility layer into the renderer during a structural refactor,
   and extract testable Daily-rendering components where useful.
5. **Historical capability:** expand the opt-in private archive into daily,
   weekly and monthly comparison/trend analysis without paid infrastructure
   unless justified.
6. **Threat-intelligence enrichment:** additional trusted deep links, stronger
   trust/corroboration rules and correlation of vendor, NVD, KEV and research
   into one development.

The proposed experimental `6.0.1` branch is `feature/v6.0.1-report-enrichment`.
Do not change `VERSION` merely to create/evaluate it. Its five gated ideas are:
per-claim corroboration/confidence; asset/technology relevance; a concise SOC
action line per top item; clear new/changed/repeated state; and explicit
uncertainty for unconfirmed exploitation/attribution.

## Engineering and release discipline

- Keep `README.md` as current behaviour, `CHANGELOG.md` as completed releases,
  `MAINTENANCE.md` as open work, and operation/architecture notes under `docs/`.
- Every functional/presentation release increments `VERSION`, updates the
  changelog/current docs/tests, removes completed backlog items, records actual
  validation, and uses commit form `<VERSION> - <short comment>`.
- Test with `PYTHONPATH=src python -m unittest discover -s tests -v`; CI also
  runs `python -m compileall -q src tests`.
- Treat workflow checks and live Gmail delivery as distinct: passing tests do
  not prove production email rendering/delivery.
- Dependencies are presently bounded by major version but not hash-pinned;
  this is known planned work, not an accidental omission.

## Canonical reading order

1. This handoff and `MAINTENANCE.md`.
2. The current `README.md` and `docs/architecture/OPTIMISATION.md`.
3. The open PR #5 and its workflow results.
4. `app.py`, `weekly_app.py`, `report_policy.py`, `vulnerability_reporting.py`
   and their focused tests before changing collection or report policy.
