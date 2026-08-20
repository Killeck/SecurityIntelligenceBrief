<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# SecurityIntelligenceBrief — Continuity Brief

**Prepared:** 20 August 2026 (Europe/Oslo)  
**Authoritative repository:** <https://github.com/Killeck/SecurityIntelligenceBrief>  
**Baseline on `main`:** `66aa0e46c88e9db9b40c3d52ecbfe19d781d6450` — release `6.1.0` (20 August 2026)

## Purpose and evidence

This document is the durable development handoff for SecurityIntelligenceBrief. The repository, release documentation, pull requests and GitHub Actions history are the evidence base. Update this document whenever a material project decision would otherwise exist only in a chat.

## Current release state

Version 6.1.0 is the current code baseline. It introduced:

- GitHub Advisory Database collection as open-source vulnerability corroboration;
- declarative priority-vendor evidence coverage;
- explicit `PARTIAL` handling for successful but incomplete collection;
- a formal distinction between authoritative and supporting vendor evidence.

The 6.0.0 baseline beneath it already introduced persistent NVD caching, source overlays, Daily duplicate suppression, bounded detail collection, stage profiling, explicit confidence and corroborating-source counts, expanded Weekly vulnerability details and modular maintenance/report components.

## Product boundaries

SecurityIntelligenceBrief is a Python/GitHub Actions intelligence pipeline producing:

- **Daily Security Brief** — time-sensitive developments, exposure and actions.
- **Weekly Vulnerability Report** — CVE-led remediation priority, lifecycle changes and month-to-date vulnerability reporting.

It uses public and authorised sources only. It must not collect directly from onion services, criminal forums, ransomware leak sites, stolen-data repositories or illicit marketplaces. Runtime intelligence is deterministic; no LLM is required.

## Source and evidence architecture

Primary source policy is separated from corroboration:

- CISA KEV and vendor PSIRT/security bulletins provide authoritative vulnerability evidence.
- NVD and GitHub Advisory Database provide structured corroboration/fallback according to evidence rules.
- recognised primary research provides context and supporting evidence.
- trusted reporting/discovery sources cannot independently establish authoritative vulnerability status.

Health states include `CONTENT`, `QUIET`, `PARTIAL`, `STALE`, `DEGRADED` and `FAILED`. Failed, stale, missing or confirmed-incomplete authoritative coverage must never be presented as a clean negative.

CrowdStrike remains supporting-only until a stable public authoritative product/security-advisory path is available.

## Daily report behaviour to preserve

- Scheduled 06:17 Europe/Oslo; Monday reporting window 72 hours, otherwise 36 hours.
- Continues through individual-source failure.
- Seven-day duplicate suppression by default while retaining materially changed advisories.
- Conservative enterprise DEFCON logic.
- One active colour-coded Overall Threat status.
- Explicit confidence and corroborating-source counts for material vulnerability claims.
- Health-aware vendor truth.
- Gmail API OAuth delivery.

The following are **open**, not current-state behaviour, and are tracked in `MAINTENANCE.md`:

- restore the text-only DEFCON 1–5 legend on the Overall Threat row;
- clean TL;DR source/Markdown artefacts;
- create a rolling 90-day Active Exploitation / Threat Actor Activity view;
- add AI Security & Trustworthiness as a dedicated reporting point;
- redesign CISO Watch Next / Security Advisory into grouped 24/72-hour developments;
- improve Retail, Housing Estates/BoligByggerlag and Energy sector classification;
- correct ambiguous vendor clean-negative presentation.

## Weekly report behaviour to preserve

- Scheduled Monday 07:23 Europe/Oslo.
- Uses the shared primary collection pipeline.
- Prioritises zero-days, exploitation, KEV, CVSS, EPSS, vendor/exposure relevance and age.
- Internal priority score remains non-user-facing.
- Every full CVE identifier links to NVD; vendor-advisory links remain available.
- SQLite lifecycle history persists descriptive context, confidence and corroboration.
- Outlook-safe table layout is retained.

## CI and validation

Repository CI uses Python 3.12 and runs compilation plus:

`PYTHONPATH=src python -m unittest discover -s tests -v`

The 6.1.0 PR head passed Repository CI with 76 tests. A known test-discovery defect remains: `tests/tests/test_priority_vendor_sources.py` is not reached by the standard discovery command and must be corrected in the next functional release.

Live Daily and Weekly Gmail delivery remain distinct from code regression validation.

## Pull request #5

PR #5 (`agent/v6-0-0-report-balance`) is an old draft based on the 6.0.0 line and must not be merged wholesale into 6.1.x.

Potentially useful functional changes—DEFCON explanatory presentation, customer-impact mappings and compact Weekly prose—should be selectively reimplemented or ported into the next functional version only after comparison with the current 6.1.0 code. Obsolete 6.0.0 release metadata must not be imported.

After relevant functionality is either ported or explicitly superseded, close PR #5.

## 6.1.1 purpose

Version 6.1.1 is a **documentation and maintenance-alignment release**.

Its purpose is to:

- reconcile `MAINTENANCE.md` with functionality already delivered by 6.0.0 and 6.1.0;
- remove completed work from the open backlog;
- replace stale proposed-6.0.1 continuation language with the current roadmap;
- align this continuity brief to the 6.1.0 main baseline;
- record the exact functional scope intended for the next release;
- make no production Python behaviour changes.

## Next functional release scope

After 6.1.1 validation, the next version should implement the highest-value Daily Brief intelligence-quality work:

1. DEFCON text legend restoration.
2. TL;DR formatting cleanup.
3. Rolling 90-day threat-actor/activity state with last-seen and days-ago.
4. AI Security & Trustworthiness section.
5. Vendor/source truth corrections, including Fortinet/Palo Alto verification.
6. Retail, Housing Estates/BoligByggerlag and Nordic Energy sector expansion.
7. Holistic CISO Watch Next / Security Advisory 24/72-hour grouping.
8. Priority-vendor regression-test discovery correction.
9. Selective reconciliation and closure/supersession of PR #5.

The exact version number should be assigned only when that functional implementation starts.

## Engineering discipline

- Never write functional release work directly to `main`; use a feature branch and PR.
- `VERSION` is the runtime version source of truth.
- `README.md` describes current behaviour.
- `CHANGELOG.md` records completed releases.
- `MAINTENANCE.md` contains open work only.
- Run compilation and the complete discoverable test suite before merge.
- Treat Repository CI and live Gmail delivery as separate validation gates.
- Do not claim a production delivery gate passed without evidence from the corresponding workflow.
