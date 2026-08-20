<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# SecurityIntelligenceBrief — Continuity Brief

**Prepared:** 20 August 2026 (Europe/Oslo)  
**Authoritative repository:** <https://github.com/Killeck/SecurityIntelligenceBrief>  
**Build base on `main`:** `f87a22fd9476425f3142f3631e3049ec43abc315`  
**Target release:** `6.1.2`

## Current continuation point

Version 6.1.2 is a focused Daily-report presentation release. It restores the
approved executive threat-header layout without reintroducing the obsolete
five-box active DEFCON scale.

After applying the 6.1.2 files:

- Overall Threat is a compact active colour-coded box on the left.
- A text-only DEFCON 1–5 explanatory legend is right-aligned on the same row.
- The current level is marked once in the legend.
- The five operational metric cards remain on the row below.
- The large `rendering.py` layout is not structurally refactored; the change is
  contained inside `rendering_components.py`.

## Product and security boundaries

SecurityIntelligenceBrief is a Python/GitHub Actions pipeline producing:

- **Daily Security Brief** — immediate developments, exposure and actions.
- **Weekly Vulnerability Report** — CVE-led remediation priority, lifecycle
  changes and month-to-date vulnerability reporting.

It uses public and authorised sources only. It must not collect directly from
onion services, criminal forums, ransomware leak sites, stolen-data repositories
or illicit marketplaces. Runtime intelligence is deterministic; no LLM is
required.

## Source and evidence baseline

Version 6.1.0 introduced GitHub Advisory Database corroboration, declarative
priority-vendor evidence coverage and explicit `PARTIAL` source-health handling.
The 6.0.0 baseline already supplied persistent NVD caching, source overlays,
Daily duplicate suppression, bounded detail collection, runtime profiling and
explicit confidence/corroboration.

Health states include `CONTENT`, `QUIET`, `PARTIAL`, `STALE`, `DEGRADED` and
`FAILED`. Failed, stale, missing or confirmed-incomplete authoritative coverage
must never be presented as a clean negative.

CrowdStrike remains supporting-only until a stable public authoritative
product/security-advisory path is available.

## Daily report behaviour to preserve

- Scheduled 06:17 Europe/Oslo; Monday 72-hour window, otherwise 36 hours.
- Continues through individual-source failure.
- Seven-day duplicate suppression by default while retaining materially changed advisories.
- Conservative enterprise DEFCON logic.
- One active colour-coded Overall Threat indicator.
- Text-only DEFCON 1–5 explanatory legend beside Overall Threat.
- Explicit confidence and corroborating-source counts for material vulnerability claims.
- Health-aware vendor truth.
- Gmail API OAuth delivery.

## Weekly report behaviour to preserve

- Scheduled Monday 07:23 Europe/Oslo.
- Uses the shared primary collection pipeline.
- Internal priority score remains non-user-facing.
- Complete CVE identifiers link to NVD; vendor-advisory links remain available.
- SQLite lifecycle history persists descriptive context, confidence and corroboration.
- Outlook-safe table layout remains unchanged by 6.1.2.

## Validation state for 6.1.2

Completed in the build package:

- changed Python files syntax-compile successfully;
- isolated functional rendering test passes;
- layout check confirms the outer executive row is 20% Overall Threat / 80%
  right-hand legend area;
- the legend panel remains capped at 400px;
- the existing nested Overall Threat `width="100%"` boundary is retained so the
  current smoke-test assumption is not unnecessarily broken.

Required after upload:

1. Run Repository CI:
   `PYTHONPATH=src python -m unittest discover -s tests -v`
2. Confirm the full discoverable suite passes.
3. Run **Test Daily Security Brief**.
4. Visually confirm the email matches the approved reference:
   Overall Threat left, DEFCON legend right, five metric tiles below.
5. Confirm no duplicate five-box active DEFCON scale appears.

Do not mark 6.1.2 production-complete until steps 1–5 pass.

## Known CI backlog

`tests/tests/test_priority_vendor_sources.py` is not reached by the standard
unittest discovery command. This remains an open maintenance item and is not
silently claimed as fixed by 6.1.2.

## Pull request #5

PR #5 (`agent/v6-0-0-report-balance`) must not be merged wholesale. Its DEFCON
presentation intent is superseded by the focused 6.1.2 implementation. Other
useful functional changes, including customer-sector mappings, should be
selectively compared with current code before porting.

## Next functional release

After 6.1.2 is validated, continue with:

1. Critical Vulnerabilities / Zero-days TL;DR cleanup.
2. Rolling 90-day Active Exploitation / Threat Actor Activity state.
3. AI Security & Trustworthiness reporting.
4. Fortinet/Palo Alto and general clean-negative source-truth corrections.
5. Retail, Housing Estates/BoligByggerlag and Nordic Energy sector expansion.
6. Holistic CISO Watch Next / Security Advisory 24/72-hour grouping.
7. Priority-vendor regression-test discovery correction.
8. GRIT public research source evaluation.

## Engineering discipline

- Use a feature branch for functional work.
- `VERSION` is the runtime version source of truth.
- `README.md` describes current behaviour.
- `CHANGELOG.md` records completed releases.
- `MAINTENANCE.md` contains open work only.
- Repository CI and live Gmail delivery are separate validation gates.
