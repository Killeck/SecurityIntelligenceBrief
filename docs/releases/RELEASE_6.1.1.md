# Release 6.1.1

**Release date:** 2026-08-20  
**Base release:** 6.1.0  
**Type:** Documentation / maintenance alignment  
**Status:** Validation candidate

## Purpose

Version 6.1.1 reconciles project maintenance and continuity documentation with the actual 6.0.0 and 6.1.0 code baselines. It intentionally introduces no production Python behaviour changes.

## Changes

- Rebuilt `MAINTENANCE.md` so it contains open work only.
- Removed already-delivered 6.0.0/6.1.0 capabilities from future-work wording.
- Added the agreed Daily Brief intelligence-quality backlog:
  - text-only DEFCON legend restoration;
  - Critical Vulnerabilities / Zero-days TL;DR cleanup;
  - rolling 90-day Active Exploitation / Threat Actor Activity;
  - dedicated AI Security & Trustworthiness reporting;
  - vendor/source clean-negative truth corrections;
  - Retail, Housing Estates/BoligByggerlag and Energy sector expansion;
  - holistic CISO Watch Next / Security Advisory 24/72-hour grouping.
- Added known CI discovery repair for the nested priority-vendor test module.
- Updated `docs/operations/CONTINUITY.md` from the stale 6.0.0 continuation point to the 6.1.0 main baseline.
- Marked PR #5 as selective-port/supersession work rather than a merge candidate.

## Validation

- Documentation consistency checks: pending.
- Python compilation: pending repository execution.
- Repository regression suite: pending repository execution.
- Repository CI: pending after branch publication.
- Live Daily/Weekly Gmail delivery: not required for a documentation-only release unless repository policy requires it.

## Production gate

Do not mark 6.1.1 complete until the unchanged codebase compiles and the repository regression suite passes on the 6.1.1 branch.
