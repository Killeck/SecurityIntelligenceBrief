# Release 5.7.0

**Release date:** 2026-08-18  
**Base release:** 5.6.8  
**Status:** Production release candidate

## Purpose

Version 5.7.0 strengthens source-health truth, authoritative vendor coverage, report usability and private historical retention without changing the deterministic, no-paid-LLM runtime model.

## Release changes

- Authoritative Cisco Security Advisories coverage.
- Source-specific freshness thresholds.
- HTML selector-health failure detection.
- Persistent stale and partial source-health handling.
- Health-aware Cisco clean-negative reporting.
- `5. GRC & Standards` presentation.
- Two-column Source Coverage ordered by health state.
- `Operational Intelligence & Impact` divider.
- Optional private report archive through `REPORT_ARCHIVE_DIR`.
- Independent repository CI workflow for pull requests, release branches and `main`.
- Release metadata and current-state documentation normalised to 5.7.0.

## Validation

- Baseline before release normalisation: **67/67 regression tests passed**.
- Production release candidate: **67/67 regression tests passed**.
- Python source/test compile validation: **passed**.
- Gmail API production credentials are not stored in the repository.
- Live Gmail delivery must be confirmed through `Test Daily Security Brief` after the release branch is pushed.

## Production gate

Do not merge this release into `main` until:

1. Repository CI passes on `agent/v5-7-0-production`.
2. Repository CI passes on the pull request.
3. The manual `Test Daily Security Brief` workflow successfully refreshes the configured Gmail OAuth credential and Gmail accepts the generated message for delivery.
4. The received report is visually checked for major rendering regressions.

Once these gates pass, 5.7.0 becomes the production baseline for the planned 6.0.0 optimisation release.
