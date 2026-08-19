# Release 6.0.0

**Release date:** 2026-08-18  
**Base release:** 5.7.0  
**Status:** Production release candidate

## Purpose

Version 6.0.0 is a major report-clarity update. It reduces duplicated threat-status presentation in the Daily Security Brief and makes the Weekly Vulnerability Report materially more useful by explaining what each vulnerability is, what it affects and where to investigate it.

## Release changes

- Removed the five-box DEFCON 1–5 strip and obsolete duplicate legend from the Daily Security Brief.
- Retained one concise, colour-coded Overall Threat status.
- Added a dedicated Weekly Vulnerability details column.
- Added the advisory title, descriptive source summary and affected scope to each displayed weekly CVE.
- Rebalanced Outlook-safe weekly table widths to prioritise explanatory content.
- Preserved descriptive summaries in the SQLite vulnerability lifecycle history.
- Added automatic migration for existing weekly history databases.
- Added stage-level runtime profiling for Daily and Weekly execution.
- Added persistent, TTL-bound NVD enrichment caching.
- Bounded HTML detail-page fetching independently of index candidate limits.
- Added validated source-definition overlays through `config/sources.json`.
- Added persistent Daily duplicate suppression while retaining material updates.
- Added explicit authoritative/corroborated/single-source confidence and source counts.
- Extracted the Overall Threat component and operational state services behind focused module boundaries.
- Rebalanced Weekly section 1 to concise Nature, Impact area and Evidence text and enriched section 3 lifecycle changes with vulnerability context.
- Restored a text-only DEFCON 1–5 guide in the Daily report without coloured level boxes.
- Added BoligByggerlag, Energy, Oppdrett and Transportation customer-impact mappings.
- Retained direct NVD CVE links, vendor-advisory links, CVSS, EPSS, KEV, exploitation state and remediation bands.
- Updated release, current-state, operational and architecture documentation for 6.0.0.

## Validation

- Local regression suite: **75/75 tests passed** after final report-balance validation.
- GitHub Python 3.12 regression suite: **passed** on the v6.0.0 branch.
- Final repository CI must pass on the completed release commit and pull request.
- Gmail production credentials remain outside the repository.
- Daily and weekly live delivery should be confirmed through their manual workflows before final production certification.

## Production gate

Do not certify 6.0.0 for production until:

1. Repository CI passes on the completed v6.0.0 branch.
2. Repository CI passes on the release pull request.
3. Manual Daily Security Brief and Weekly Vulnerability Report workflows complete successfully using the configured Gmail OAuth credentials.
4. Received daily and weekly emails are visually checked for rendering regressions and the expanded vulnerability text is confirmed readable.
