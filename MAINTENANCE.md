# Maintenance priorities

## Release discipline

Every functional or presentation update must include, as applicable:

- Increment `VERSION` using semantic-style versioning.
- Add a dated entry to `CHANGELOG.md` describing added, changed and fixed
  behaviour.
- Update `README.md` when features, layout, operation, configuration or
  repository structure changes.
- Update `MAINTENANCE.md` to close completed work and capture follow-up work.
- Update focused operating documents such as
  `WEEKLY_VULNERABILITY_REPORT.md` when their report or workflow changes.
- Add or update regression tests and record the validation result in the
  changelog.
- Format every update commit message as `<VERSION> - <short comment>`.
- Commit the implementation, tests, version and documentation together unless
  a version-only release is explicitly intended.

## Completed in 5.6.3

- Fixed the embedded DEFCON pyramid display height at 91 pixels.
- Aligned five non-wrapping description rows at 18 pixels each with the five
  pyramid layers.
- Shortened legend descriptions to retain readable one-line alignment inside
  the compact 400-pixel panel.

## Completed in 5.6.2

- Reduced the DEFCON legend panel width by approximately 30%, from 570 to 400
  pixels.
- Moved reporting-window, source-count and `VERSION` metadata to the top-right
  of the daily header.
- Preserved the existing logo and compact embedded DEFCON asset.

## Completed in 5.6.1

- Replaced the character-based DEFCON approximation with a compact embedded
  solid-layer pyramid containing labels inside each level.
- Moved the legend below the report metadata and right-aligned it beside the
  bottom-aligned 20% Overall Threat box.
- Centered the compact numeric threat level and status without a redundant
  icon or `DEFCON` prefix.
- Isolated the five supporting metrics in their own fixed-layout table to
  prevent email-client column collapse.
- Preserved `VERSION` as the single runtime source of truth and left the
  existing logo unchanged.

## Completed in 5.6.0

- Introduced the Weekly Vulnerability Report and month-to-date overview.
- Added persistent vulnerability lifecycle tracking through SQLite and the
  GitHub Actions cache.
- Corrected weekly NVD limits and upgraded lifecycle cache actions for Node.js
  24 runners.
- Reworked the top layout with a compact top-right layered DEFCON legend.
- Separated DEFCON descriptions from the pyramid layers.
- Moved Overall Threat to a shallow full-width row and balanced the remaining
  five metrics.
- Added ranked, linked KEV and priority-vendor status cards.

## Current priorities

- Restore and protect core functionality
  - Add live parser-health and source-freshness monitoring.
  - Detect failed requests.
  - Detect successful responses with no usable records.
  - Detect stale feeds.
  - Detect broken HTML selectors.
  - Report source-health changes between runs.
- **Improve security and report reliability**
  - Pin Python dependencies with hashes.
  - Generate a machine-readable CycloneDX or SPDX SBOM.
  - Add persistent state and cross-run deduplication.
  - Prevent repeated advisories across overlapping reporting windows.
  - Retain meaningful updates to previously reported stories.
  - Track first-seen and last-seen timestamps.
- **Improve maintainability**
  - Externalise frequently changed source definitions and relevance rules.
  - Externalise source URLs.
  - Externalise selectors.
  - Externalise keywords.
  - Externalise vendor priorities.
  - Externalise sector mappings.
  - Externalise source limits.
- **Add historical capability**
  - Add private report archiving and historical comparison.
  - Store generated HTML or structured JSON.
  - Compare daily, weekly and monthly trends.
  - Avoid introducing paid infrastructure.
- **Threat intelligence**
  - Continue expanding source-specific deep-dive links where a trusted
    destination is available.
