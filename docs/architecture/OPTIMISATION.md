<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Architecture and Optimisation Notes — 6.1.3

## Design goals

6.1.3 improves truthfulness and historical context without widening the entire
Daily report into a 90-day news digest.

## Daily time model

Three windows are deliberately separated:

1. **Nominal Daily window** — 36 hours Tue–Sun / 72 hours Monday.
2. **Catch-up window** — expands from last successful delivery after a failed run,
   with six-hour overlap and seven-day maximum.
3. **Vendor/threat context** — up to 90 days for authoritative vendor status and
   selected high-value research context.

Only items inside the effective Daily/catch-up window become current Daily report
items. Longer context is used for truthful status and historical activity.

## Source-health model

A source may be:

- CONTENT
- QUIET
- PARTIAL
- DEGRADED
- STALE
- FAILED

6.1.3 removes age-only stale inference for successfully checked low-frequency
sources. Parser/transport failure remains a health problem; publishing cadence does not.

## Resilient source adapters

`source_resilience.py` handles page families that historically changed selectors.
Claroty Team82 uses the structured disclosure dashboard instead of the broad
research landing page.

`config/sources.json` holds release-time URL/selector/freshness overrides so
future page changes can often be corrected without editing the source catalogue.

## Daily Priority-1 presentation

`report_policy.py` remains the compatibility policy boundary around the large
Daily renderer.

6.1.3 uses it to:

- normalise TL;DR output;
- provide vendor truth;
- inject rolling threat-activity history;
- inject the decision-oriented Watch Next model.

A future structural refactor should move these hooks into first-class renderer
components and remove monkey-patching.

## Weekly history model

The existing SQLite lifecycle database remains authoritative.

`weekly_trends.py` performs rolling 13-week aggregation. Each CVE is counted once
using first-observed lifecycle history. The Zero-Day series is additional to the
CVSS severity series.

This approach avoids counting the same persistent CVE every week and produces a
trend of newly observed vulnerability pressure rather than inventory size.

## Email-safe graph

The quarterly trend uses nested HTML presentation tables rather than JavaScript,
SVG or externally hosted chart images. Each weekly cell contains a count and a
proportional colour bar. This is intentionally conservative for Outlook/email
client compatibility.

## CI

The nested priority-vendor tests are promoted to the top-level `tests` directory
so standard unittest discovery covers the authoritative source architecture.
