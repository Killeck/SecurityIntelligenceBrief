<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# SecurityIntelligenceBrief — Continuity Brief

**Prepared:** 21 August 2026 (Europe/Oslo)  
**Repository:** `Killeck/SecurityIntelligenceBrief`  
**Build base inspected:** `2fc9f2691d5698aa82f1525dcb4618682dbb5d36`  
**Target release:** `6.1.3`

## Continuation point

6.1.3 is a combined intelligence-quality and Weekly reporting release.

The 6.1.2 DEFCON restoration remains intact.

### Daily implemented

- bounded catch-up from last successful Daily delivery;
- 90-day priority-vendor context separate from reader-facing Daily content;
- source-health/current-window/latest-material vendor truth;
- HPE and Aruba separate status cards;
- resilient source paths for the reported problem sources;
- TL;DR normalisation;
- rolling 90-day actor/campaign activity;
- grouped 24/72h CISO Watch Next.

### Weekly implemented

- Top Vulnerabilities of the Week;
- vendor + vulnerability-class grouping in section 3;
- four remediation bands with vendor-first CVE grouping in section 4;
- 13-week Zero-Day/Critical/High/Medium graphical trend;
- four-week direction and quarter insight;
- A Month in the Rearview limited to 20 entities.

## Persistent state

Daily workflow `.state` now includes:

- `pipeline_state.json` — last successful Daily delivery;
- `threat_activity.json` — rolling 90-day actor/campaign state;
- existing NVD cache, dedup state, source health and runtime profile.

Weekly state retains:

- `data/vulnerability_history.sqlite3`;
- `.state`.

No new paid infrastructure is required.

## Important source policy

Source health and content age are different concepts. A successfully checked
low-frequency publisher is not stale merely because it has not published
recently.

A clean current-window vendor state is only valid when the expected
authoritative source was successfully checked. The status should still show the
latest retained material advisory when one exists.

## CI note

Upload `tests/test_priority_vendor_sources.py` to the top-level tests directory.
After confirming it is discovered by CI, delete the old nested
`tests/tests/test_priority_vendor_sources.py`.

## Production gate

Run Repository CI, Daily manual delivery and Weekly manual delivery before
promoting the release. Pay particular attention to the source-status cards and
the Weekly trend rendering.

## Next open work

See `MAINTENANCE.md`. AI Security & Trustworthiness is the highest-priority
remaining functional intelligence enhancement after 6.1.3 validation.
