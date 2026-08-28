# Release 6.1.3

**Release date:** 2026-08-21  
**Base:** 6.1.2 + Weekly renderer hotfix on current `main`  
**Type:** Intelligence quality / source truth / Weekly reporting enhancement  
**Status:** Validation candidate

## Purpose

6.1.3 fixes the Daily source-truth problem that made active vendor and research
sources appear empty or misleadingly show `No material update`, completes the
former Priority 1 Daily backlog, and expands the Weekly Vulnerability Report
into a more useful weekly/monthly/quarterly management view.

## Daily changes

### Source truth

The report now separates:

- source/collector health;
- priority findings inside the effective Daily reporting window;
- latest material vendor advisory retained in a 90-day context window.

A source that is checked successfully but has no current priority advisory no
longer implies that the vendor has no important vulnerabilities.

HPE and Aruba are represented separately in vendor-status presentation.

### Failed-run catch-up

`.state/pipeline_state.json` stores the last successful Daily delivery. If a
Daily run fails, the next successful attempt expands the collection window from
the last successful delivery with a six-hour overlap, bounded to seven days.

### Historically problematic sources

6.1.3 adds configuration/adapters for:

- BankInfoSecurity — first-party RSS override;
- Claroty Team82 — structured vulnerability disclosure dashboard;
- Dragos — resilient HTML fallback;
- FBI Cyber News — low-frequency source treated as healthy when successfully checked;
- ISACA News and Trends — resilient selectors;
- ISO News — tighter security/AI/risk topic filtering;
- NIST CSRC News — resilient selectors and longer cadence tolerance;
- Nozomi Networks Labs — resilient selectors;
- Splunk Security Blog — resilient selectors.

### Priority 1 complete

- TL;DR Markdown/hash artefact normalisation.
- Persistent rolling 90-day threat-actor/campaign activity with last observed,
  days ago, confidence and evidence.
- Decision-oriented CISO Watch Next:
  - Next 24h — action and verification;
  - Next 72h — emerging developments and monitoring;
  - Development;
  - Evidence;
  - Enterprise relevance;
  - Sector relevance;
  - What to watch next;
  - Recommended action.

## Weekly changes

### Top Vulnerabilities of the Week

Adds an evidence-first ranked view of the week's most important vulnerabilities.

### 3. Exploitation, KEV & EPSS Changes

Lifecycle changes are grouped:

`Vendor → Vulnerability class/type → CVE/change`

### 4. Remediation Priority

The four established remediation bands are retained:

1. Patch immediately
2. Patch within 7 days
3. Validate exposure
4. Monitor

Within each band:

`Vendor → CVE → vulnerability class → advisory`

### Quarterly Vulnerability Trend — Rolling 13 Weeks

Adds an email-safe graphical trend view for:

- Zero-Day
- Critical
- High
- Medium

Low/Informational are intentionally excluded.

The trend engine uses the SQLite lifecycle database and counts each CVE once in
the week it was first observed. Zero-Day is a separate additional series and may
overlap the CVSS severity series.

Management insight includes:

- current four-week direction;
- latest four weeks versus previous four;
- quarter totals;
- peak week;
- material vendor/technology concentration.

### A Month in the Rearview

Adds the 20 most prominent month-to-date vulnerability entities, ranked by
zero-day/exploitation/KEV status, remediation urgency, CVSS and EPSS rather than
publication date alone.

## CI correction

The priority-vendor test module is supplied at:

`tests/test_priority_vendor_sources.py`

This fixes the earlier nested-test discovery gap under the repository's standard:

`python -m unittest discover -s tests -v`

The old nested copy should be deleted after the root-level file is uploaded to
avoid duplicate maintenance.

## Files introduced

- `src/security_brief/pipeline_state.py`
- `src/security_brief/source_resilience.py`
- `src/security_brief/threat_activity.py`
- `src/security_brief/weekly_trends.py`
- `tests/test_v6_1_3_intelligence_quality.py`
- `tests/test_weekly_trends.py`
- `tests/test_priority_vendor_sources.py`

## Validation completed in build package

- Python syntax compilation for all supplied Python files: **PASS**.
- Rolling-quarter trend engine basic execution: **PASS**.
- Documentation/manifest consistency checks: recorded in the supplied validation artefact.

## Production gates

Do not mark 6.1.3 production-complete until:

1. Repository CI passes.
2. Full discoverable regression suite passes.
3. Daily Security Brief is successfully delivered and visually reviewed.
4. Weekly Vulnerability Report is successfully delivered and visually reviewed.
5. Daily source cards show truthful source/window/latest context.
6. Weekly trend graph and grouping sections render correctly in the target mail client.
