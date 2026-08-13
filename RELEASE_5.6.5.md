# Daily Security Brief 5.6.5 — Release Package

## Scope

- Weekly ISO week number/year.
- Weekly main-table alignment.
- Remove user-facing raw priority number while retaining internal scoring.
- Direct NVD links for every displayed full CVE in the weekly report.
- Maintenance Priority 1 phase 1: source-health/vendor-status truth.
- Complete former Maintenance Priority 2: critical/zero-day ordering and mandatory retention.

## Files

`VERSION`, `CHANGELOG.md`, `MAINTENANCE.md`, `README.md`, `OPTIMISATION.md`, `WEEKLY_VULNERABILITY_REPORT.md`, `src/security_brief/app.py`, `src/security_brief/report_policy.py`, `src/security_brief/weekly_app.py`, `src/security_brief/weekly_rendering.py`, `tests/test_report_policy.py`, `tests/test_weekly_rendering.py`.

All are complete replacement/new files. No patch file is required. Overlay onto v5.6.4.

## Validate

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Then run the Daily test workflow and the Weekly Vulnerability Report manually. Verify health-aware vendor states, evidence-first critical ordering, ISO week display, aligned weekly columns, no raw Priority number and clickable CVEs.

## Commit

`5.6.5 - improve vulnerability prioritisation and source-health truth`
