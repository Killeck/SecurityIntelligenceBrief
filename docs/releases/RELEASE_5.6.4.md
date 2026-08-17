# Daily Security Brief 5.6.4 — Release Package

## Purpose

This release addresses the first item in the restructured maintenance backlog:
**authoritative priority-vendor vulnerability sources**.

It also cleans the documentation model so release history and future maintenance
work are no longer duplicated between `CHANGELOG.md` and `MAINTENANCE.md`.

## Supersedes

Do **not** apply the earlier `DailySecurityBrief_authoritative_vendor_sources.zip`.
This 5.6.4 package supersedes it.

## Files in this release

```text
VERSION
CHANGELOG.md
MAINTENANCE.md
README.md
OPTIMISATION.md
WEEKLY_VULNERABILITY_REPORT.md
src/security_brief/app.py
src/security_brief/priority_vendor_sources.py
tests/test_priority_vendor_sources.py
```

These are complete replacement/new files; no `.patch` file is required.

## Apply

Extract the ZIP over a clean v5.6.3 working tree so the paths above replace or
create the corresponding repository files.

Then review:

```bash
git status --short
git diff -- VERSION CHANGELOG.md MAINTENANCE.md README.md OPTIMISATION.md   WEEKLY_VULNERABILITY_REPORT.md src/security_brief/app.py   src/security_brief/priority_vendor_sources.py   tests/test_priority_vendor_sources.py
```

## Offline validation

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Live validation

Run:

```text
Actions → Test Daily Security Brief
```

Confirm the Actions log contains these source checks:

```text
Fortinet PSIRT RSS
AWS Security Bulletins
Google Cloud Security Bulletins
Google Chrome Releases
Palo Alto Networks Security Advisories
Okta Security Advisories
HPE Security Bulletin Library
NVD priority-vendor CVEs
```

For the first validation run, use a 72-hour window so there is a better chance
of seeing recent vendor advisories.

Inspect the resulting KEV & Priority Vendor Status and Vendor Updates sections.
The next release will address the status-state wording so degraded/unavailable
sources cannot appear as a clean `No material update` result.

## Commit

Use the repository release convention:

```text
5.6.4 - improve authoritative vendor vulnerability coverage
```

## No new secrets

This release uses the existing Gmail OAuth and optional NVD settings. No new
credentials are required.
