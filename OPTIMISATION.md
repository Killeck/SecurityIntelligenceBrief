<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Architecture and Optimisation Notes — 5.6.4

## Objective

Keep one low-cost intelligence engine that can produce daily and weekly reports
while isolating source failures, avoiding duplicated source definitions and
keeping authoritative vulnerability data separate from research/news context.

## Current module boundaries

```text
send_security_advisory.py
        ↓
security_brief.app
        ├── priority_vendor_sources   # vendor-owned bulletins + HPE adapter
        ├── collectors                # generic RSS/HTML, KEV, NVD, HIBP
        ├── sources                   # broad configured intelligence sources
        ├── analysis                  # scoring, selection and correlation
        ├── governance                # forward-looking milestones
        ├── rendering                 # text + HTML report
        ├── branding                  # inline branding assets
        ├── delivery                  # Gmail API OAuth delivery
        ├── http_client               # thread-local sessions/retries
        ├── models
        ├── rules
        ├── config
        └── utils

send_weekly_vulnerability_report.py
        ↓
security_brief.weekly_app
        └── reuses security_brief.app.primary_tasks()
```

## Why the priority-vendor layer exists

Several priority vendors provide security bulletins through dedicated official
channels that are materially different from their research blogs. Treating a
research blog as the vendor's vulnerability feed can produce a misleading
`No material update` result when the actual PSIRT/security-bulletin portal has
new CVEs.

Version 5.6.4 therefore gives vendor-owned bulletin feeds explicit ownership and
keeps research channels as complementary sources.

## NVD role

NVD remains useful for:

- CVSS enrichment
- corroborating vendor CVEs
- fallback coverage when a vendor feed is delayed or unavailable

It is not treated as a replacement for vendor PSIRT/security bulletins. The new
priority NVD collector uses specific vendor attribution instead of broad cloud or
other-vendor buckets.

## Execution characteristics

- Independent sources are collected concurrently.
- `SOURCE_WORKERS` defaults to 8 and is bounded 1–16.
- `executor.map` preserves source-health output order.
- Each worker uses its own reusable `requests.Session`.
- HTTP 429 and transient 5xx responses receive bounded retries/backoff.
- Primary items are deduplicated before NVD enrichment.
- Daily and weekly reporting share the same primary source task builder.

## Delivery

Delivery uses the Gmail API with OAuth refresh-token credentials. SMTP/App
Password delivery is no longer the current architecture.

## Documentation model

- `README.md`: current state
- `CHANGELOG.md`: released history
- `MAINTENANCE.md`: open work
- `OPTIMISATION.md`: architecture/rationale

Completed maintenance work is not retained as a second release history inside
`MAINTENANCE.md`.

## Next optimisation areas

The active backlog is maintained only in `MAINTENANCE.md`. Important themes are
source-health state, cross-run state, report correlation, source externalisation,
SBOM/dependency hardening and historical reporting.
