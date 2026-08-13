<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Architecture and Optimisation Notes — 5.6.6

## Objective

Keep one low-cost intelligence engine for daily and weekly reports while isolating source failures, separating authoritative vulnerability coverage from research/news context and keeping presentation policy testable.

## Module boundaries

```text
security_brief.app
 ├── priority_vendor_sources
 ├── collectors / sources
 ├── analysis / governance
 ├── report_policy -> rendering
 ├── branding / delivery / http_client
 └── models / rules / config / utils

security_brief.weekly_app
 ├── reuses app.primary_tasks()
 ├── vulnerability_reporting   # scoring + lifecycle
 └── weekly_rendering          # week identity + aligned presentation
```

## Source-health model

Collection records compatibility `status` plus `health_state` (`CONTENT`, `QUIET`, `FAILED`), `checked_at` and `newest_item` when an in-window record exposes a timestamp. The daily vendor policy maps expected authoritative source operations to vendor status. Failed/missing authoritative coverage cannot produce a clean `Checked — no material update`. Cross-run last-success history, stale-feed detection and selector-health checks remain open.

## Critical vulnerability ordering

The critical view orders current zero-days, then exploitation/KEV, then remaining entries by CVSS, with EPSS as equal-CVSS tie-breaker. Mandatory critical/exploited records survive normal item limits.

## Weekly presentation

The internal composite urgency score remains used for sorting/remediation but is no longer displayed. Explicit column widths and matching `align`/`text-align` attributes improve Outlook consistency. Complete CVE identifiers are deep-linked to NVD.

## Delivery and documentation

Delivery remains Gmail API OAuth, with workflow preflight for required secrets
and safe logs for token refresh/Gmail acceptance. The Daily DEFCON legend is
now table-based HTML, avoiding a second inline image and making the current
level explicit in Outlook-compatible markup. `README.md` is current state,
`CHANGELOG.md` released history, `MAINTENANCE.md` open work and this file
architecture/rationale. Release notes and manifests reside under
`docs/releases/`.
