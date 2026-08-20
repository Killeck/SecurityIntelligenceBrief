<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Architecture and Optimisation Notes — 6.1.2

## Objective

Keep one low-cost intelligence engine for daily and weekly reports while
isolating source failures, separating authoritative vulnerability coverage from
research/news context and keeping presentation policy testable.

## Module boundaries

```text
security_brief.app
 ├── priority_vendor_sources
 ├── open_source_sources / vendor_coverage
 ├── collectors / sources
 ├── source_config / nvd_cache / dedup_state
 ├── analysis / governance
 ├── evidence / report_policy -> rendering -> rendering_components
 ├── branding / delivery / http_client
 └── runtime_profile / models / rules / config / utils

security_brief.weekly_app
 ├── reuses app.primary_tasks()
 ├── vulnerability_reporting   # scoring + lifecycle
 └── weekly_rendering          # week identity + aligned presentation
```

## Source-health model

Collection records carry compatibility `status` plus `health_state`
(`CONTENT`, `QUIET`, `PARTIAL`, `STALE`, `DEGRADED`, `FAILED`), `checked_at`
and newest-item timestamps. Persistent state allows stale feeds to remain
explicit across quiet runs. Failed, missing or confirmed-incomplete
authoritative coverage cannot produce a clean negative.

## Critical vulnerability ordering

The critical view orders current zero-days, then exploitation/KEV, then
remaining entries by CVSS, with EPSS as the equal-CVSS tie-breaker. Mandatory
critical/exploited records survive normal item limits.

## Weekly presentation

The internal composite urgency score remains used for sorting/remediation but is
not displayed. Explicit column widths and matching alignment attributes improve
Outlook consistency. Complete CVE identifiers are deep-linked to NVD. Lifecycle
history retains source summaries, affected scope, confidence and corroboration.

## Runtime and network bounds

Daily and weekly orchestration records named stage durations in persistent JSON.
NVD per-CVE enrichment uses a persistent cache, and HTML sources cap detail-page
expansion independently of index candidate limits.

## Persistent deduplication and evidence

The Daily pipeline stores fingerprints of delivered advisory content and
suppresses unchanged repeats during the configured window. Material changes to
severity, exploitation, summary or action remain reportable. CVE/link
consolidation records corroborating sources and explicit confidence.

## Configuration and rendering boundaries

Named source definitions accept validated JSON overlays from
`config/sources.json`.

The Daily executive threat header is deliberately isolated in
`rendering_components.py`. Version 6.1.2 uses that boundary to restore the
approved layout without modifying the large Daily renderer:

- 20% compact Overall Threat area at left;
- 80% right-hand area containing a right-aligned, maximum-400px text-only
  DEFCON 1–5 explanatory legend;
- no five-box active DEFCON scale;
- metric cards remain owned by `rendering.py` and render on the row below.

The nested Overall Threat table is retained for Outlook safety and to preserve
existing smoke-test boundaries.

Version 6.1.0 also added a separate open-source corroboration catalogue and
declarative vendor-coverage registry. GitHub Advisory Database entries provide
structured OSS vulnerability context but cannot establish vendor remediation,
confirmed exploitation or clean-negative status by themselves. CrowdStrike
remains supporting-only until a stable public product-advisory path exists.

## Delivery and documentation

Delivery remains Gmail API OAuth, with workflow preflight for required secrets
and safe logs for token refresh/Gmail acceptance.

The Daily report uses one active colour-coded Overall Threat status plus a
text-only explanatory DEFCON legend. This is intentionally different from the
obsolete five-colour active-box scale.

`README.md` is current state, `CHANGELOG.md` released history,
`MAINTENANCE.md` open work and this file architecture/rationale. Release notes
and manifests reside under `docs/releases/`.
