<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Architecture and Optimisation Notes — 6.0.0

## Objective

Keep one low-cost intelligence engine for daily and weekly reports while isolating source failures, separating authoritative vulnerability coverage from research/news context and keeping presentation policy testable.

## Module boundaries

```text
security_brief.app
 ├── priority_vendor_sources
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

Collection records carry compatibility `status` plus `health_state` (`CONTENT`, `QUIET`, `STALE`, `FAILED`), `checked_at` and newest-item timestamps. An optional JSON state file persists last-success/newest-seen values, allowing stale feeds to remain explicit across quiet runs. Failed/missing authoritative coverage cannot produce a clean `Checked — no material update`.

## Critical vulnerability ordering

The critical view orders current zero-days, then exploitation/KEV, then remaining entries by CVSS, with EPSS as equal-CVSS tie-breaker. Mandatory critical/exploited records survive normal item limits.

## Weekly presentation

The internal composite urgency score remains used for sorting/remediation but is no longer displayed. Explicit column widths and matching `align`/`text-align` attributes improve Outlook consistency. Complete CVE identifiers are deep-linked to NVD. The weekly lifecycle model now retains source summaries so each displayed CVE can explain the vulnerability behaviour and affected scope instead of presenting identifiers and scores alone.

## Runtime and network bounds

Daily and weekly orchestration records named stage durations in a persistent JSON profile. NVD per-CVE enrichment uses a 24-hour persistent cache by default, and HTML sources cap detail-page expansion independently of their index candidate limits. These controls are environment-configurable and restored through GitHub Actions state caches.

## Persistent deduplication and evidence

The Daily pipeline stores fingerprints of delivered advisory content and suppresses unchanged repeats during a seven-day default window. Material changes to severity, exploitation, summary or action generate a new fingerprint and remain reportable. CVE/link consolidation also records unique corroborating sources and assigns an explicit authoritative, corroborated or single-source confidence label used by both report families.

## Configuration and rendering boundaries

Named source definitions accept validated JSON overlays from `config/sources.json`, allowing URL, selector, scoring, freshness and enablement changes without editing collector code. The Overall Threat component is isolated from the main Daily renderer, while weekly presentation remains in its dedicated module. Focused maintenance tests cover these boundaries.

## Delivery and documentation

Delivery remains Gmail API OAuth, with workflow preflight for required secrets
and safe logs for token refresh/Gmail acceptance. The Daily report uses one
colour-coded Overall Threat status; the redundant five-level DEFCON scale and
duplicate legend presentation are removed. `README.md` is current state,
`CHANGELOG.md` released history, `MAINTENANCE.md` open work and this file
architecture/rationale. Release notes and manifests reside under
`docs/releases/`.
