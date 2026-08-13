<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Daily Security Brief

A Python and GitHub Actions cybersecurity-intelligence pipeline producing two
companion reports for Security Advisors, SOC functions, Security Architects and
CISOs:

- **Daily Security Brief** — immediate developments, exposure and actions.
- **Weekly Vulnerability Report** — CVE-centred remediation priorities,
  lifecycle changes and a month-to-date vulnerability overview.

`VERSION` is the single runtime source of truth for the release number.

## Current architecture

```text
Official advisories / vendor bulletins / research / discovery
                         │
                         ▼
               bounded parallel collection
                         │
             ┌───────────┴───────────┐
             │                       │
  authoritative vendor layer    general collectors
             │                       │
             └───────────┬───────────┘
                         ▼
               normalise + deduplicate
                         ▼
              NVD CVSS + FIRST EPSS
                         ▼
        deterministic scoring / correlation
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
       Daily Security Brief   Weekly Vulnerability Report
             │                       │
             └───────────┬───────────┘
                         ▼
                    Gmail API
```

The pipeline uses public and authorised sources. It does **not** connect to
onion services, criminal forums, ransomware leak sites, stolen-data repositories
or illicit marketplaces.

## Authoritative priority-vendor vulnerability coverage

Version 5.6.5 retains vendor-owned security-bulletin channels from research
and news sources.

| Vendor / area | Authoritative collection path |
|---|---|
| CISA KEV | CISA Known Exploited Vulnerabilities catalogue |
| Microsoft | Microsoft Security Response Center Security Update Guide |
| Fortinet | Fortinet PSIRT RSS |
| AWS | AWS Security Bulletins RSS |
| Google Cloud | Google Cloud Security Bulletins XML feed |
| Google Chrome | Official Chrome Releases feed |
| Palo Alto Networks | Palo Alto Networks Security Advisories RSS |
| HPE / Aruba | HPE Security Bulletin Library structured adapter |
| Okta | Okta Security Advisories RSS |
| Apple | Apple Security Releases |
| NVD | Priority-vendor CVE corroboration/fallback with specific vendor attribution |

Research sources such as Palo Alto Unit 42, FortiGuard Labs, Google Security
Blog, Google Project Zero and AWS Security Blog remain useful context sources,
but they no longer stand in for the vendor's vulnerability-advisory channel.

The NVD fallback attributes records to specific priority vendors rather than
leaving AWS, Google and Okta inside a broad cloud bucket or Palo Alto/Cisco/Apple
inside a generic `Other priority vendors` bucket.

Version 5.6.5 makes KEV & Priority Vendor Status health-aware. A clean negative
is shown only when the expected authoritative source was successfully checked.
Failed or partial authoritative coverage is shown as unknown/degraded instead of
`No material update`.

## Daily report behaviour

- Runs automatically at **06:17 Europe/Oslo**.
- Uses the previous **72 hours on Mondays**.
- Uses the previous **36 hours Tuesday through Sunday**.
- Continues when individual sources fail.
- Keeps primary advisories separate from secondary discovery reporting.
- Uses deterministic scoring; no LLM is required at runtime.
- Uses a conservative Enterprise DEFCON-style threat model.
- Labels exposure intelligence by confidence.
- Sends multipart HTML/plain-text email through the Gmail API.

The current dashboard includes:

- Outlook-safe HTML/table Enterprise DEFCON legend with the live level highlighted, and Overall Threat
- supporting metric cards
- Executive Summary / Top Developments
- KEV & Priority Vendor Status
- Critical Vulnerabilities / Zero-Days
- Active Exploitation / Threat Actor Activity
- Dark Web / Exposure
- Vendor Updates
- Standards / Compliance / Governance
- Recommended Actions Today
- Customer & Sector Impact
- SOC & Detection Engineering
- Threat Intelligence
- Security Advisory & CISO Watch Next — 24/72h
- Source Coverage

## Weekly vulnerability report

The weekly report runs Monday at **07:23 Europe/Oslo** and uses the same
`primary_tasks()` pipeline as the daily report. It shares authoritative
Fortinet, AWS, Google, Palo Alto, HPE/Aruba and Okta coverage without a second
source configuration.

The header and subject include ISO week number/year. The main table uses fixed
Outlook-safe column widths. The raw internal 0–100 priority score is no longer
shown; remediation bands remain user-facing. Every displayed full CVE identifier
links directly to NVD.

It provides:

- ISO week number/year and reporting window
- Critical, High, exploited, KEV and zero-day metrics
- CVSS and EPSS prioritisation
- priority-vendor vulnerability overview
- remediation bands
- lifecycle/state changes
- month-to-date vulnerability overview
- SQLite history stored through the GitHub Actions cache

See [`WEEKLY_VULNERABILITY_REPORT.md`](WEEKLY_VULNERABILITY_REPORT.md).

## Source trust model

### Tier A — authoritative

Government vulnerability catalogues, vendor PSIRT/security bulletins and
standards/regulatory authorities. These sources may establish vulnerability,
severity, exploitation or official-remediation facts.

### Tier B — primary research

Vendor research teams and recognised technical/security research organisations.
Used for exploitation context, detections, attribution and technical detail.

### Tier C — trusted reporting

Selected security and general-news publications. Used for discovery and
corroboration, not as the sole authority for CVSS, KEV or remediation state.

### Tier D — discovery signals

Unverified or aggregation sources. These remain visibly labelled and cannot
independently establish a confirmed organisational incident.

## Package layout

```text
.
├── .github/workflows/
│   ├── daily-security-brief.yml
│   ├── test-security-brief.yml
│   └── weekly-vulnerability-report.yml
├── assets/
├── config/
│   └── upcoming_governance.json
├── src/
│   ├── security_brief/
│   │   ├── analysis.py
│   │   ├── app.py
│   │   ├── branding.py
│   │   ├── collectors.py
│   │   ├── config.py
│   │   ├── delivery.py
│   │   ├── governance.py
│   │   ├── http_client.py
│   │   ├── models.py
│   │   ├── priority_vendor_sources.py
│   │   ├── report_policy.py
│   │   ├── rendering.py
│   │   ├── rules.py
│   │   ├── sources.py
│   │   ├── utils.py
│   │   ├── vulnerability_reporting.py
│   │   ├── weekly_app.py
│   │   └── weekly_rendering.py
│   ├── send_security_advisory.py
│   └── send_weekly_vulnerability_report.py
├── tests/
│   ├── test_priority_vendor_sources.py
│   ├── test_report_policy.py
│   ├── test_smoke.py
│   ├── test_vulnerability_reporting.py
│   └── test_weekly_rendering.py
├── CHANGELOG.md
├── MAINTENANCE.md
├── OPTIMISATION.md
├── README.md
├── WEEKLY_VULNERABILITY_REPORT.md
├── VERSION
└── requirements.txt
```

## Gmail API delivery

Required GitHub Actions secrets:

| Secret | Required | Purpose |
|---|---|---|
| `GMAIL_USERNAME` | Yes | Authenticated sender account |
| `GMAIL_CLIENT_ID` | Yes | Google OAuth client ID |
| `GMAIL_CLIENT_SECRET` | Yes | Google OAuth client secret |
| `GMAIL_REFRESH_TOKEN` | Yes | OAuth refresh token with `gmail.send` scope |
| `EMAIL_TO` | Yes | Report recipient |
| `NVD_API_KEY` | No | Higher NVD request capacity |
| `HIBP_API_KEY` | No | Verified-domain HIBP monitoring |
| `MONITORED_DOMAINS` | No | Comma-separated authorised domains |
| `MONITORED_BRANDS` | No | Comma-separated organisation/brand names |

The application does not require the old Gmail App Password/SMTP path. Both
delivery workflows verify required Gmail API secrets before attempting to send
and log only safe milestones: OAuth refresh and Gmail API acceptance.

## Runtime settings

| Variable | Default | Purpose |
|---|---:|---|
| `NEWS_LOOKBACK_HOURS` | `auto` | 36/72-hour daily window |
| `KEV_LOOKBACK_DAYS` | `auto` | KEV collection window |
| `NEWS_MAX_ITEMS` | `40` | Maximum selected daily primary advisories |
| `EXEC_NEWS_MAX_ITEMS` | `10` | Maximum discovery links |
| `EXPOSURE_MAX_ITEMS` | `20` | Maximum exposure signals |
| `EXEC_NEWS_MIN_SCORE` | `24` | Discovery relevance threshold |
| `UPCOMING_GOVERNANCE_DAYS` | `365` | Forward governance horizon |
| `SOURCE_WORKERS` | `8` | Parallel source workers, 1–16 |
| `NVD_API_KEY` | Empty | Optional NVD API key |
| `HIBP_API_KEY` | Empty | Optional HIBP API key |

Weekly-specific variables are documented in
`WEEKLY_VULNERABILITY_REPORT.md`.

## Manual validation

Run offline regression tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Then run:

```text
Actions → Test Daily Security Brief
```

For v5.6.5, verify the Actions log contains successful checks for:

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

A failed authoritative source must be investigated in GitHub Actions rather
than assuming the vendor had no security updates. Version 5.6.5 exposes failed
or partial authoritative coverage as unknown/degraded in the vendor-status view.

## Documentation roles

To avoid duplicated or contradictory project records:

- `README.md` describes **what the current release does**.
- `CHANGELOG.md` describes **what completed releases changed**.
- `MAINTENANCE.md` describes **what remains to be fixed or improved**.
- Completed maintenance items are removed from `MAINTENANCE.md` when their
  release is added to `CHANGELOG.md`.

## Known limitations

- Vendor feeds and HTML portals can change without notice.
- The HPE library adapter depends on the official result table remaining
  available in returned HTML.
- NVD is a corroborating/fallback source and may publish CVE enrichment later
  than the vendor advisory.
- Collection retains optional cross-run state in `.state/source_health.json`
  (or `SOURCE_HEALTH_STATE_FILE`) and reports stale sources explicitly.
- No direct dark-web/onion collection.
- No customer CMDB or asset-inventory integration.

## Privacy and handling

- Use HIBP domain search only for domains the account is authorised to query.
- Do not include personal email addresses in `MONITORED_DOMAINS`.
- Treat unverified dark-web/ransomware claims as intelligence leads, not proof.
- Do not download stolen data or contact threat actors for validation.
- Follow contractual, legal and incident-response requirements.

## Licence and ownership

Copyright © 2026 John-Helge Gantz. All rights reserved.

Daily Security Brief is proprietary software. See `LICENSE`, `NOTICE` and
`THIRD_PARTY_NOTICES.md` for the complete terms and third-party information.
