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
  lifecycle changes, monthly rearview and rolling-quarter severity trends.

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
              persistent NVD cache
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

Version 6.1.x keeps vendor-owned security-bulletin channels separate from research
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
| HPE | HPE Security Bulletin Library structured adapter |
| Aruba | HPE Security Bulletin Library structured adapter with separate vendor-status presentation |
| Okta | Okta Security Advisories RSS |
| Apple | Apple Security Releases |
| Cisco | Cisco Security Advisories |
| NVD | Priority-vendor CVE corroboration/fallback with specific vendor attribution |
| GitHub Advisory Database | Structured open-source vulnerability corroboration; not an authoritative remediation source |

Research sources such as Palo Alto Unit 42, FortiGuard Labs, Google Security
Blog, Google Project Zero and AWS Security Blog remain useful context sources,
but they do not stand in for the vendor's vulnerability-advisory channel.

The NVD fallback attributes records to specific priority vendors rather than
leaving AWS, Google and Okta inside a broad cloud bucket or Palo Alto/Cisco/Apple
inside a generic `Other priority vendors` bucket.

KEV & Priority Vendor Status is health-aware with source-specific freshness,
selector-health detection and persistent partial/stale-state handling. A clean
negative is shown only when the expected authoritative source was successfully
checked. Failed or partial authoritative coverage is shown as unknown/degraded.

## Daily report behaviour

- Runs automatically at **06:17 Europe/Oslo**.
- Uses the previous **72 hours on Mondays**.
- Uses the previous **36 hours Tuesday through Sunday**.
- Continues when individual sources fail.
- Keeps primary advisories separate from secondary discovery reporting.
- Uses deterministic scoring; no LLM is required at runtime.
- Suppresses unchanged advisories already delivered during the configured cross-run deduplication window.
- Retains materially changed advisories when exploitation, severity, summary or recommended action changes.
- Records stage-level runtime profiles for operational tuning.
- Uses a conservative Enterprise DEFCON-style threat model.
- Labels exposure intelligence by confidence.
- Adds GitHub Advisory Database records as open-source vulnerability corroboration, while retaining vendor, CISA and NVD evidence rules for authoritative claims.
- Sends multipart HTML/plain-text email through the Gmail API.


### Intelligence quality and source truth — 6.1.3

Version 6.1.3 separates three facts that older releases could collapse into a
misleading `No material update` state:

1. **Collector health** — was the authoritative source checked successfully?
2. **Current reporting window** — did a priority advisory occur in the effective
   Daily/catch-up window?
3. **Latest material context** — what is the most recent material advisory in the
   retained 90-day vendor context, and how many days ago was it observed?

A failed Daily delivery no longer creates a blind interval. The last successful
delivery timestamp is persisted in `.state/pipeline_state.json`; if necessary,
the next run expands its collection cutoff with overlap, bounded to seven days.

Priority-vendor feeds and selected high-value threat-research sources can retain
up to 90 days of context for status/history while reader-facing Daily items
remain limited to the effective 36/72-hour or catch-up window.

Version 6.1.3 also:

- normalises Critical Vulnerability / Zero-Day TL;DR text before HTML rendering;
- persists a rolling 90-day Active Exploitation / Threat Actor Activity view;
- groups CISO Watch Next into **Next 24h** action/verification and **Next 72h**
  emerging/monitoring horizons;
- separates HPE and Aruba vendor-status cards;
- avoids treating low publication frequency as proof that a successfully checked
  source is stale;
- uses resilient/custom collection paths for the historically problematic
  BankInfoSecurity, Claroty Team82, Dragos, FBI Cyber News, ISACA, ISO, NIST,
  Nozomi Networks Labs and Splunk Security Blog sources.


### Nordics, IT/OT balance and AI Security & Trustworthiness — 6.1.4

Version 6.1.4 adds a dedicated, content-routed **AI Security and
Trustworthiness** section to the Daily report — material AI-security and
AI-use/abuse content is routed here from any source (including vendor
sources like Microsoft) rather than being absorbed into that source's usual
section. Coverage spans both AI's own security posture (model
vulnerabilities, prompt injection, supply-chain compromise, governance) and
real-world AI use/abuse (deepfakes, voice cloning, AI-generated
phishing/malware, jailbreak-as-a-service, disinformation campaigns,
defensive AI use). Sources: OpenAI News, Google DeepMind Blog, Anthropic
News, plus MITRE ATLAS and OWASP GenAI LLM Top 10 framework-update trackers.

Version 6.1.4 also:

- adds structured CISA advisory collection (`cisa_csaf.py`) via the official
  `cisagov/CSAF` GitHub repository (IT, OT and VA branches), replacing the
  brittle "CISA ICS Advisories" HTML scrape and adding IT-side CISA coverage
  that was previously absent — requires a `GITHUB_TOKEN` in CI for a usable
  rate limit (see `MAINTENANCE.md`);
- migrates NSM/NCSC to its confirmed RSS feed;
- splits Nozomi Networks into a PSIRT RSS feed and a separately-named
  research blog source;
- adds sticky Nordic-relevance tagging, priority sort and a visual badge to
  the rolling 90-day Active Exploitation / Threat Actor Activity view;
- splits sector-impact classification into Retail, Housing
  Estates/BoligByggerlag, and Energy (separated from Oil & Gas);
- adds SentinelOne, Trend Micro, Kubernetes and Salesforce vendor coverage,
  cross-checked against the organisation's monitored security stack;
- removes the dead `src/Archive/` directory and fixes a Bandit B608 false
  positive with a justified `# nosec`.


### Executive threat header — 6.1.2

Version 6.1.2 restores the approved executive threat-header hierarchy:

- one compact, colour-coded **Overall Threat** box on the left;
- a **text-only DEFCON 1–5 explanatory legend** aligned to the right on the same row;
- the current DEFCON level is marked in the legend;
- no duplicate five-box active DEFCON scale is rendered;
- the five operational metric cards remain on the full-width row immediately below.

The current dashboard includes:

- Overall Threat + text-only DEFCON 1–5 legend
- supporting metric cards
- Executive Summary / Top Developments
- KEV & Priority Vendor Status
- Critical Vulnerabilities / Zero-Days
- Active Exploitation / Threat Actor Activity
- Dark Web / Exposure
- Vendor Updates
- GRC & Standards
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
Outlook-safe column widths. The raw internal 0–100 priority score is not shown;
remediation bands remain user-facing. Every displayed full CVE identifier links
directly to NVD. The dedicated Vulnerability details column contains the
advisory title, descriptive source summary and explicit affected scope.
Descriptive text, confidence and corroborating-source count are retained in
lifecycle history.

It provides:

- ISO week number/year and reporting window
- Critical, High, exploited, KEV and zero-day metrics
- **Top Vulnerabilities of the Week**
- CVSS and EPSS prioritisation
- priority-vendor vulnerability overview
- lifecycle changes grouped by **vendor and vulnerability class/type**
- remediation priority grouped by the four established bands, then **vendor → CVE**
- **Quarterly Vulnerability Trend — Rolling 13 Weeks** for Zero-Day, Critical,
  High and Medium, with current four-week direction, prior-four-week comparison,
  peak week and concentration insight
- **A Month in the Rearview**, limited to the 20 most prominent vulnerability entities
- month-to-date vulnerability overview
- SQLite lifecycle history stored through the GitHub Actions cache

The quarterly trend counts a CVE once, in the week it is first observed in the
lifecycle database. Zero-Day is intentionally a separate series and may overlap
the CVE's CVSS severity series. Historical depth therefore improves as the
weekly lifecycle database accumulates observations.

See [`docs/operations/WEEKLY_VULNERABILITY_REPORT.md`](docs/operations/WEEKLY_VULNERABILITY_REPORT.md).

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
│   ├── repository-ci.yml
│   ├── test-security-brief.yml
│   └── weekly-vulnerability-report.yml
├── assets/
├── docs/
│   ├── architecture/
│   │   └── OPTIMISATION.md
│   ├── operations/
│   │   ├── CONTINUITY.md
│   │   └── WEEKLY_VULNERABILITY_REPORT.md
│   └── releases/
│       ├── RELEASE_6.1.3.md
│       ├── RELEASE_6.1.2.md
│       ├── RELEASE_6.1.1.md
│       ├── RELEASE_6.1.0.md
│       └── manifests/
│           ├── RELEASE_6.1.3.json
│           └── RELEASE_6.1.2.json
├── config/
│   ├── sources.json
│   └── upcoming_governance.json
├── src/
│   ├── security_brief/
│   │   ├── analysis.py
│   │   ├── app.py
│   │   ├── archive.py
│   │   ├── branding.py
│   │   ├── collectors.py
│   │   ├── config.py
│   │   ├── delivery.py
│   │   ├── dedup_state.py
│   │   ├── evidence.py
│   │   ├── governance.py
│   │   ├── http_client.py
│   │   ├── models.py
│   │   ├── priority_vendor_sources.py
│   │   ├── nvd_cache.py
│   │   ├── open_source_sources.py
│   │   ├── report_policy.py
│   │   ├── rendering.py
│   │   ├── rendering_components.py
│   │   ├── rules.py
│   │   ├── sources.py
│   │   ├── source_health.py
│   │   ├── source_resilience.py
│   │   ├── pipeline_state.py
│   │   ├── threat_activity.py
│   │   ├── source_config.py
│   │   ├── runtime_profile.py
│   │   ├── utils.py
│   │   ├── vulnerability_reporting.py
│   │   ├── vendor_coverage.py
│   │   ├── weekly_app.py
│   │   └── weekly_rendering.py
│   ├── send_security_advisory.py
│   └── send_weekly_vulnerability_report.py
├── tests/
│   ├── test_archive.py
│   ├── test_report_policy.py
│   ├── test_smoke.py
│   ├── test_source_health.py
│   ├── test_priority_vendor_sources.py
│   ├── test_v6_1_3_intelligence_quality.py
│   ├── test_weekly_trends.py
│   ├── test_v6_maintenance.py
│   ├── test_vulnerability_reporting.py
│   └── test_weekly_rendering.py
├── CHANGELOG.md
├── MAINTENANCE.md
├── README.md
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
| `HTML_DETAIL_FETCH_LIMIT` | `8` | Maximum detail pages fetched per HTML source |
| `NVD_CACHE_FILE` | `.state/nvd_cache.json` | Persistent NVD enrichment cache |
| `NVD_CACHE_TTL_HOURS` | `24` | NVD cache freshness period |
| `DAILY_DEDUP_DAYS` | `7` | Suppression window for unchanged Daily items |
| `DAILY_DEDUP_STATE_FILE` | `.state/daily_dedup.json` | Persistent Daily duplicate state |
| `RUNTIME_PROFILE_FILE` | `.state/runtime_profile.json` | Latest stage-level timing profile |
| `SOURCE_DEFINITIONS_FILE` | `config/sources.json` | Source-definition override file |
| `VENDOR_CONTEXT_DAYS` | `90` | Historical context retained for priority-vendor status |
| `PIPELINE_STATE_FILE` | `.state/pipeline_state.json` | Last successful Daily delivery used for bounded catch-up |
| `THREAT_ACTIVITY_STATE_FILE` | `.state/threat_activity.json` | Rolling 90-day actor/campaign activity state |
| `NVD_API_KEY` | Empty | Optional NVD API key |
| `HIBP_API_KEY` | Empty | Optional HIBP API key |

Weekly-specific variables are documented in
`WEEKLY_VULNERABILITY_REPORT.md`.

## Source configuration overlays

`config/sources.json` can update or disable a named built-in source without a
Python change. Supported source fields include URL, selectors, inclusion and
exclusion patterns, candidate limits, freshness, scoring, section, vendor and
topic keywords. Set `"enabled": false` for a named source to disable it. Invalid
field names fail closed during startup.

## Manual validation

Run offline regression tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Then run:

```text
Actions → Test Daily Security Brief
```

For 6.1.3, visually verify the received Daily report still has:

1. compact Overall Threat box at the left;
2. DEFCON 1–5 text legend at the right on the same row;
3. exactly one current-level marker in the legend;
4. the five metric cards on the row below;
5. no duplicate five-box active DEFCON scale.

A failed authoritative source must be investigated in GitHub Actions rather
than assuming the vendor had no security updates.

For 6.1.3, also visually verify the Weekly report contains:

1. Top Vulnerabilities of the Week.
2. Section 3 grouped by vendor and vulnerability class/type.
3. Section 4 grouped by remediation band, then vendor, then CVE.
4. Quarterly Vulnerability Trend — Rolling 13 Weeks with Zero-Day, Critical,
   High and Medium series only.
5. A Month in the Rearview with no more than 20 entities.

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
- GitHub Actions restores and saves `.state` for NVD caching, Daily duplicate
  suppression, source health and runtime profiles; local state remains ignored
  by Git.
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
