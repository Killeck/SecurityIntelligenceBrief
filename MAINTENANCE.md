<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Maintenance Backlog

`MAINTENANCE.md` contains **open work only**. Completed work is recorded in
`CHANGELOG.md` and the corresponding release note.

## Documentation ownership

- `README.md` — current system behaviour, architecture, operation and setup.
- `CHANGELOG.md` — completed release changes.
- `MAINTENANCE.md` — open defects, improvements and planned work only.
- `docs/operations/CONTINUITY.md` — durable development handoff.
- `docs/operations/WEEKLY_VULNERABILITY_REPORT.md` — Weekly report operating reference.
- `docs/architecture/OPTIMISATION.md` — architecture and optimisation rationale.

## Current baseline

Version **6.1.4** is the current validation candidate.

The former Priority 1 Daily intelligence-quality work, source-truth correction,
failed-run catch-up, Weekly Top Vulnerabilities, vendor/class lifecycle grouping,
vendor-first remediation grouping, A Month in the Rearview and rolling-quarter
severity trend are implemented in 6.1.3 and therefore removed from this open
backlog.

## Priority 1 — AI Security & Trustworthiness

Implemented in 6.1.4: dedicated "AI Security and Trustworthiness" first-class
Daily section via content-based routing (takes precedence over vendor
routing); OpenAI/DeepMind/Anthropic sources; MITRE ATLAS and OWASP GenAI LLM
Top 10 framework-update trackers; expanded term coverage for real-world AI
use/abuse (deepfakes, voice cloning, AI-generated phishing/malware, scams,
jailbreak-as-a-service, disinformation) alongside AI's-own-security and
governance language.

[DONE] Dedicated "AI security and abuse" category added to CATEGORY_RULES
(keyed on the same AI_SECURITY_TERMS), with matching WHY, ACTIONS and
DETECTION_TEMPLATES entries - AI-related items get tailored guidance text
instead of falling through to generic "General security" defaults.
Positioned after Active exploitation/Ransomware/Nation-state/Identity
security in rule precedence, so operational urgency still overrides topical
AI labeling (verified by test: an actively-exploited AI-platform CVE keeps
"Active exploitation" category, not "AI security and abuse").

[DECIDED] Weekly report does NOT get an equivalent AI Security
section/tagging. Weekly's vulnerability-class taxonomy (`_VULN_CLASSES` in
weekly_rendering.py) is a technical-mechanism axis (RCE, SQLi, XSS, SSRF,
etc.) describing *how* a CVE manifests, not a topical/domain axis - "AI
security and abuse" doesn't fit that taxonomy the way it fits Daily's
narrative section. Weekly is explicitly a CVE remediation/lifecycle report;
narrative AI content (deepfakes, jailbreaks, disinformation, governance
developments) isn't CVE-shaped and doesn't belong in a remediation
worklist. If a genuine AI/ML-product CVE arises, Weekly's existing
vendor -> vulnerability-class -> CVE grouping already handles it correctly
without modification (e.g. an RCE in an ML framework is still "Remote code
execution", grouped under whatever vendor produces it).

[DONE] Regulatory/availability news about major AI vendors (e.g. "Anthropic
pauses a Claude feature in Europe") now routes to AI Security and
Trustworthiness. This class of story often carries no AI-specific keyword
beyond the vendor name, and is usually reported by general tech/policy
press rather than the vendor's own blog - so this only works because
route_section checks content from every source, not just the three
AI-vendor sources. Implemented with a precision guard rather than adding
the generic regulatory terms straight to AI_SECURITY_TERMS: terms like
"antitrust investigation", "regulatory fine", "data protection authority"
are common in totally unrelated contexts (any company's GDPR fine, any
telecom antitrust case), so AI_REGULATORY_AVAILABILITY_TERMS only counts
when it co-occurs with a named AI_VENDOR_PRODUCT_NAMES entry
(is_ai_security_relevant in rules.py) - verified by tests including a
negative case (bare "antitrust investigation" about an unrelated company
does NOT route to the AI section).

AI_VENDOR_PRODUCT_NAMES currently covers Anthropic/Claude, OpenAI/ChatGPT/
GPT, Google DeepMind/Gemini, Microsoft Copilot, Meta AI/Llama, xAI/Grok,
Mistral AI and Perplexity - the most prominent consumer/enterprise AI
vendors, not an exhaustive list. Not yet covered, worth adding if relevant
stories start appearing: Amazon/AWS Bedrock, DeepSeek, Cohere, Stability
AI, Hugging Face (as a platform), Nvidia (AI software/chips), Baidu/Ernie,
Alibaba/Qwen, IBM watsonx, ElevenLabs, Databricks. Low cost to extend
(append to the tuple in rules.py) whenever a gap is actually observed in
practice - not pre-emptively exhaustive by design, since the list only
gates the generic regulatory-term co-occurrence check, not the core
AI_SECURITY_TERMS matching.

Anthropic News (HTML scrape, href-pattern selectors `a[href^='/news/']`):
lower risk than originally flagged - this session's Nozomi Blog investigation
confirmed href-pattern selectors (as opposed to semantic-tag selectors like
`main h2 a[href]`) are the more robust approach generally, and Anthropic's
selector already uses that pattern. Still not live-DOM-verified from this
sandbox (no network access to anthropic.com); confirm on the next real run
rather than treating as high-risk.

## Priority 2 — Source architecture follow-on

- [DONE] GitHub Advisory Database pagination (bounded to 10 pages via the
  `Link` header's `rel="next"`) with explicit `PartialItemList` signalling
  when the bound is hit while more pages remain - now correctly surfaces
  as `PARTIAL` source health via the existing (previously-unused)
  `entry["partial"]` mechanism in `source_health.py`.
- [DONE] GHSA collection now uses `updated_at` (the field the API is
  already sorted by) instead of `published_at`, so a materially revised
  old advisory surfaces instead of being silently missed.
- [DONE] GHSA records enriched with package/ecosystem (from
  `vulnerabilities[].package`, appended to the item summary) and CVE
  aliases (from `identifiers[]`, merged into `item.cves` - catches CVEs
  only listed there and not in the top-level `cve_id` field).
- [DONE] Withdrawn GHSA advisories (`withdrawn_at` present) are now
  excluded entirely rather than reported as active vulnerabilities.
- [DONE] Source-specific fixture tests added for the three custom/resilient
  adapters that had zero coverage: `fetch_resilient_html`,
  `fetch_authoritative_vendor_rss`, `fetch_priority_vendor_nvd`.
- [DONE, found during the above audit] `fetch_resilient_html`'s own
  fallback tier assumed semantic wrapper tags (`main`/`article`/`h2`/`h3`)
  - the exact blind spot that broke the original Nozomi Blog selectors.
  Any other `RESILIENT_HTML_SOURCES` entry hitting a Webflow-style (or
  similarly non-semantic) site would have failed the same way. Added a
  third, fully structure-agnostic fallback tier (`a[href]`, relying on
  existing include/exclude URL patterns) as a last resort.
- Add a stronger authoritative CrowdStrike path if a stable public source becomes available.
  [CONFIRMED BLOCKED 6.1.6] CrowdStrike's structured API (Falcon
  Adversary Intelligence, CVE/ExPRT data) requires an authenticated
  OAuth2 API client tied to a paid Falcon platform subscription -
  "not public, only accessible by partners or customers" (per Sumo
  Logic's own integration docs). No public unauthenticated alternative
  exists. Pursuing this would also violate the "no paid dependencies"
  principle below. The current RSS blog feed
  (crowdstrike.com/en-us/blog/feed/) remains the best available free
  option - not a gap to keep chasing.
- Continue replacing fragile generic HTML parsing with structured vendor,
  government, RSS, API or disclosure feeds where available.
  [6.1.6 audit] Current status of every source in HTML_SOURCES, explicit
  before/after:
    - Converted to structured feeds and suppressed from the generic HTML
      loop via REPLACED_GENERIC_HTML_SOURCES: Fortinet PSIRT (RSS),
      HPE Security Bulletin Library (RSS, 6.1.5), Okta Security (RSS),
      CISA ICS Advisories (structured JSON via cisagov/CSAF, 6.1.4).
    - Fixed this session (selector/URL bugs, still HTML but now working):
      Nozomi Networks Labs Blog (href-pattern selectors), Trend Micro
      Research (was miscategorised as RSS with a broken URL, now fixed).
    - Migrated to RSS entirely (no longer in HTML_SOURCES): Kubernetes
      Official CVE Feed (JSON Feed, 6.1.5), NSM NCSC Security Warnings
      (confirmed working RSS, 6.1.6), Nozomi Networks PSIRT (RSS -
      also fixed a real dispatch bug, see below).
    - Wrapped in the 3-tier resilient fallback (semantic-tag tier, then
      fully structure-agnostic tier as of 6.1.6): NIST CSRC News, ISACA
      News and Trends, ISO News, Splunk Security Blog, Dragos, FBI Cyber
      News.
    - Still plain HTML scrape, not yet audited/converted this session:
      Anthropic News, Salesforce Security Blog, Shadowserver Foundation,
      Cisco Talos, FortiGuard Labs Threat Research, Apple Security
      Releases (SOFA identified as the right replacement, blocked on
      URL ambiguity - see below), ENISA News, PCI Security Standards
      Council, NSM Updates, Elastic Security Labs, Claroty Team82
      (has its own dedicated dashboard parser, not a generic scrape).
- [DONE 6.1.6] Found and fixed two real source-dispatch bugs during the
  above audit: "Nozomi Networks PSIRT" (source_type="rss") was
  physically grouped inside the HTML_SOURCES Python tuple next to a
  topically-related HTML source; "Salesforce Security Blog"
  (source_type="html") was physically grouped inside RSS_SOURCES the
  same way. app.py's dispatch loops call fetch_html()/fetch_rss()
  based on which tuple a source is defined in, not its source_type field
  - both had been silently getting the wrong fetch function called on
  them. Both moved to their correct tuple; added a permanent regression
  test (test_smoke.py) verifying every RSS_SOURCES entry has
  source_type="rss" and every HTML_SOURCES entry has source_type="html",
  so this class of mistake cannot silently recur.
- Evaluate public GuidePoint Security GRIT research as Tier-B supporting
  threat intelligence. [RESEARCHED 6.1.6] GuidePoint's "GRIT Threat
  Feed" is a paid/curated commercial product ("Advisory Services",
  "Platform Services" per their own site) - same category as CrowdStrike,
  conflicts with the no-paid-dependencies principle. Their GRIT Blog
  (quarterly ransomware/threat reports with real data - e.g. Q2 2025
  report tracked 71 active ransomware groups, sector-targeting stats) is
  genuinely valuable free Tier-B content and worth adding, but no
  confirmed RSS feed URL was found via search - same discipline as the
  Apple/SOFA situation: get a real fetch of guidepointsecurity.com/blog
  before building, rather than guessing a feed URL.
- Do not introduce paid/licensed dependencies solely for source enrichment.
- [DONE - code] `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` added to both
  `daily-security-brief.yml` and `weekly-vulnerability-report.yml`.
  [STILL PENDING - apply] Could not be pushed via PAT (GitHub blocks PAT
  pushes to workflow files without a separate `Workflows` scope) -
  delivered as standalone files for manual application twice now
  (2026-08-29 and 2026-09-01). Confirm these were actually applied to
  the live workflow files before considering this closed.
- Norwegian sector-CERT coverage confirmed structurally blocked for
  HelseCERT, KraftCERT and FinansCERT/NFCERT (closed sector-ISAC models, no
  public feed) — not revisitable without direct membership access.
- Symantec/Broadcom vendor coverage remains blocked: advisories are
  login-gated on the Broadcom Support Portal with no public feed.
- [DONE 6.1.5] Trend Micro Research feed URL fixed (http, not https - the
  https variant does not resolve, was causing "temporarily unavailable").
- [DONE 6.1.5] Nozomi Networks Labs Blog selectors fixed: the site is
  Webflow-built (no semantic h2/h3/article wrapper tags), so the original
  selectors matched zero elements. Replaced with href-pattern selectors
  matching the site's actual /blog/{slug} link convention.
- Anthropic News, Salesforce Security Blog and Apple Security Releases
  (item 2 and related): still not live-DOM-verified from this sandbox
  (no network access to any of these three domains). Anthropic and
  Salesforce use plausible, pattern-matched selectors (href-pattern for
  Anthropic, semantic-tag for Salesforce - the latter is the same class
  of risk that broke Nozomi Blog, though Salesforce's real WordPress-
  style markup makes it lower-risk than Nozomi's Webflow markup was).
  Apple has no usable path at all without either scraping (currently
  done, unverified) or confirming SOFA's real current URL. Get real
  page HTML/fetch access for any of the three to close this out properly.
- Nozomi Networks Vulnerability Advisories page (nozominetworks.com/vulnerability-advisories)
  identified as high-value (third-party OT/ICS/IoT CVE disclosures from
  Nozomi Labs, openly available, no login) but structurally unsuited to the
  generic link-based HTML collector: content is duplicated in the DOM
  (table + card responsive layouts render the same rows twice) and most
  rows have no reliable per-item link to Nozomi's own domain (the
  "Details" link is a dead `#` on most rows; "Notification" links point
  to third-party vendor PDFs, GitHub, or CISA advisories, not a Nozomi
  page). Needs a dedicated row-based table parser (like
  `parse_hpe_security_bulletins_html`), keyed on the CVE-ID text itself,
  not a `Source(selectors=...)` config. Building this blind carries a real
  risk of silent duplication (not just clean failure) given the doubled
  DOM - get real page HTML (view-source/curl from a machine with access)
  before implementing.
- Nozomi Networks Threat Intelligence Feed (STIX 2.0/2.1 over a hosted
  TAXII server) identified as the proper structured alternative to scraping
  entirely: official, documented REST protocol (TAXII 2.x), IOCs
  (IPs/domains/URLs/hashes) plus YARA/Sigma/packet detection rules and
  vulnerability descriptions. Marketed explicitly for IT+OT ingestion
  (Splunk, QRadar, Azure Sentinel are Nozomi's own example targets, not
  just OT sensors). Sold standalone, independent of owning Guardian/Vantage
  sensors, via AWS Marketplace or a reseller (e.g. BAKOTECH). To pursue:
  (1) purchase the subscription - business/procurement decision, not
  technical; (2) Nozomi provisions TAXII server credentials on purchase;
  (3) build a TAXII 2.x client collector against Nozomi's published
  "Threat Intelligence Feed - Configuration Guide" once credentials exist.
  Scope caveat: this is tactical IOC/detection-rule content, not the
  narrative CVE write-ups from the Vulnerability Advisories page above -
  complementary, not a replacement.
- Two lower-cost paths worth trying before any purchase decision: (a)
  email Nozomi PSIRT/Labs directly (prodsec@nozominetworks.com) to ask
  whether structured API access to the Vulnerability Advisories dataset
  specifically exists for legitimate aggregation/research use, independent
  of the commercial TI feed; (b) if NetNordic does not already have a
  Nozomi partner relationship, explore whether one would open up better
  data access as a side benefit.
- Salesforce Security Blog is HTML-scraped with best-effort selectors,
  unverified against live DOM — same caveat as Anthropic News above.
- [DONE 6.1.5] HPE Security Bulletin Library switched from custom HTML
  table scrape to HPE's official RSS feed. CVSS/severity extraction from
  the feed's item description is best-effort and unverified against real
  feed content in this environment — confirm on the next real run whether
  severity data is actually present, and whether it's as complete as the
  old parser's direct table-column extraction. Old parser code kept as
  fallback (`priority_vendor_sources.fetch_hpe_security_bulletins`), not
  wired into any task.
- BankInfoSecurity has a real, confirmed-active official RSS feed
  (bankinfosecurity.com/rss-feeds shows genuine current article content),
  but the exact `.xml`/feed endpoint wasn't pinned down — worth switching
  from the current HTML scrape once confirmed, given BankInfoSecurity is
  one of the pre-existing historically-fragile sources.
- Apple Security Releases: Apple itself has no official RSS/feed at all
  (confirmed). SOFA (sofa.macadmins.io, MacAdmins community project) is
  the right replacement — JSON feed, updated every 6h via GitHub Actions,
  and critically flags `ActivelyExploitedCVEs` directly, which the current
  scraper has no equivalent for. Do NOT implement from search results
  alone: multiple sources gave conflicting URLs (`sofa.macadmins.io/v2/...`
  vs `sofafeed.macadmins.io/v1/...` vs a 2024 migration notice) - confirm
  the live, current URL via a real fetch before building, same lesson as
  the Trend Micro http/https mistake.

## Priority 3 — Sector relevance

Implemented in 6.1.4: Retail, Housing Estates/BoligByggerlag, and Energy
(split from Oil & Gas) across both `RELEVANCE_RULES` and
`SECTOR_IMPACT_RULES`.

## Priority 4 — GRC & Standards redesign

- Add direct source/deep-dive links for current changes and forward-look milestones.
- Expand authoritative EU, Norway, Sweden, Finland and Denmark coverage.
- Strengthen NIS2, DORA, EU AI Act, Cyber Resilience Act and national implementation coverage.
- Expand relevant ISO/IEC security, risk, privacy, resilience and management-system coverage.
- Maintain a persistent governance horizon with verified dates and primary sources.

## Priority 5 — Reliability, security and CI integrity

- Pin Python dependencies with hashes.
- Generate a machine-readable CycloneDX or SPDX SBOM.
- Review `main` branch protection and require Repository CI before merge.
- Review repository visibility against the proprietary/confidential project posture.
- Add parser-fixture tests for source pages that have historically changed templates.
- Consider a controlled source-health canary that checks parser structure without
  treating publication cadence as collector failure.

## Priority 6 — Maintainability

- Fold the report-policy compatibility/monkey-patch layer into the main renderer
  during the next structural refactor.
- Continue extracting self-contained Daily presentation components where this
  improves testability.
- Keep source policy, evidence policy, presentation and orchestration boundaries explicit.

## Priority 7 — Historical capability

- Extend the optional private report archive with daily/weekly/monthly comparison.
- Reuse historical state for meaningful change detection rather than repeating unchanged intelligence.
- Consider backfilling the Weekly 13-week trend database from trusted historical
  advisory data so a new installation does not need 13 weeks to reach full depth.
- Avoid paid infrastructure unless operationally justified.
