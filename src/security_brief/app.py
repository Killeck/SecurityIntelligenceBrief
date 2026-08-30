# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Application orchestration for the Daily Security Brief."""

from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Generic, TypeVar

from .analysis import (
    advisory_status,
    build_detection_opportunities,
    build_open_source_exposure_signals,
    build_regional_links,
    build_sector_impacts,
    deduplicate,
    deduplicate_exposure_signals,
    select_executive_news,
    select_final_items,
)
from .archive import archive_report
from .dedup_state import suppress_recent_duplicates
from .collectors import (
    enrich_nvd,
    fetch_executive_news_html,
    fetch_executive_news_rss,
    fetch_hibp_breaches,
    fetch_hibp_domain_exposure,
    fetch_html,
    fetch_github_advisories,
    fetch_kev,
    fetch_rss,
)
from .config import EMAIL_SUBJECT, OSLO_TIMEZONE
from .sources import (
    EXECUTIVE_NEWS_HTML,
    EXECUTIVE_NEWS_RSS,
    HTML_SOURCES,
    RSS_SOURCES,
)
from .delivery import send_email
from .governance import (
    deduplicate_governance_events,
    detect_governance_go_live_events,
    load_configured_governance_events,
)
from .models import ExposureSignal, Item, NewsLink
from .pipeline_state import (
    effective_daily_cutoff,
    effective_lookback_hours,
    mark_daily_success,
)
from .priority_vendor_sources import (
    AUTHORITATIVE_VENDOR_RSS_SOURCES,
    REPLACED_GENERIC_HTML_SOURCES,
    fetch_authoritative_vendor_rss,
    fetch_priority_vendor_nvd,
)
from .hpe_security_bulletins_rss import fetch_hpe_security_bulletins_rss
from .cisa_csaf import fetch_cisa_csaf_branch
from .ai_security_trackers import fetch_mitre_atlas_updates, fetch_owasp_llm_top10_updates
from .kubernetes_cve_feed import fetch_kubernetes_cve_feed
from .open_source_sources import OPEN_VULNERABILITY_SOURCES
from .report_policy import ensure_mandatory_vulnerabilities, render_report
from .runtime_profile import RuntimeProfiler
from .source_config import (
    configure_mapping_sources,
    configure_sources,
    load_source_overrides,
)
from .source_health import assess_and_persist
from .source_resilience import (
    RESILIENT_HTML_SOURCES,
    fetch_claroty_team82_disclosures,
    fetch_resilient_html,
)
from .utils import (
    csv_setting,
    integer_setting,
    kev_lookback_days,
    reporting_window_hours,
    required,
)


T = TypeVar("T")


HISTORICAL_CONTEXT_SOURCES = frozenset(
    {
        "Microsoft Security Response Center",
        "Google Threat Intelligence",
        "Palo Alto Unit 42",
        "CrowdStrike Blog",
        "The DFIR Report",
        "Cisco Talos",
        "FortiGuard Labs Threat Research",
        "Dragos",
        "Nozomi Networks Labs Blog",
    }
)


@dataclass(frozen=True)
class RuntimeSettings:
    """Environment-derived settings resolved once per pipeline execution."""

    username: str
    client_id: str
    client_secret: str
    refresh_token: str
    recipient: str
    lookback_hours: int
    max_items: int
    kev_days: int
    upcoming_days: int
    exposure_max: int
    executive_news_max: int
    source_workers: int
    dedup_days: int
    vendor_context_days: int
    monitored_brands: tuple[str, ...]
    monitored_domains: tuple[str, ...]
    hibp_api_key: str

    @classmethod
    def from_environment(cls) -> "RuntimeSettings":
        """Validate required secrets and load bounded optional settings."""

        lookback_hours = reporting_window_hours()
        return cls(
            username=required("GMAIL_USERNAME"),
            client_id=required("GMAIL_CLIENT_ID"),
            client_secret=required("GMAIL_CLIENT_SECRET"),
            refresh_token=required("GMAIL_REFRESH_TOKEN"),
            recipient=required("EMAIL_TO"),
            lookback_hours=lookback_hours,
            max_items=integer_setting(
                "NEWS_MAX_ITEMS",
                default=40,
                minimum=5,
                maximum=80,
            ),
            kev_days=kev_lookback_days(lookback_hours),
            upcoming_days=integer_setting(
                "UPCOMING_GOVERNANCE_DAYS",
                default=365,
                minimum=14,
                maximum=365,
            ),
            exposure_max=integer_setting(
                "EXPOSURE_MAX_ITEMS",
                default=20,
                minimum=5,
                maximum=60,
            ),
            executive_news_max=integer_setting(
                "EXEC_NEWS_MAX_ITEMS",
                default=10,
                minimum=1,
                maximum=20,
            ),
            source_workers=integer_setting(
                "SOURCE_WORKERS",
                default=8,
                minimum=1,
                maximum=16,
            ),
            dedup_days=integer_setting(
                "DAILY_DEDUP_DAYS",
                default=7,
                minimum=1,
                maximum=90,
            ),
            vendor_context_days=integer_setting(
                "VENDOR_CONTEXT_DAYS",
                default=90,
                minimum=30,
                maximum=180,
            ),
            monitored_brands=csv_setting("MONITORED_BRANDS"),
            monitored_domains=csv_setting("MONITORED_DOMAINS"),
            hibp_api_key=os.getenv("HIBP_API_KEY", "").strip(),
        )


@dataclass
class PipelineState:
    """Mutable pipeline collections kept together to simplify orchestration."""

    primary_items: list[Item] = field(default_factory=list)
    exposure_candidates: list[ExposureSignal] = field(default_factory=list)
    news_candidates: list[NewsLink] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_health: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class FetchTask(Generic[T]):
    """A named source operation with reporting metadata."""

    name: str
    fetch: Callable[[], list[T]]
    detail: str = ""
    unit: str = "item(s)"
    freshness_days: int = 14


@dataclass(frozen=True)
class FetchOutcome(Generic[T]):
    """Normalised success or failure result from one source operation."""

    task: FetchTask[T]
    values: list[T]
    error: Exception | None = None


def _execute_task(task: FetchTask[T]) -> FetchOutcome[T]:
    try:
        return FetchOutcome(task=task, values=task.fetch())
    except Exception as error:  # Source isolation is intentional.
        return FetchOutcome(task=task, values=[], error=error)


def _newest_value_timestamp(values: list[Any]) -> str:
    candidates: list[datetime] = []
    for value in values:
        for attribute in ("published", "observed"):
            timestamp = getattr(value, attribute, None)
            if not isinstance(timestamp, datetime):
                continue
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            candidates.append(timestamp.astimezone(timezone.utc))
            break
    return max(candidates).isoformat() if candidates else ""


def collect_tasks(
    tasks: list[FetchTask[T]],
    target: list[T],
    state: PipelineState,
    *,
    workers: int,
) -> None:
    """Fetch independent sources concurrently and record ordered health data."""

    if not tasks:
        return
    worker_count = min(workers, len(tasks))
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="brief-source",
    ) as executor:
        outcomes = executor.map(_execute_task, tasks)
        for outcome in outcomes:
            task = outcome.task
            if outcome.error is None:
                target.extend(outcome.values)
                state.source_health.append(
                    assess_and_persist(
                        {
                            "source": task.name,
                            "status": "OK",
                            "health_state": "CONTENT" if outcome.values else "QUIET",
                            "items": len(outcome.values),
                            "detail": task.detail,
                            "checked_at": datetime.now(timezone.utc).isoformat(),
                            "newest_item": _newest_value_timestamp(outcome.values),
                        },
                        freshness_days=task.freshness_days,
                    )
                )
                print(f"{task.name}: {len(outcome.values)} {task.unit}")
                continue

            error = outcome.error
            detail = f"{type(error).__name__}: {error}"
            warning = f"{task.name}: {detail}"
            state.warnings.append(warning)
            state.source_health.append(
                assess_and_persist(
                    {
                        "source": task.name,
                        "status": "FAILED",
                        "health_state": "FAILED",
                        "items": 0,
                        "detail": detail,
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                        "newest_item": "",
                    },
                    freshness_days=task.freshness_days,
                )
            )
            print(f"WARNING: {warning}", file=sys.stderr)


def primary_tasks(
    cutoff: datetime,
    kev_days: int,
    *,
    vendor_context_cutoff: datetime | None = None,
) -> list[FetchTask[Item]]:
    """Build independent primary-intelligence source operations.

    Priority-vendor advisory channels may use a longer context window than the
    normal Daily report. Their older records are retained only for vendor-status
    context; ``run_pipeline`` filters reader-facing Daily content back to the
    effective Daily/catch-up cutoff.
    """

    vendor_cutoff = vendor_context_cutoff or cutoff
    tasks: list[FetchTask[Item]] = [
        FetchTask(name="CISA KEV", fetch=lambda: fetch_kev(kev_days)),
        FetchTask(
            name="NVD priority-vendor CVEs",
            fetch=lambda: fetch_priority_vendor_nvd(cutoff),
            detail="Priority-vendor CVE corroboration and fallback",
        ),
    ]

    overrides = load_source_overrides()
    tasks.extend(
        FetchTask(
            name=source.name,
            fetch=lambda source=source: fetch_authoritative_vendor_rss(
                source,
                vendor_cutoff,
            ),
            detail="Authoritative vendor security bulletin feed with historical context",
            freshness_days=source.freshness_days,
        )
        for source in configure_sources(AUTHORITATIVE_VENDOR_RSS_SOURCES, overrides)
    )
    tasks.append(
        FetchTask(
            name="HPE Security Bulletin Library",
            fetch=lambda: fetch_hpe_security_bulletins_rss(vendor_cutoff),
            detail="Official HPE Security Bulletin RSS feed",
            freshness_days=30,
        )
    )

    if overrides.get("Claroty Team82", {}).get("enabled") is not False:
        tasks.append(
            FetchTask(
                name="Claroty Team82",
                fetch=lambda: fetch_claroty_team82_disclosures(vendor_cutoff),
                detail="Structured Team82 CPS vulnerability disclosure dashboard",
                freshness_days=45,
            )
        )

    tasks.extend(
        FetchTask(
            name=f"CISA CSAF - {branch} Advisories",
            fetch=lambda branch=branch: fetch_cisa_csaf_branch(branch, vendor_cutoff),
            detail=(
                "Structured CISA advisory JSON (cisagov/CSAF) - replaces HTML "
                "scraping with CVE/CVSS/tracking-date fields read directly "
                "from the source document."
            ),
            freshness_days=14,
        )
        for branch in ("OT", "IT", "VA")
        if overrides.get(f"CISA CSAF - {branch} Advisories", {}).get("enabled") is not False
    )

    if overrides.get("MITRE ATLAS Framework Updates", {}).get("enabled") is not False:
        tasks.append(
            FetchTask(
                name="MITRE ATLAS Framework Updates",
                fetch=lambda: fetch_mitre_atlas_updates(vendor_cutoff),
                detail="AI Security & Trustworthiness: adversarial-AI framework releases",
                freshness_days=45,
            )
        )

    if overrides.get("OWASP GenAI LLM Top 10 Updates", {}).get("enabled") is not False:
        tasks.append(
            FetchTask(
                name="OWASP GenAI LLM Top 10 Updates",
                fetch=lambda: fetch_owasp_llm_top10_updates(vendor_cutoff),
                detail="AI Security & Trustworthiness: OWASP GenAI LLM Top 10 changes",
                freshness_days=60,
            )
        )

    if overrides.get("Kubernetes Official CVE Feed", {}).get("enabled") is not False:
        tasks.append(
            FetchTask(
                name="Kubernetes Official CVE Feed",
                fetch=lambda: fetch_kubernetes_cve_feed(vendor_cutoff),
                detail="Official Kubernetes CVE JSON Feed (kubernetes.io)",
                freshness_days=30,
            )
        )

    tasks.extend(
        FetchTask(
            name=source.name,
            fetch=lambda source=source: fetch_github_advisories(source, cutoff),
            detail="Open-source vulnerability corroboration",
            freshness_days=source.freshness_days,
        )
        for source in configure_sources(OPEN_VULNERABILITY_SOURCES, overrides)
    )
    tasks.extend(
        FetchTask(
            name=source.name,
            fetch=lambda source=source: fetch_rss(
                source,
                vendor_cutoff if source.name in HISTORICAL_CONTEXT_SOURCES else cutoff,
            ),
            freshness_days=source.freshness_days,
        )
        for source in configure_sources(RSS_SOURCES, overrides)
    )

    for source in configure_sources(HTML_SOURCES, overrides):
        if source.name in REPLACED_GENERIC_HTML_SOURCES or source.name == "Claroty Team82":
            continue
        source_cutoff = (
            vendor_cutoff
            if source.name == "Apple Security Releases" or source.name in HISTORICAL_CONTEXT_SOURCES
            else cutoff
        )
        fetcher = fetch_resilient_html if source.name in RESILIENT_HTML_SOURCES else fetch_html
        tasks.append(
            FetchTask(
                name=source.name,
                fetch=lambda source=source, source_cutoff=source_cutoff, fetcher=fetcher: fetcher(
                    source,
                    source_cutoff,
                ),
                detail=(
                    "Historical vendor/threat context"
                    if source.name == "Apple Security Releases" or source.name in HISTORICAL_CONTEXT_SOURCES
                    else "Primary HTML intelligence"
                ),
                freshness_days=source.freshness_days,
            )
        )
    return tasks


def exposure_tasks(
    settings: RuntimeSettings,
    cutoff: datetime,
) -> list[FetchTask[ExposureSignal]]:
    tasks = [
        FetchTask(
            name="Have I Been Pwned breach catalogue",
            fetch=lambda: fetch_hibp_breaches(cutoff),
            detail="Public breach metadata",
            unit="new exposure signal(s)",
        )
    ]
    if settings.monitored_domains and settings.hibp_api_key:
        tasks.append(
            FetchTask(
                name="Have I Been Pwned domain search",
                fetch=lambda: fetch_hibp_domain_exposure(
                    settings.monitored_domains,
                    settings.hibp_api_key,
                ),
                detail=f"{len(settings.monitored_domains)} verified domain(s) configured",
                unit="domain exposure signal(s)",
            )
        )
    return tasks


def discovery_tasks(cutoff: datetime) -> list[FetchTask[NewsLink]]:
    """Build secondary discovery operations with BankInfoSecurity RSS fallback."""

    overrides = load_source_overrides()
    tasks = [
        FetchTask(
            name=source["name"],
            fetch=lambda source=source: fetch_executive_news_rss(source, cutoff),
            detail="Executive news discovery",
            unit="relevant news link(s)",
        )
        for source in configure_mapping_sources(EXECUTIVE_NEWS_RSS, overrides)
    ]
    for source in configure_mapping_sources(EXECUTIVE_NEWS_HTML, overrides):
        if source["name"] == "BankInfoSecurity":
            tasks.append(
                FetchTask(
                    name=source["name"],
                    fetch=lambda source=source: fetch_executive_news_rss(source, cutoff),
                    detail="Executive news discovery via BankInfoSecurity RSS",
                    unit="relevant news link(s)",
                )
            )
        else:
            tasks.append(
                FetchTask(
                    name=source["name"],
                    fetch=lambda source=source: fetch_executive_news_html(source, cutoff),
                    detail="Executive news discovery",
                    unit="relevant news link(s)",
                )
            )
    return tasks


def run_pipeline(settings: RuntimeSettings) -> None:
    """Collect, analyse, render and deliver one briefing."""

    local_now = datetime.now(OSLO_TIMEZONE)
    utc_now = datetime.now(timezone.utc)
    cutoff = effective_daily_cutoff(utc_now, settings.lookback_hours)
    effective_hours = effective_lookback_hours(utc_now, cutoff)
    vendor_context_cutoff = utc_now - timedelta(days=settings.vendor_context_days)
    state = PipelineState()
    profiler = RuntimeProfiler("daily")

    if effective_hours > settings.lookback_hours:
        print(
            f"Reporting window expanded to {effective_hours} hours to catch up from the last successful delivery."
        )
    else:
        print(
            f"Reporting window: {effective_hours} hours "
            f"(Europe/Oslo weekday={local_now.strftime('%A')})"
        )
    print(f"Vendor status context: {settings.vendor_context_days} days")
    print(f"Parallel source workers: {settings.source_workers}")

    with profiler.stage("collection"):
        collect_tasks(
            primary_tasks(
                cutoff,
                settings.kev_days,
                vendor_context_cutoff=vendor_context_cutoff,
            ),
            state.primary_items,
            state,
            workers=settings.source_workers,
        )
        collect_tasks(
            exposure_tasks(settings, cutoff),
            state.exposure_candidates,
            state,
            workers=min(settings.source_workers, 2),
        )
        collect_tasks(
            discovery_tasks(cutoff),
            state.news_candidates,
            state,
            workers=settings.source_workers,
        )

    # ``status_items`` includes the longer authoritative vendor context. Only
    # records inside the effective Daily/catch-up window enter the actual report.
    status_items = deduplicate(state.primary_items)
    report_candidates = [item for item in status_items if item.published >= cutoff]

    with profiler.stage("enrichment"):
        enrich_nvd(report_candidates, state.warnings)

    status_items.sort(key=lambda item: (item.score, item.published), reverse=True)
    report_candidates.sort(key=lambda item: (item.score, item.published), reverse=True)
    items = select_final_items(report_candidates, settings.max_items)
    items = ensure_mandatory_vulnerabilities(items, report_candidates)
    items, suppressed_duplicates = suppress_recent_duplicates(
        items,
        now=utc_now,
        retention_days=settings.dedup_days,
    )
    if suppressed_duplicates:
        print(f"Persistent duplicates suppressed: {suppressed_duplicates}")

    executive_news = select_executive_news(
        state.news_candidates,
        items,
        settings.executive_news_max,
    )
    state.exposure_candidates.extend(
        build_open_source_exposure_signals(
            items,
            executive_news,
            settings.monitored_brands,
            settings.monitored_domains,
            max_items=settings.exposure_max,
        )
    )
    exposure_signals = deduplicate_exposure_signals(
        state.exposure_candidates,
        settings.exposure_max,
    )
    sector_impacts = build_sector_impacts(items, executive_news, max_items=5)
    detection_opportunities = build_detection_opportunities(items, max_items=6)
    regional_links = build_regional_links(items, executive_news, max_items=8)

    today = local_now.date()
    upcoming_events = deduplicate_governance_events(
        load_configured_governance_events(
            today,
            settings.upcoming_days,
            state.warnings,
        )
        + detect_governance_go_live_events(
            report_candidates,
            today,
            settings.upcoming_days,
        )
    )

    with profiler.stage("rendering"):
        text_body, html_body = render_report(
            items,
            state.warnings,
            effective_hours,
            upcoming_events,
            settings.upcoming_days,
            state.source_health,
            executive_news,
            sector_impacts,
            detection_opportunities,
            regional_links,
            exposure_signals,
            settings.monitored_brands,
            settings.monitored_domains,
            status_items=status_items,
        )

    advisory = advisory_status(items, exposure_signals)
    subject = EMAIL_SUBJECT
    archive_directory = archive_report(
        generated_at=utc_now,
        html_body=html_body,
        text_body=text_body,
        summary={
            "advisory": advisory["display"],
            "items": len(items),
            "exposure_signals": len(exposure_signals),
            "warnings": len(state.warnings),
            "effective_lookback_hours": effective_hours,
        },
    )

    with profiler.stage("delivery"):
        send_email(
            settings.username,
            settings.client_id,
            settings.client_secret,
            settings.refresh_token,
            settings.recipient,
            subject,
            text_body,
            html_body,
        )
    mark_daily_success(utc_now)

    profile = profiler.persist()
    print(
        f"Briefing sent: {advisory['display']}, "
        f"{len(items)} item(s), "
        f"{len(upcoming_events)} upcoming event(s), "
        f"{len(executive_news)} relevant news link(s), "
        f"{len(exposure_signals)} exposure signal(s), "
        f"{len(sector_impacts)} sector impact(s), "
        f"{len(detection_opportunities)} detection opportunity(s), "
        f"{len(regional_links)} regional link(s), "
        f"{len(state.warnings)} warning(s)."
    )
    print(f"Total profiled runtime: {profile['total_seconds']:.3f}s")
    if archive_directory:
        print(f"Private report archive updated: {archive_directory}")


def main() -> int:
    try:
        run_pipeline(RuntimeSettings.from_environment())
        return 0
    except Exception as error:
        print(f"Pipeline failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
