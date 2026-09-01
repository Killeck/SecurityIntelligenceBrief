# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.
# Last modified: v6.1.6

"""Orchestration for the Weekly Vulnerability Report."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .analysis import deduplicate
from .app import PipelineState, collect_tasks, primary_tasks
from .collectors import enrich_nvd
from .config import OSLO_TIMEZONE, PROJECT_ROOT
from .delivery import send_email
from .runtime_profile import RuntimeProfiler
from .utils import integer_setting, required
from .vulnerability_reporting import (
    VulnerabilityStore,
    build_vulnerability_records,
    weekly_display_records,
)
from .weekly_rendering import (
    iso_week_label,
    render_weekly_vulnerability_report,
)
from .weekly_trends import build_quarterly_vulnerability_trend


@dataclass(frozen=True)
class WeeklySettings:
    """Environment-derived settings for the weekly report."""

    username: str
    client_id: str
    client_secret: str
    refresh_token: str
    recipient: str
    lookback_days: int
    max_records: int
    source_workers: int
    vendor_context_days: int
    database_path: Path

    @classmethod
    def from_environment(cls) -> "WeeklySettings":
        return cls(
            username=required("GMAIL_USERNAME"),
            client_id=required("GMAIL_CLIENT_ID"),
            client_secret=required("GMAIL_CLIENT_SECRET"),
            refresh_token=required("GMAIL_REFRESH_TOKEN"),
            recipient=required("EMAIL_TO"),
            lookback_days=integer_setting(
                "WEEKLY_LOOKBACK_DAYS",
                default=7,
                minimum=7,
                maximum=31,
            ),
            max_records=integer_setting(
                "WEEKLY_MAX_RECORDS",
                default=100,
                minimum=10,
                maximum=500,
            ),
            source_workers=integer_setting(
                "SOURCE_WORKERS",
                default=8,
                minimum=1,
                maximum=16,
            ),
            vendor_context_days=integer_setting(
                "VENDOR_CONTEXT_DAYS",
                default=90,
                minimum=30,
                maximum=180,
            ),
            database_path=Path(
                os.getenv(
                    "VULNERABILITY_DB_PATH",
                    str(PROJECT_ROOT / "data" / "vulnerability_history.sqlite3"),
                )
            ),
        )


def run_weekly_pipeline(settings: WeeklySettings) -> None:
    """Collect, prioritise, persist, render and send one weekly report."""

    local_now = datetime.now(OSLO_TIMEZONE)
    utc_now = datetime.now(timezone.utc)
    cutoff = utc_now - timedelta(days=settings.lookback_days)
    vendor_context_cutoff = utc_now - timedelta(days=settings.vendor_context_days)
    state = PipelineState()
    profiler = RuntimeProfiler("weekly")

    with profiler.stage("collection"):
        collect_tasks(
            primary_tasks(
                cutoff,
                settings.lookback_days + 7,
                vendor_context_cutoff=vendor_context_cutoff,
            ),
            state.primary_items,
            state,
            workers=settings.source_workers,
        )

    # The shared primary pipeline can contain historical vendor/threat context.
    # Only the Weekly reporting window becomes current Weekly vulnerability rows.
    with profiler.stage("enrichment"):
        all_items = deduplicate(state.primary_items)
        current_items = [item for item in all_items if item.published >= cutoff]
        ai_digest_items = [
            item
            for item in current_items
            if item.section == "AI Security and Trustworthiness"
        ]
        enrich_nvd(current_items, state.warnings)
        records = weekly_display_records(
            build_vulnerability_records(current_items, now=utc_now)
        )[: settings.max_records]

    week_end = local_now.date()
    week_start = week_end - timedelta(days=settings.lookback_days - 1)
    week_label = iso_week_label(week_end)

    with profiler.stage("lifecycle"):
        with VulnerabilityStore(settings.database_path) as store:
            changes = store.record(records, utc_now)
            mtd_records = store.month_to_date(week_end)
            monthly_counts = store.monthly_counts(week_end)

        quarterly_trend = build_quarterly_vulnerability_trend(
            settings.database_path,
            week_end,
            weeks=13,
        )

    with profiler.stage("rendering"):
        text_body, html_body = render_weekly_vulnerability_report(
            records,
            changes,
            mtd_records,
            monthly_counts,
            week_start,
            week_end,
            state.source_health,
            quarterly_trend=quarterly_trend,
            ai_digest=ai_digest_items,
        )

    subject = (
        f"Weekly Vulnerability Report — {week_label} — "
        f"{week_end.isoformat()}"
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

    profile = profiler.persist()
    print(
        f"Weekly vulnerability report sent: {week_label}, "
        f"{len(records)} CVE(s), "
        f"{len(changes)} lifecycle change(s), "
        f"{len(mtd_records)} MTD CVE(s), "
        f"{len(state.warnings)} warning(s)."
    )
    print(f"Total profiled runtime: {profile['total_seconds']:.3f}s")


def main() -> int:
    """CLI entry point with a single failure boundary."""

    try:
        run_weekly_pipeline(WeeklySettings.from_environment())
        return 0
    except Exception as error:
        print(
            f"Weekly pipeline failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
