# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Rolling-quarter vulnerability trend analysis for the Weekly report."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

SERIES = ("Zero-Day", "Critical", "High", "Medium")


def _monday(value: date) -> date:
    return value - timedelta(days=value.weekday())


def _week_labels(as_of: date, weeks: int = 13) -> list[date]:
    current = _monday(as_of)
    first = current - timedelta(weeks=max(1, weeks) - 1)
    return [first + timedelta(weeks=index) for index in range(max(1, weeks))]


def _empty(as_of: date, weeks: int = 13) -> dict[str, Any]:
    starts = _week_labels(as_of, weeks)
    return {
        "weeks": [
            {
                "week_start": value.isoformat(),
                "label": f"W{value.isocalendar().week:02d}",
                "Zero-Day": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
            }
            for value in starts
        ],
        "totals": {series: 0 for series in SERIES},
        "latest_four": {series: 0 for series in SERIES},
        "previous_four": {series: 0 for series in SERIES},
        "direction": "stable",
        "direction_delta": 0,
        "peak_week": "",
        "peak_count": 0,
        "concentrations": [],
        "counting_note": (
            "Each CVE is counted once, in the week it was first observed in lifecycle "
            "history. Zero-Day is an additional series and may overlap a severity series."
        ),
    }


def _parse_date(value: object) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def build_quarterly_vulnerability_trend(
    database_path: str | Path,
    as_of: date,
    *,
    weeks: int = 13,
) -> dict[str, Any]:
    """Build a first-observed 13-week Zero-Day/Critical/High/Medium trend."""

    result = _empty(as_of, weeks)
    path = Path(database_path)
    if not path.exists():
        return result

    starts = _week_labels(as_of, weeks)
    start_date = starts[0]
    index_by_start = {value: index for index, value in enumerate(starts)}

    try:
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                v.cve,
                v.vendor,
                v.category,
                v.first_seen,
                MIN(o.report_date) AS first_report_date,
                MAX(COALESCE(o.cvss, 0)) AS max_cvss,
                MAX(o.zero_day) AS ever_zero_day
            FROM vulnerabilities v
            JOIN observations o ON o.cve = v.cve
            WHERE o.report_date BETWEEN ? AND ?
            GROUP BY v.cve, v.vendor, v.category, v.first_seen
            """,
            (start_date.isoformat(), as_of.isoformat()),
        ).fetchall()
    except sqlite3.Error:
        return result
    finally:
        try:
            connection.close()
        except (UnboundLocalError, sqlite3.Error):
            pass

    concentrations: dict[tuple[str, str], int] = {}
    for row in rows:
        first_seen = _parse_date(row["first_seen"]) or _parse_date(row["first_report_date"])
        if first_seen is None or first_seen < start_date or first_seen > as_of:
            continue
        bucket_index = index_by_start.get(_monday(first_seen))
        if bucket_index is None:
            continue
        bucket = result["weeks"][bucket_index]
        cvss = float(row["max_cvss"] or 0.0)

        if bool(row["ever_zero_day"]):
            bucket["Zero-Day"] += 1
        if cvss >= 9.0:
            bucket["Critical"] += 1
        elif cvss >= 7.0:
            bucket["High"] += 1
        elif cvss >= 4.0:
            bucket["Medium"] += 1

        key = (str(row["vendor"] or "Unknown"), str(row["category"] or "Unclassified"))
        concentrations[key] = concentrations.get(key, 0) + 1

    for series in SERIES:
        result["totals"][series] = sum(int(bucket[series]) for bucket in result["weeks"])
        result["latest_four"][series] = sum(int(bucket[series]) for bucket in result["weeks"][-4:])
        result["previous_four"][series] = sum(int(bucket[series]) for bucket in result["weeks"][-8:-4])

    latest_material = sum(result["latest_four"].values())
    previous_material = sum(result["previous_four"].values())
    delta = latest_material - previous_material
    result["direction_delta"] = delta
    if previous_material == 0:
        result["direction"] = "increasing" if latest_material > 0 else "stable"
    else:
        ratio = delta / previous_material
        result["direction"] = (
            "increasing" if ratio >= 0.15 else
            "decreasing" if ratio <= -0.15 else
            "stable"
        )

    peak = max(
        result["weeks"],
        key=lambda bucket: sum(int(bucket[series]) for series in SERIES),
        default=None,
    )
    if peak:
        result["peak_week"] = str(peak["label"])
        result["peak_count"] = sum(int(peak[series]) for series in SERIES)

    result["concentrations"] = [
        {"vendor": vendor, "category": category, "count": count}
        for (vendor, category), count in sorted(
            concentrations.items(),
            key=lambda item: (item[1], item[0][0], item[0][1]),
            reverse=True,
        )[:5]
    ]
    return result


__all__ = ["SERIES", "build_quarterly_vulnerability_trend"]
