# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from security_brief.weekly_trends import build_quarterly_vulnerability_trend


class WeeklyTrendTests(unittest.TestCase):
    def test_quarterly_trend_counts_each_cve_once_by_first_observed_week(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE vulnerabilities (
                    cve TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    title TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_tier TEXT NOT NULL,
                    link TEXT NOT NULL,
                    published TEXT NOT NULL,
                    action TEXT NOT NULL,
                    affected TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    confidence TEXT NOT NULL DEFAULT 'Single-source report',
                    corroboration_count INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE observations (
                    cve TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    report_date TEXT NOT NULL,
                    cvss REAL,
                    epss REAL NOT NULL,
                    kev INTEGER NOT NULL,
                    exploited INTEGER NOT NULL,
                    ransomware INTEGER NOT NULL,
                    zero_day INTEGER NOT NULL,
                    priority_score INTEGER NOT NULL,
                    remediation_band TEXT NOT NULL,
                    PRIMARY KEY (cve, report_date)
                );
                """
            )
            connection.execute(
                """
                INSERT INTO vulnerabilities
                (cve, first_seen, last_seen, title, vendor, product, category,
                 source, source_tier, link, published, action, affected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "CVE-2026-11111",
                    "2026-08-03T08:00:00+00:00",
                    "2026-08-10T08:00:00+00:00",
                    "Test",
                    "Fortinet",
                    "FortiOS",
                    "Network / Security Appliances",
                    "Test",
                    "A",
                    "https://example.invalid",
                    "2026-08-03T08:00:00+00:00",
                    "Patch",
                    "FortiOS",
                ),
            )
            for report_date in ("2026-08-03", "2026-08-10"):
                connection.execute(
                    """
                    INSERT INTO observations
                    (cve, observed_at, report_date, cvss, epss, kev, exploited,
                     ransomware, zero_day, priority_score, remediation_band)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CVE-2026-11111",
                        report_date + "T08:00:00+00:00",
                        report_date,
                        9.8,
                        0.5,
                        1,
                        1,
                        0,
                        1,
                        90,
                        "Patch immediately",
                    ),
                )
            connection.commit()
            connection.close()

            trend = build_quarterly_vulnerability_trend(
                path,
                date(2026, 8, 21),
            )

        self.assertEqual(trend["totals"]["Zero-Day"], 1)
        self.assertEqual(trend["totals"]["Critical"], 1)
        self.assertEqual(
            sum(week["Critical"] for week in trend["weeks"]),
            1,
        )
        self.assertEqual(len(trend["weeks"]), 13)

    def test_missing_history_returns_thirteen_zero_weeks(self) -> None:
        trend = build_quarterly_vulnerability_trend(
            "/does/not/exist.sqlite3",
            date(2026, 8, 21),
        )
        self.assertEqual(len(trend["weeks"]), 13)
        self.assertEqual(sum(trend["totals"].values()), 0)


if __name__ == "__main__":
    unittest.main()
