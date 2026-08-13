from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from security_brief.archive import archive_report


class ArchiveTests(unittest.TestCase):
    def test_archive_is_opt_in_and_writes_private_snapshot(self) -> None:
        self.assertIsNone(archive_report(generated_at=datetime.now(timezone.utc), html_body="<p>x</p>", text_body="x", summary={}))
        with tempfile.TemporaryDirectory() as directory:
            os.environ["REPORT_ARCHIVE_DIR"] = directory
            result = archive_report(generated_at=datetime(2026, 8, 13, tzinfo=timezone.utc), html_body="<p>x</p>", text_body="x", summary={"items": 1})
            self.assertEqual(result.name, Path(directory).name)
            self.assertEqual(len(list(Path(directory).glob("daily-*"))), 3)
        os.environ.pop("REPORT_ARCHIVE_DIR", None)
