# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Regression tests for Daily Security Brief email branding."""

from __future__ import annotations

import struct
import unittest

from security_brief.branding import (
    DEFCON_LEGEND_CONTENT_ID,
    LEGACY_REPORT_TITLE,
    LOGO_CONTENT_ID,
    load_defcon_legend_bytes,
    load_logo_bytes,
)
from security_brief.config import BRIEF_NAME, BRIEF_VERSION
from security_brief.delivery import build_message


class BrandingTests(unittest.TestCase):
    """Validate logo embedding and version placement."""

    def test_logo_is_valid_and_below_one_megabyte(self) -> None:
        logo = load_logo_bytes()

        self.assertTrue(logo.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertLessEqual(len(logo), 1_000_000)

    def test_defcon_legend_is_valid_and_compact(self) -> None:
        legend = load_defcon_legend_bytes()

        self.assertTrue(legend.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertLessEqual(len(legend), 500_000)
        self.assertEqual(struct.unpack(">II", legend[16:24]), (660, 364))

    def test_build_message_uses_logo_and_keeps_metadata_version(self) -> None:
        text_body = (
            f"{LEGACY_REPORT_TITLE}\n"
            "====================\n"
            "Reporting window: previous 24 hours\n"
        )
        html_body = f"""
        <html>
          <body>
            <table>
              <tr>
                <td valign="middle">
                  <div style="color:#e6edf3;
                              font-size:28px;font-weight:700;">
                    <span style="color:#8b5cf6;">◈</span>
                    {LEGACY_REPORT_TITLE}
                  </div>
                  <div style="color:#8b949e;
                              font-size:14px;margin-top:2px;">
                    Security Advisory + Threat Intelligence
                  </div>
                </td>
                <td align="right">
                  Reporting window: previous 24 hours<br>
                  Primary sources: 42<br>
                  Version {BRIEF_VERSION}
                  <img src="cid:{DEFCON_LEGEND_CONTENT_ID}"
                       alt="Enterprise DEFCON legend">
                </td>
              </tr>
            </table>
          </body>
        </html>
        """

        message = build_message(
            "sender@example.com",
            "recipient@example.com",
            "Security Intelligence Brief",
            text_body,
            html_body,
        )

        plain_part = message.get_body(preferencelist=("plain",))
        html_part = message.get_body(preferencelist=("html",))

        self.assertIsNotNone(plain_part)
        self.assertIsNotNone(html_part)

        plain_content = plain_part.get_content()
        html_content = html_part.get_content()

        self.assertIn(BRIEF_NAME, plain_content)
        self.assertNotIn(LEGACY_REPORT_TITLE, plain_content)

        self.assertIn(f"cid:{LOGO_CONTENT_ID}", html_content)
        self.assertNotIn(LEGACY_REPORT_TITLE, html_content)
        self.assertIn(f"Version {BRIEF_VERSION}", html_content)
        self.assertNotIn(
            "Security Advisory + Threat Intelligence",
            html_content,
        )

        image_parts = [
            part
            for part in message.walk()
            if part.get_content_maintype() == "image"
        ]
        self.assertEqual(len(image_parts), 2)
        self.assertEqual(
            image_parts[0]["Content-ID"],
            f"<{LOGO_CONTENT_ID}>",
        )
        self.assertEqual(
            image_parts[1]["Content-ID"],
            f"<{DEFCON_LEGEND_CONTENT_ID}>",
        )

    def test_defcon_asset_is_omitted_when_report_does_not_reference_it(self) -> None:
        message = build_message(
            "sender@example.com",
            "recipient@example.com",
            "Weekly Vulnerability Report",
            "Weekly Vulnerability Report",
            "<html><body><p>Weekly Vulnerability Report</p></body></html>",
        )

        image_parts = [
            part
            for part in message.walk()
            if part.get_content_maintype() == "image"
        ]
        self.assertEqual(len(image_parts), 1)
        self.assertEqual(
            image_parts[0]["Content-ID"],
            f"<{LOGO_CONTENT_ID}>",
        )


if __name__ == "__main__":
    unittest.main()
