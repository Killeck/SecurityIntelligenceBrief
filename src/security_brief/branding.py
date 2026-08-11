# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Email branding helpers for the Daily Security Brief."""

from __future__ import annotations

import html
import re
from pathlib import Path

from .config import BRIEF_NAME, BRIEF_VERSION, PROJECT_ROOT


LOGO_CONTENT_ID = "daily-security-brief-logo"
LOGO_PATH = PROJECT_ROOT / "assets" / "DailySecurityBrief.png"
DEFCON_LEGEND_CONTENT_ID = "enterprise-defcon-legend"
DEFCON_LEGEND_PATH = PROJECT_ROOT / "assets" / "DefconLegend.png"
LEGACY_REPORT_TITLE = f"{BRIEF_NAME} v{BRIEF_VERSION}"

_HEADER_BLOCK_RE = re.compile(
    (
        r'<div style="color:[^"]+;\s*'
        r'font-size:28px;font-weight:700;">\s*'
        r'<span style="color:[^"]+;">◈</span>\s*'
        + re.escape(html.escape(LEGACY_REPORT_TITLE))
        + r'\s*</div>\s*'
        r'<div style="color:[^"]+;\s*'
        r'font-size:14px;margin-top:2px;">\s*'
        r'Security Advisory \+ Threat Intelligence\s*'
        r'</div>'
    ),
    flags=re.MULTILINE,
)


def load_logo_bytes(path: Path = LOGO_PATH) -> bytes:
    """Read and validate the inline PNG logo used by the email."""

    try:
        logo = path.read_bytes()
    except OSError as error:
        raise RuntimeError(f"Unable to read brief logo: {path}") from error

    if not logo.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError(f"Brief logo is not a valid PNG: {path}")

    if len(logo) > 1_000_000:
        raise RuntimeError(
            f"Brief logo exceeds the 1 MB limit: {len(logo)} bytes"
        )

    return logo


def load_defcon_legend_bytes(path: Path = DEFCON_LEGEND_PATH) -> bytes:
    """Read and validate the compact inline DEFCON pyramid PNG."""

    try:
        legend = path.read_bytes()
    except OSError as error:
        raise RuntimeError(f"Unable to read DEFCON legend: {path}") from error

    if not legend.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError(f"DEFCON legend is not a valid PNG: {path}")

    if len(legend) > 500_000:
        raise RuntimeError(
            f"DEFCON legend exceeds the 500 KB limit: {len(legend)} bytes"
        )

    return legend


def apply_email_branding(
    text_body: str,
    html_body: str,
) -> tuple[str, str]:
    """Replace the versioned heading with the inline report logo.

    The version remains untouched in the top-right metadata block.
    """

    branded_text = text_body.replace(
        LEGACY_REPORT_TITLE,
        BRIEF_NAME,
        1,
    )

    logo_markup = f"""
    <div style="line-height:0;">
      <img src="cid:{LOGO_CONTENT_ID}"
           alt="{html.escape(BRIEF_NAME, quote=True)}"
           width="360"
           style="display:block;width:100%;max-width:360px;
                  height:auto;border:0;outline:none;text-decoration:none;">
    </div>
    """

    branded_html, replacements = _HEADER_BLOCK_RE.subn(
        logo_markup.strip(),
        html_body,
        count=1,
    )

    if replacements == 0:
        # Keep the visible title clean even if the surrounding renderer markup
        # changes in a future release.
        branded_html = html_body.replace(
            html.escape(LEGACY_REPORT_TITLE),
            html.escape(BRIEF_NAME),
            1,
        )

    return branded_text, branded_html
