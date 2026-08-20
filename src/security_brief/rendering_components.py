# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Self-contained Outlook-safe components used by report renderers.

Version 6.0.0 separates the colour-coded Overall Threat component from the
plain-text Enterprise DEFCON guide so the Daily report avoids duplicate boxes.
"""

from __future__ import annotations

import html
from typing import Mapping


def render_overall_threat_status(
    *,
    level: int,
    label: str,
    colour: str,
    text_colour: str,
    border_colour: str,
) -> str:
    """Render the single Daily Overall Threat status component."""

    safe_label = html.escape(label)
    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="table-layout:fixed;margin:0 0 6px 0;">
      <tr>
        <td width="100%" valign="bottom" style="padding:4px;">
          <a href="#executive-summary" aria-label="Jump to Overall Threat detail"
             style="display:block;width:100%;box-sizing:border-box;
                    background:{colour};border:1px solid {border_colour};
                    border-radius:7px;text-decoration:none;color:inherit;">
            <span style="display:block;padding:9px 10px 3px;color:{text_colour};
                         font-size:11px;font-weight:700;">
              Overall Threat
            </span>
            <span style="display:block;padding:2px 8px 10px;color:{text_colour};
                         font-size:16px;font-weight:700;text-align:center;
                         white-space:nowrap;">
              {level} — {safe_label}
            </span>
          </a>
        </td>
      </tr>
    </table>
    """


def render_defcon_text_guide(
    *,
    current_level: int,
    definitions: Mapping[int, Mapping[str, str]],
    text_colour: str,
    muted_colour: str,
) -> str:
    """Render a plain-text DEFCON guide without level boxes or backgrounds."""

    current = definitions[current_level]
    scale = " · ".join(
        f"DEFCON {level} {html.escape(definitions[level]['label'])}"
        for level in sorted(definitions)
    )
    return f"""
    <div style="margin:0 4px 10px;padding:3px 0;color:{text_colour};
                font-size:11px;line-height:1.45;">
      <strong>Enterprise DEFCON:</strong>
      Current DEFCON {current_level} — {html.escape(current['label'])}<br>
      <span style="color:{muted_colour};">{scale}</span>
    </div>
    """
