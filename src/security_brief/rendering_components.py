# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Self-contained Outlook-safe components used by report renderers."""

from __future__ import annotations

import html

from .config import DEFCON_LEVELS


_DEFCON_DESCRIPTIONS = {
    1: "Immediate action for exceptional verified threat.",
    2: "Urgent action for relevant active exploitation.",
    3: "Increased risk requiring enhanced attention.",
    4: "Meaningful developments; no direct exposure.",
    5: "Routine activity and normal monitoring.",
}

_LEGEND_BACKGROUND = "#022329"
_LEGEND_TEXT = "#EEF3F8"


def _render_defcon_text_legend(current_level: int) -> str:
    """Render the compact text-only DEFCON 1-5 explanatory legend."""

    if current_level not in DEFCON_LEVELS:
        raise ValueError(f"Unsupported DEFCON level: {current_level}")

    rows: list[str] = []
    for level in range(1, 6):
        definition = DEFCON_LEVELS[level]
        active = level == current_level
        emphasis = "font-weight:700;" if active else "font-weight:400;"
        current_marker = " (current level)" if active else ""
        rows.append(
            f"""
            <tr>
              <td width="66" valign="middle"
                  style="padding:2px 7px 2px 0;
                         color:{definition['colour']};
                         font-size:10px;line-height:14px;
                         font-weight:700;white-space:nowrap;">
                DEFCON {level}
              </td>
              <td valign="middle"
                  style="padding:2px 0;color:{_LEGEND_TEXT};
                         font-size:9px;line-height:14px;{emphasis}">
                {html.escape(_DEFCON_DESCRIPTIONS[level])}{current_marker}
              </td>
            </tr>
            """
        )

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="border-collapse:collapse;">'
        + "".join(rows)
        + "</table>"
    )


def render_overall_threat_status(
    *,
    level: int,
    label: str,
    colour: str,
    text_colour: str,
    border_colour: str,
) -> str:
    """Render Overall Threat at left and the DEFCON text legend at right.

    This deliberately restores the approved pre-6.0 executive-header hierarchy:
    one active colour-coded Overall Threat box, a separate explanatory text-only
    DEFCON 1-5 legend on the same row, and no second set of active status boxes.
    The five metric cards remain owned by ``rendering.py`` and render below this
    component.
    """

    if level not in DEFCON_LEVELS:
        raise ValueError(f"Unsupported DEFCON level: {level}")

    safe_label = html.escape(label)
    legend = _render_defcon_text_legend(level)

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="table-layout:fixed;margin:0 0 6px 0;">
      <tr>
        <td width="20%" valign="bottom" style="padding:4px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr>
              <td width="100%" valign="bottom">
                <a href="#executive-summary"
                   aria-label="Jump to Overall Threat detail"
                   style="display:block;width:100%;box-sizing:border-box;
                          background:{colour};border:1px solid {border_colour};
                          border-radius:7px;text-decoration:none;color:inherit;">
                  <span style="display:block;padding:9px 10px 3px;
                               color:{text_colour};
                               font-size:11px;font-weight:700;">
                    Overall Threat
                  </span>
                  <span style="display:block;padding:2px 8px 10px;
                               color:{text_colour};
                               font-size:16px;font-weight:700;text-align:center;
                               white-space:nowrap;">
                    {level} — {safe_label}
                  </span>
                </a>
              </td>
            </tr>
          </table>
        </td>

        <td width="80%" align="right" valign="bottom" style="padding:4px;">
          <table role="presentation" width="400" cellspacing="0" cellpadding="0"
                 bgcolor="{_LEGEND_BACKGROUND}"
                 style="width:100%;max-width:400px;margin-left:auto;
                        background:{_LEGEND_BACKGROUND};
                        border:1px solid {border_colour};
                        border-radius:6px;">
            <tr>
              <td style="padding:5px 8px;">
                {legend}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
    """


__all__ = [
    "render_overall_threat_status",
]
