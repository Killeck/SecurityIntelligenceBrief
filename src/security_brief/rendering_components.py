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

_LEGEND_PANEL = "#022329"
_LEGEND_TEXT = "#EEF3F8"
_LEGEND_HEADING = "#b778ff"


def _render_defcon_legend(current_level: int, border_colour: str) -> str:
    """Render the compact five-row Enterprise DEFCON legend.

    The legend intentionally contains only one row per DEFCON level. It does
    not render the older duplicated five-cell colour strip.
    """

    if current_level not in DEFCON_LEVELS:
        raise ValueError(f"Unsupported DEFCON level: {current_level}")

    rows: list[str] = []

    for level in range(1, 6):
        definition = DEFCON_LEVELS[level]
        colour = str(definition["colour"])
        label = html.escape(str(definition["label"]))
        description = html.escape(_DEFCON_DESCRIPTIONS[level])
        current = level == current_level

        font_weight = "700" if current else "400"
        marker = " · CURRENT" if current else ""

        rows.append(
            f"""
            <tr>
              <td width="10" bgcolor="{colour}"
                  style="width:10px;background:{colour};
                         font-size:1px;line-height:1px;">
                &nbsp;
              </td>
              <td width="150" valign="middle"
                  style="padding:3px 8px;color:{colour};
                         font-size:10px;line-height:14px;
                         font-weight:{font_weight};white-space:nowrap;">
                DEFCON {level} — {label}{marker}
              </td>
              <td valign="middle"
                  style="padding:3px 0;color:{_LEGEND_TEXT};
                         font-size:9px;line-height:14px;
                         font-weight:{font_weight};">
                {description}
              </td>
            </tr>
            """
        )

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           bgcolor="{_LEGEND_PANEL}"
           style="width:100%;background:{_LEGEND_PANEL};
                  border:1px solid {border_colour};
                  border-radius:6px;border-collapse:separate;
                  border-spacing:0;">
      <tr>
        <td style="padding:6px 8px 3px;
                   color:{_LEGEND_HEADING};
                   font-size:12px;font-weight:700;text-align:left;">
          Enterprise DEFCON Legend
        </td>
      </tr>
      <tr>
        <td style="padding:2px 8px 7px;">
          <table role="presentation" width="100%"
                 cellspacing="0" cellpadding="0"
                 style="border-collapse:separate;border-spacing:0 2px;">
            {''.join(rows)}
          </table>
        </td>
      </tr>
    </table>
    """


def render_overall_threat_status(
    *,
    level: int,
    label: str,
    colour: str,
    text_colour: str,
    border_colour: str,
) -> str:
    """Render Daily Overall Threat with the compact DEFCON legend to its right."""

    if level not in DEFCON_LEVELS:
        raise ValueError(f"Unsupported DEFCON level: {level}")

    safe_label = html.escape(label)
    legend = _render_defcon_legend(level, border_colour)

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="table-layout:fixed;margin:0 0 6px 0;">
      <tr>
        <td width="20%" valign="bottom" style="padding:4px;">
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

        <td width="80%" align="right" valign="bottom" style="padding:4px;">
          <table role="presentation" width="560"
                 cellspacing="0" cellpadding="0"
                 style="width:100%;max-width:560px;margin-left:auto;">
            <tr>
              <td>
                {legend}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
    """
