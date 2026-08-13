# Daily Security Brief 5.6.6

## Delivery reliability and email presentation

- Daily workflow scheduled at 06:17 Europe/Oslo; weekly workflow scheduled at
  07:23 Europe/Oslo on Monday.
- Both workflows perform a non-secret Gmail configuration preflight.
- Gmail API delivery logs safe refresh and acceptance milestones.
- Daily DEFCON legend uses Outlook-safe HTML tables, highlights the current
  level and no longer embeds a second inline PNG.
- Release records are consolidated under `docs/releases/`.

## Validation

Run the offline test suite, then manually dispatch both delivery workflows and
verify successful completion and expected recipient delivery.

## Commit

`5.6.6 - harden report delivery and operational email layout`
