# Release 6.1.2

**Release date:** 2026-08-20  
**Base runtime:** 6.1.0  
**Preceding maintenance documentation:** 6.1.1  
**Type:** Focused presentation fix  
**Status:** Validation candidate

## Purpose

Version 6.1.2 restores the approved Daily Security Brief executive DEFCON layout
that was lost when the 6.0.0 header was simplified.

## Fixed

- Restored the compact Overall Threat box on the left side of the executive
  threat row.
- Restored the text-only DEFCON 1–5 explanatory legend on the right side of the
  same row.
- Restored the five level descriptions:
  - DEFCON 1 — Immediate action for exceptional verified threat.
  - DEFCON 2 — Urgent action for relevant active exploitation.
  - DEFCON 3 — Increased risk requiring enhanced attention.
  - DEFCON 4 — Meaningful developments; no direct exposure.
  - DEFCON 5 — Routine activity and normal monitoring.
- Marks the current level once in the explanatory legend.
- Preserves the five operational metric cards on the full-width row below.

## Design constraint

The legend is explanatory text only. Version 6.1.2 does **not** restore the
obsolete five-box active DEFCON scale. There remains exactly one active
colour-coded threat status: Overall Threat.

## Implementation

The change is isolated to `src/security_brief/rendering_components.py`.
`rendering.py` continues to own the five metric cards and therefore needs no
structural change for this release.

Regression coverage in `tests/test_v6_maintenance.py` is updated from the
6.0.0 "legend absent" expectation to the approved 6.1.2 layout.

## Documentation

Updated:

- `VERSION`
- `README.md`
- `CHANGELOG.md`
- `MAINTENANCE.md`
- `docs/operations/CONTINUITY.md`
- `docs/architecture/OPTIMISATION.md`
- `docs/releases/RELEASE_6.1.2.md`
- `docs/releases/manifests/RELEASE_6.1.2.json`

The completed DEFCON restoration is removed from the open maintenance backlog.

## Validation

Completed in the build package:

- `rendering_components.py` syntax compilation: **PASS**
- updated `test_v6_maintenance.py` syntax compilation: **PASS**
- isolated DEFCON component functional/layout test: **PASS**
- current smoke-test nested Overall Threat table assumption preserved: **PASS**

Still required after upload:

- full Repository CI regression suite;
- manual Test Daily Security Brief workflow;
- visual inspection of the delivered email against the approved reference.

## Production gate

Do not mark 6.1.2 complete until Repository CI passes and the manual Daily
delivery visually confirms:

1. Overall Threat left;
2. DEFCON 1–5 text legend right;
3. current-level marker present once;
4. five metric cards below;
5. no duplicate active five-box DEFCON scale.
