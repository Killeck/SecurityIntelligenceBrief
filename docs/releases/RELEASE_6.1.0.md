# Release 6.1.0

**Release date:** 2026-08-20
**Base release:** 6.0.0
**Status:** Production release candidate

## Purpose

Version 6.1.0 starts the source-architecture release line. It strengthens the
distinction between authoritative evidence and freely available corroborating
intelligence while reducing source-specific policy embedded in generic modules.

## Release changes

- Added GitHub Advisory Database collection as structured open-source
  vulnerability corroboration.
- Added a declarative vendor-coverage registry used by report truth evaluation.
- Kept CrowdStrike public coverage supporting-only; public signals cannot create
  an authoritative clean-negative claim.
- Added explicit `PARTIAL` source-health state handling for a source that is
  reachable but confirmed incomplete.
- Added focused regression coverage for the new collector, vendor policy and
  source-health semantics.

## Validation

- Local offline regression suite: **76/76 tests passed**.
- Python compilation passed locally.
- Repository CI and manual Daily/Weekly Gmail API delivery remain required
  production gates.

## Production gate

Do not certify 6.1.0 until Repository CI passes on this branch and pull
request, then both manual delivery workflows complete successfully and the
received reports are visually reviewed.
