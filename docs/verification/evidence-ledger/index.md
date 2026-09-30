---
tags:
  - verification
  - evidence
---

# Evidence records

Maintained documentation describes current behavior and reproducible workflows.
Investigation logs belong with their artifacts under `analysis/`, identified by
artifact SHA256 and implementation commit. Completed plans are retired after their
lasting contracts and evidence have been incorporated into the reference pages.
Git history retains obsolete plans and unsupported reports.

## Record a comparison

For each investigation, keep:

- Artifact paths and SHA256 values for the `.cdt` and `.crd` files.
- Binary [provenance](../../contributor/project-tracking/provenance.md), producer
  version, plus the candidate implementation commit.
- Exact health, recording and comparison commands, with output paths.
- First mismatch for each channel, affected entity/field, and float bit/ULP
  details where relevant. Record caller-attribution diagnostics separately.
- Confirmed cause, landed fix, validation span, and any unresolved next probe.

Continue the same record when the artifact SHA is unchanged; distinguish each
candidate commit and comparison result. A new artifact gets a new record.
Do not assume two playthroughs have the same absolute tick timeline.

## Trace comparisons

Use the [current format contract](../../rewrite/trace-format-alignment.md) and
`uv run crimson dbg verify` as the version authority. Regenerate obsolete
recordings; do not add migrations or salvage incomplete runs for parity work.

Run `dbg health` on both CDTs before interpreting a diff. Both selected windows
must be parity-ready. Run the full-channel `dbg diff` first, then `dbg bisect`
or `dbg focus` for localization. A caller-label-only difference is an
attribution diagnostic when RNG values and state transitions agree.

Passing a fixture, matching recovered code, completing a native trace,
and visually playtesting a run establish different things; state which evidence
supports each claim.
