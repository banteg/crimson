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

- Artifact paths and SHA256 values for the `.crd` replays and any `.cdt` traces.
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

CDT traces come from the port alone, so a trace diff localizes a regression
between two port revisions or two playthroughs of the same replay. Use the
[CDT contract](../../rewrite/cdt-trace-format.md#versioning) as the version
authority. Regenerate obsolete recordings; do not add migrations or salvage
incomplete runs.

Run `dbg health` on both CDTs before interpreting a diff. Both selected windows
must be ready for comparison. Run the full-channel `dbg diff` first, then
`dbg bisect` or `dbg focus` for localization. A caller-label-only difference is
an attribution diagnostic when RNG values and state transitions agree.

## Evidence kinds

Passing a replay fixture, agreeing with the original code under the
[native execution oracle](../differential-testing/native-oracle.md), passing the
[recovered core gate](https://github.com/banteg/crimson/tree/master/crimson-core#whole-run-gate),
matching recovered code, and visually playtesting a run establish different
things; state which evidence supports each claim.
