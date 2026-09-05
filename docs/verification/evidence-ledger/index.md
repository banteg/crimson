---
tags:
  - verification
  - evidence
---

# Evidence records

Maintained documentation describes current behavior and reproducible workflows.
Investigation logs belong with their artifacts under `analysis/`, identified by
capture SHA256 and implementation commit. Completed plans are retired after their
lasting contracts and evidence have been incorporated into the reference pages.
Git history retains obsolete plans and unsupported capture reports.

## Record a comparison

For each investigation, keep:

- Native artifact paths and SHA256 values for the `.cdt`, `.crd`,
  `.rng_evidence.json`, and `.evidence.msgpack.zst` bundle.
- Binary [provenance](../../contributor/project-tracking/provenance.md), capture
  settings and producer version, plus the candidate implementation commit.
- Exact health, recording and comparison commands, with output paths.
- First mismatch for each channel, affected entity/field, and float bit/ULP
  details where relevant. Record caller-attribution diagnostics separately.
- Confirmed cause, landed fix, validation span, and any unresolved next probe.

Continue the same record when the capture SHA is unchanged; distinguish each
candidate commit and comparison result. A new capture gets a new artifact record.
Do not assume two playthroughs have the same absolute tick timeline.

## Capture acceptance

Use the [current format contract](../../rewrite/trace-format-alignment.md) and
`uv run crimson dbg verify` as the version authority. Regenerate obsolete
recordings; do not add migrations or salvage incomplete runs for parity work.
Captures must be full-detail with unlimited limits. Capture errors, missing
lifecycle rows and unfinished runs invalidate the evidence.

Keep the native bundle together, record the matching CRD through Python or Zig,
and run `dbg health` on both CDTs before interpreting a diff. Both selected
windows must be parity-ready. Run the full-channel `dbg diff` first, then
`dbg bisect` or `dbg focus` for localization. A caller-label-only difference is
an attribution diagnostic when RNG values and state transitions agree.

The [differential playbook](../../frida/differential-playbook.md) gives the command
sequence. Passing a fixture, matching recovered code, completing a native trace,
and visually playtesting a run establish different things; state which evidence
supports each claim.
