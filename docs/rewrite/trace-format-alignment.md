---
tags:
  - rewrite
  - differential-testing
  - formats
---

# Trace format alignment plan

This page tracks the owned `.cdt` trace format alignment across the three
producers we compare during parity work:

1. Original executable capture through Frida JSONL, finalized by
   `src/crimson/dbg/frida_finalize.py`.
2. Python replay recording through `src/crimson/dbg/record.py`.
3. Zig replay recording through `crimson-zig/src/cdt_trace.zig`.

The goal is not to make Frida raw JSONL, Python internals, and Zig internals look
identical. The goal is that once a run becomes a `.cdt`, consumers compare
original, Python, and Zig traces without producer-specific interpretation.

## Current contract

The on-disk container is `trace_format_version = 1`. The active payload schema is
`trace_schema_version = 12`.

This is the shared `.cdt` schema. Zig's runtime replay trace structs are internal
collection types and no longer define a separate on-disk msgpack trace format.

Each tick has:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `channels`

Required channels are:

- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples`

The core channel payload structs live in `src/crimson/dbg/canonical_channels.py`.
Zig mirrors the same schema in `crimson-zig/src/cdt_trace.zig`.

`TraceMeta` is typed in Python and mirrored by Zig:

- `TraceProducer`
- `TraceSource`
- `TraceTickRange`

Unknown metadata fields are rejected. Producer-private config stays in
producer-private logs because it is diagnostic context, not part of the shared
comparison contract.

## Why this format exists

The trace format needs to answer parity questions in a stable order:

1. Did the two runs process the same tick?
2. Did they reach the same replay checkpoint?
3. Did they consume the same RNG draws in the same order?
4. Did the same simulation state and entity samples exist after the tick?
5. Did timing inputs and timing-sensitive phases match?

The format should preserve enough evidence to let `dbg diff` find the first bad
tick and let `dbg focus` explain that tick without going back to producer-private
logs.

## Producer alignment

### Frida original capture

Frida JSONL is an owned producer-private wire format. It may keep capture-side
field names and diagnostic bags, but `frida_finalize.py` is the boundary that
must produce canonical `.cdt` rows.

- current raw capture format is `capture_format_version = 12`
- lifecycle rows are strict and typed
- tick channels are decoded with `msgspec` and unknown fields are rejected
- `caller_static` is normalized into durable RNG `caller`
- raw `branch_id` is no longer accepted
- timing samples are validated as replay-grade evidence
- Frida session config stays in the raw JSONL stream, not in shared CDT metadata

### Python replay recorder

Python replay recording produces canonical checkpoint, state, entity, and RNG
rows from the replay driver.

- RNG rows carry direct draw state and optional static caller addresses
- strict RNG trace mode catches untagged supported gameplay draws
- metadata points at the replay file fingerprint and selected implementation
- Python now emits the shared minimum `timing_samples` row set
- metadata uses the same typed `TraceMeta` contract as finalized Frida and Zig
  traces

### Zig replay recorder

Zig replay recording is no longer a verifier-only side path. Its `.cdt` writer
targets schema 12 and serializes the same required channels.

- Zig writes schema 12 `.cdt` traces
- Zig exposes native trace export as `crimson-zig dbg record <replay.crd> --out <trace.cdt>`
- Zig exposes the matching schema/replay contract check as `crimson-zig dbg verify`
- RNG rows come from direct traced draws, not post-hoc lifecycle reconstruction
- RNG rows include optional static caller addresses
- timing rows are emitted and have coverage tests
- metadata is structured in Zig before msgpack encoding
- Zig metadata field names and requiredness match Python `TraceMeta`

## Timing policy

`timing_samples` is required by the schema and compared by `dbg diff`, but
Python replay traces used to write an empty list for every tick. Timing is now
core, not optional.

The shared minimum per tick is a `gpur_enter` sample with:

- `tick_index`
- `gameplay_frame`
- `phase = "gpur_enter"`
- `write_kind = "snapshot"`
- `frame_dt_f32`
- `frame_dt_ms_i32`
- `frame_dt_ms_f32`
- `time_scale_active_entry`
- `time_scale_active_current`
- `time_scale_factor`
- `bonus_reflex_boost_timer`
- `mode_fn = "gameplay_update_and_render"`

Frida validates this row against raw tick `dt`, Python records it from the replay
driver `before_tick` hook, and Zig emits it from the replay step timing trace.
`dbg diff` and `dbg focus` compare timing rows. Python `dbg health` and native
`crimson-zig dbg health <trace.cdt> --format json` report required row channels
that are present but empty across the selected trace window. Native
`crimson-zig dbg tick <trace.cdt> <tick> --json` can inspect one tick's
checkpoint, entity-count, event-count, RNG-row, and timing-row summary directly
from the same CDT chunks. Native
`crimson-zig dbg entity <trace.cdt> <entity_uid> --json` can also follow one
sampled entity UID across a selected tick range.

## Phase model

Schema 11 removes durable `phase_markers`. They were low-authority labels and
the actual debugging workflow now uses timing rows plus RNG caller rows for
intra-tick localization.

Add typed phase anchors only if a current parity investigation needs localization
that those channels cannot explain.

If phase anchors are added later:

- add them as a typed channel, not producer-private marker payloads
- require Frida, Python, and Zig producer support in the same schema bump
- update `diff` and `focus` to explain how anchors affect mismatch reporting

## Schema 11 cleanup

The schema 11 bump folds the stale cleanup items into the shared contract:

- `TickRecord.phase_markers` was removed
- Frida raw `branch_id` is rejected instead of carried as a capture alias
- Zig's old `--debug-trace-msgpack` path was removed; use `--debug-trace-cdt`
- `TraceFooter.channel_counts` was split into `channel_tick_counts` and
  `channel_row_counts`
- `dbg health` reports `ok_for_parity_analysis` and prints
  `parity_analysis_ready`

## Schema 12 cleanup

Schema 12 collapses owned-producer metadata that had no independent consumer:

- `TraceMeta.channels` and `TraceMeta.channel_versions` were removed because
  the schema always requires the same channel set
- `TraceMeta.config` was removed because producer-private config belongs in raw
  producer logs
- footer channel count summaries were removed because Python and native
  `dbg health` recompute row coverage from ticks
- raw Frida JSONL dropped its separate `schema_version` and now uses only
  `capture_format_version = 12`
- public trace chunk-size options were removed; CDT chunking is fixed at the
  writer boundary
