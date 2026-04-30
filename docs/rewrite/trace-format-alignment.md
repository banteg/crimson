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
`trace_schema_version = 10`.

This is the shared `.cdt` schema, not the local Zig replay diagnostic trace
schema in `crimson-zig/src/runtime/replay/diagnostic_trace.zig`.

Each tick has:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `phase_markers`
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
- `TraceChannelVersions`
- `TraceTickRange`
- `TraceConfig`

Unknown metadata fields are rejected. Producer-private config is allowed only in
the named Frida extension bag, because raw capture settings are diagnostics and
not part of the shared comparison contract.

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

- lifecycle rows are strict and typed
- tick channels are decoded with `msgspec` and unknown fields are rejected
- `caller_static` is normalized into durable RNG `caller`
- `branch_id` is dropped from the durable RNG row
- timing samples are validated as replay-grade evidence
- Frida session config is kept under `TraceConfig.frida`, not mixed into the
  shared metadata shape

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
targets schema 10 and serializes the same required channels.

- Zig writes schema 10 `.cdt` traces
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
`dbg diff` and `dbg focus` compare timing rows. `dbg health` reports required row
channels that are present but empty across the selected trace window.

## Phase model

Durable traces currently keep `phase_markers: list[str]`. Frida raw capture can
hold richer structured marker payloads, but finalization flattens them. Python
and Zig do not provide a shared structured phase model.

Decision for schema 10: keep phase markers as labels only. They are low-authority
hints, while RNG caller rows and timing samples are the durable comparison tools.
Add typed phase anchors only if a current parity investigation needs intra-tick
localization that those channels cannot explain.

If phase anchors are added later:

- add them as a typed channel, not producer-private marker payloads
- require Frida, Python, and Zig producer support in the same schema bump
- update `diff` and `focus` to explain how anchors affect mismatch reporting

## Next-version cleanup notes

These are intentionally not part of schema 10 alignment, but they look stale or
low-value enough to discuss before the next schema bump:

- `phase_markers` may be removable if timing rows and RNG caller rows keep
  covering the actual debugging workflow.
- `crimson-zig/src/runtime/replay/diagnostic_trace.zig` still has its own local
  schema version. Keep it only if the per-tick diagnostic trace remains useful
  outside `.cdt` generation.
- `TraceFooter.channel_counts` counts channel presence per tick, not row counts.
  Health now reports row coverage separately; the footer field may be redundant
  or should be renamed in a future format bump.
- `ok_for_movement_root_cause` in health output is older wording. The checks now
  cover broader parity readiness, not only movement root-cause analysis.
- Frida raw `branch_id` is only a capture-side alias for caller diagnostics. It
  should stay out of durable traces and may be removable from capture once
  existing raw logs no longer need finalization.
