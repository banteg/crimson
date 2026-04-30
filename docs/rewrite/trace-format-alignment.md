---
tags:
  - rewrite
  - differential-testing
  - formats
---

# Trace format alignment plan

This page tracks the remaining work to keep the owned `.cdt` trace format aligned
across the three producers we compare during parity work:

1. Original executable capture through Frida JSONL, finalized by
   `src/crimson/dbg/frida_finalize.py`.
2. Python replay recording through `src/crimson/dbg/record.py`.
3. Zig replay recording through `crimson-zig/src/cdt_trace.zig`.

The goal is not to make Frida raw JSONL, Python internals, and Zig internals look
identical. The goal is that once a run becomes a `.cdt`, consumers can compare
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

## Producer state

### Frida original capture

Frida JSONL is an owned producer-private wire format. It may keep capture-side
field names and diagnostic bags, but `frida_finalize.py` is the boundary that
must produce canonical `.cdt` rows.

Current strengths:

- lifecycle rows are strict and typed
- tick channels are decoded with `msgspec` and unknown fields are rejected
- `caller_static` is normalized into durable RNG `caller`
- `branch_id` is dropped from the durable RNG row
- timing samples are validated as replay-grade evidence

Remaining work:

- keep raw-only Frida diagnostics out of durable channel semantics
- decide whether structured phase-marker payloads should become a durable
  channel, or stay raw-only and unavailable to `diff`/`focus`

### Python replay recorder

Python replay recording produces canonical checkpoint, state, entity, and RNG
rows from the replay driver.

Current strengths:

- RNG rows carry direct draw state and optional static caller addresses
- strict RNG trace mode catches untagged supported gameplay draws
- metadata points at the replay file fingerprint and selected implementation

Remaining work:

- emit meaningful `timing_samples` or explicitly downgrade timing to an optional
  diagnostic channel for Python traces
- replace generic `TraceMeta` dictionaries with typed metadata shared with
  Frida and Zig
- stop treating channel presence as equivalent to useful channel coverage

### Zig replay recorder

Zig replay recording is no longer a verifier-only side path. Its `.cdt` writer
targets schema 10 and serializes the same required channels.

Current strengths:

- Zig writes schema 10 `.cdt` traces
- RNG rows come from direct traced draws, not post-hoc lifecycle reconstruction
- RNG rows include optional static caller addresses
- timing rows are emitted and have coverage tests
- metadata is structured in Zig before msgpack encoding

Remaining work:

- keep Zig structs mechanically in sync with the Python schema until the schema
  has a generated or shared contract
- align metadata field names and requiredness with Python `TraceMeta` once that
  type is made explicit

## Remaining alignment work

### 1. Type trace metadata

`TraceMeta` still uses generic dictionaries for `producer`, `source`,
`channel_versions`, `tick_range`, and `config`. That makes the payload easy to
extend accidentally and makes cross-producer compatibility depend on convention.

Target:

- introduce typed Python metadata structs for producer, source, tick range, and
  config
- keep producer-specific extras behind typed optional fields or a typed
  extension map with a clear name
- update Frida and Python producers to construct those structs directly
- mirror the same required fields in Zig

Acceptance:

- metadata decoding rejects unknown required-shape fields
- Frida, Python, and Zig traces decode through the same `TraceMeta` type
- tests cover all three producer metadata shapes

### 2. Resolve timing policy

`timing_samples` is required by the schema and compared by `dbg diff`, but
Python replay traces currently write an empty list for every tick. Frida treats
timing as replay-grade and Zig emits timing samples.

Target decision:

- if timing is core, Python must emit at least the shared minimum row set
- if timing is diagnostic, remove it from required channels and make `diff`
  compare it only when both traces carry meaningful rows

Recommended direction:

- keep timing core
- define the minimum per-tick row as a `gpur_enter` sample with `frame_dt_f32`,
  `frame_dt_ms_i32`, and `mode_fn` when known
- have Python record the same minimum from replay dt and gameplay mode context

Acceptance:

- Frida, Python, and Zig traces all contain non-empty timing rows for supported
  replay ticks
- `health` reports an issue when a required channel is present but empty across
  the whole window
- `focus` includes timing sample comparison in its tick report

### 3. Decide the durable phase model

Durable traces currently keep `phase_markers: list[str]`. Frida raw capture can
hold richer structured marker payloads, but finalization flattens them. Python
and Zig do not provide a shared structured phase model.

Target decision:

- either keep phase markers as labels only and document them as low-authority
  hints
- or add a typed phase channel with ranges or anchors that can localize RNG and
  state drift inside a tick

Recommended direction:

- do not add a broad phase taxonomy yet
- first add timing comparison to `focus`
- add structured phase anchors only when a current parity investigation needs
  intra-tick localization that RNG caller and timing rows cannot explain

Acceptance if implemented:

- phase anchors are a typed channel, not producer-private marker payloads
- Frida, Python, and Zig either all emit the channel or it remains optional
- `diff` and `focus` explain how phase anchors affect mismatch reporting

### 4. Make consumers match the contract

`dbg diff` already compares checkpoint, RNG, sim state, entity samples, and
timing samples. `dbg focus` omits timing, and `dbg health` does not flag all-empty
timing coverage.

Target:

- `focus` should compare every required channel
- `health` should distinguish "channel key exists on each tick" from "channel
  carries useful rows"
- human output should show timing row counts alongside RNG/entity metrics

Acceptance:

- focused tick output includes timing sample detail and contributes it to the
  `diverged` flag
- health reports all-empty required row channels as issues
- tests cover timing mismatches in both `diff` and `focus`

### 5. Keep docs synchronized with schema

The docs should describe the current schema, not old migration stages.

Target:

- `docs/rewrite/cdt-trace-format.md` remains the authoritative format spec
- this page remains the current alignment roadmap
- Frida capture docs describe raw JSONL as producer-private and `.cdt` as the
  shared durable format
- stale schema-version references are updated with every schema bump

Acceptance:

- schema version in docs matches `src/crimson/dbg/schema.py`
- docs name `caller`, not historical `caller_static_u32` or `branch_id`, for the
  durable RNG row
- docs clearly separate raw Frida JSONL fields from durable `.cdt` fields

## Suggested sequencing

1. Update docs to schema 10 and remove stale root planning notes.
2. Type `TraceMeta` in Python and add cross-producer metadata tests.
3. Make Python emit minimum timing samples.
4. Extend `focus` and `health` for timing coverage.
5. Reassess whether structured phase anchors are still needed.
6. If phase anchors are needed, add them as a new typed channel with Frida,
   Python, and Zig producer support in the same schema bump.
