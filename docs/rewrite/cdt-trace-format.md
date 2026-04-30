---
tags:
  - rewrite
  - formats
---

# CDT trace format (rewrite)

`CDT` is the debug trace container used by `crimson dbg record|diff|bisect|focus|tick|entity|query`.
It is rewrite tooling format, not an original Crimsonland asset/container format.

This spec describes the current on-disk contract implemented by `src/crimson/dbg/schema.py`
and `src/crimson/dbg/trace.py`.

For cross-producer alignment details, see
[`trace-format-alignment.md`](trace-format-alignment.md).

## Versioning

- `trace_format_version`: container/envelope version (`1` currently)
- `trace_schema_version`: channel payload schema version (`11` currently)
- container and schema versions are independent
- Zig's runtime replay trace structs are internal collection types; CDT is the
  shared on-disk debug trace format

## File layout

1. `TRACE_MAGIC` bytes: `b"crimson_debug_trace_v1\n"`
2. `<u32le trace_format_version>`
3. one `META` chunk
4. zero or more `TICK` chunks
5. one `FOTR` chunk
6. trailer `<8-byte magic, u64le footer_offset>`

Trailer magic is `b"CDTFTR1\n"`.

## Chunk envelope

Each chunk has a fixed header followed by a compressed payload:

- Header struct: `<4siiIIIQ>`
- Fields in order:
1. `kind` (`META`, `TICK`, `FOTR`)
2. `start_tick` (`i32`)
3. `end_tick` (`i32`)
4. `flags` (`u32`)
5. `compressed_len` (`u32`)
6. `uncompressed_len` (`u32`)
7. `checksum64` (`u64`, blake2b-64 of uncompressed bytes)

Payload encoding:

- `flags & CHUNK_FLAG_ZSTD` must be set (zstd compressed payload)
- `flags & CHUNK_FLAG_MSGPACK` must be set (msgpack encoded payload)

## Msgpack payload types

- `META` payload: `TraceMeta`
- `TICK` payload: `TickBlock`
- `FOTR` payload: `TraceFooter`

`TickBlock` contains ordered `TickRecord` rows:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `channels` (`ReplayTickChannels`)

Tick rows are required to be non-decreasing by `tick_index`.

`TraceMeta` uses typed metadata structs for `producer`, `source`,
`channel_versions`, `tick_range`, and `config`. Unknown metadata fields are
rejected. Frida raw capture settings live only under `config.frida` because they
are producer-private diagnostics.

`TraceFooter` stores the tick block index, total tick window, channel presence
counts in `channel_tick_counts`, and concrete emitted row counts in
`channel_row_counts`.

## Channel contract (schema v11)

Required channels in both compared traces:

- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples`

Canonical typed payloads are defined in `src/crimson/replay/checkpoints.py`
and `src/crimson/dbg/canonical_channels.py`:

- `checkpoint` -> `ReplayCheckpoint`
- `sim_state` -> `SimStateSnapshot`
- `entity_samples` -> `EntitySamplesSnapshot`
- `rng_stream` -> `list[RngStreamRow]`
- `timing_samples` -> `list[TimingSampleRow]`

`rng_stream` rows contain:

- `tick_call_index`
- `value_15`
- `state_before_u32`
- `state_after_u32`
- `caller`

`caller` is the optional static caller address used for parity diagnostics. It is
stored as an integer and rendered as hex only in human-facing diff output. Frida
raw JSONL still uses producer-private field names such as `caller_static`, but
finalization canonicalizes them into this durable `caller` field.

`timing_samples` rows contain phase-level timing evidence. Frida captures,
Python replay traces, and Zig replay traces all emit a non-empty row set with a
`gpur_enter` sample for supported replay ticks. The shared minimum row records
the tick index, gameplay frame, `frame_dt_f32`, `frame_dt_ms_i32`,
`frame_dt_ms_f32`, time-scale state, reflex boost timer, and
`mode_fn = "gameplay_update_and_render"`.

## Producers

The intended comparison set is:

1. Original game capture, produced by Frida JSONL and finalized by
   `src/crimson/dbg/frida_finalize.py`.
2. Python replay trace, produced by `src/crimson/dbg/record.py`.
3. Zig replay trace, produced by `crimson-zig/src/cdt_trace.zig`.

All three producers should emit the same required channels and the same durable
row semantics. Producer-private fields are allowed before finalization, but the
`.cdt` payload must stay canonical.

## Diff contract

`dbg diff` compares traces by tick and returns the first divergent tick.
For that tick, it reports all channel mismatches in deterministic order:

1. `checkpoint`
2. `rng_stream`
3. `sim_state`
4. `entity_samples`
5. `timing_samples`

Mismatch payload format:

- top-level `mismatch.kind = "tick_mismatch"`
- top-level `mismatch.detail.mismatch_count`
- top-level `mismatch.detail.mismatches[]`
- each row has `kind`, `channel`, and `detail`

This enables correlating divergence across channels at the same tick instead of failing after
the first channel-level mismatch.
