---
tags:
  - rewrite
  - formats
---

# CDT trace format (rewrite)

`CDT` is the debug trace container used by `crimson dbg record|diff|bisect|focus|viz`.
It is rewrite tooling format, not an original Crimsonland asset/container format.

This spec describes the current on-disk contract implemented by `src/crimson/dbg/schema.py`
and `src/crimson/dbg/trace.py`.

## Versioning

- `trace_format_version`: container/envelope version (`1` currently)
- `trace_schema_version`: channel payload schema version (`3` currently)
- container and schema versions are independent

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
- `phase_markers`
- `channels` (`dict[str, object]`)

Tick rows are required to be non-decreasing by `tick_index`.

## Channel contract (schema v3)

Required channels in both compared traces:

- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_marks`
- `rng_stream`

Canonical typed payloads are defined in `src/crimson/dbg/canonical_channels.py`:

- `sim_state` -> `SimStateSnapshot`
- `entity_samples` -> `EntitySamplesSnapshot`
- `rng_stream` -> `list[RngStreamRow]`

## Diff contract

`dbg diff` compares traces by tick and returns the first divergent tick.
For that tick, it reports all channel mismatches in deterministic order:

1. `checkpoint`
2. `rng_stream`
3. `sim_state`
4. `entity_samples`

Mismatch payload format:

- top-level `mismatch.kind = "tick_mismatch"`
- top-level `mismatch.detail.mismatch_count`
- top-level `mismatch.detail.mismatches[]`
- each row has `kind`, `channel`, and `detail`

This enables correlating divergence across channels at the same tick instead of failing after
the first channel-level mismatch.
