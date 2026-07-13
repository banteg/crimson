---
tags:
  - rewrite
  - formats
---

# CDT trace format

CDT is Crimson's owned debug-trace container. It is used by
`crimson dbg record|health|diff|bisect|focus|tick|entity|query`; it is not an
original Crimsonland asset format.

This document specifies the only supported contract implemented by
`src/crimson/dbg/schema.py` and `src/crimson/dbg/trace.py`. For producer and
workflow details, see
[`trace-format-alignment.md`](trace-format-alignment.md).

## Versioning

- `trace_format_version = 2`: container and envelope
- `trace_schema_version = 15`: typed tick payloads

The reader requires both exact versions. There is no compatibility path for an
older CDT because traces are cheap to record again.

## File layout

1. `TRACE_MAGIC`: `b"crimson_debug_trace_v2\n"`
2. `<u32le trace_format_version>`
3. one `META` chunk
4. one or more `TICK` chunks
5. one `FOTR` chunk
6. trailer `<8-byte magic, u64le footer_offset>`

The trailer magic is `b"CDTFTR2\n"`.
Chunks are adjacent in the declared order: unindexed bytes, padding, extra
chunks, and bytes between the footer and trailer are rejected.

## Chunk envelope

Each chunk has header struct `<4siiIIIQ>` followed by its payload:

1. `kind`: `META`, `TICK`, or `FOTR`
2. `start_tick`: signed 32-bit tick bound
3. `end_tick`: signed 32-bit tick bound
4. `flags`: exactly `CHUNK_FLAG_MSGPACK`
5. `compressed_len`: stored payload length
6. `uncompressed_len`: stored payload length
7. `checksum64`: little-endian blake2b-64 of the payload

The legacy length field names remain in the fixed envelope, but CDT v2 payloads
are raw msgpack. The two lengths are equal and the zstd flag is not accepted.

Payload types are:

- `META` -> `TraceMeta`
- `TICK` -> `TickBlock`
- `FOTR` -> `TraceFooter`

`TraceFooter` indexes every tick block and records the total count plus first
and last tick. Its offset in the trailer allows direct lookup without scanning
the whole trace.

## Metadata

`TraceMeta` contains:

- the exact container and schema versions
- creation time
- typed producer identity
- typed source identity and replay fingerprint
- declared tick range
- optional captured game status

Unknown fields are rejected. Producer-private Frida settings and diagnostic
bags move to the versioned typed evidence sidecar rather than widening the
shared metadata schema; the raw JSONL may be deleted after finalization.
The declared tick range must exactly match the rows and footer written to disk.

## Tick blocks

A `TickBlock` contains ordered `TickRecord` rows. Every row contains:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `channels`

Tick indices must be non-negative, strictly increasing, and unique. A CDT may
represent a selected window and therefore need not start at zero. The health
report exposes gaps so a user can decide whether the selected evidence is
suitable for a comparison.

## Channel contract (schema 15)

Every tick requires all six channels:

| Channel | Payload |
| --- | --- |
| `replay_step` | `ReplayStepSnapshot` |
| `checkpoint` | `ReplayCheckpoint` |
| `sim_state` | `SimStateSnapshot` |
| `entity_samples` | `EntitySamplesSnapshot` |
| `rng_stream` | `list[RngStreamRow]` |
| `timing_samples` | `list[TimingSampleRow]` |

### `replay_step`

The replay step is the authoritative driving evidence for the tick:

- `dt`: finite, non-negative f32 frame delta
- `inputs`: a non-empty row per player containing `move_x`, `move_y`, `aim_x`,
  `aim_y`, and uint32 `flags`
- `prelude`: ordered native frame-RNG advances and perk operations applied before simulation
- `postlude`: perk-menu generation applied after simulation while tick RNG
  tracing remains active
- `commands`: Typ-o commands applied as part of the tick

Checkpoint and simulation player counts must equal the input count.

### `checkpoint`

The checkpoint tick and elapsed time must equal their enclosing `TickRecord`.
Effective hit and pickup counts are cross-producer fields. The non-equivalent
audio count, detailed death rows, and SFX/hit heads are zero or empty in CDT.
Native raw details live in the capture evidence sidecar, while replay-only
checkpoint sidecars may retain their fully typed rows. This makes the shared
channel strictly comparable without producer masks.
It carries the compact deterministic state used for fast divergence detection.

### `sim_state`

The gameplay mode must equal the enclosing mode. Each player row includes
position and gameplay state plus the movement fields needed to explain input
integration:

- `heading`
- `move_speed`
- `move_phase`
- `aim`
- `aim_heading`

### `entity_samples`

Creature, projectile, secondary-projectile, and bonus samples use stable UIDs.
UIDs must be unique within each entity kind for a tick, allowing `dbg entity`
to follow slot reuse without confusing two lifetimes.

### `rng_stream`

Each row contains:

- one-based `tick_call_index`
- `value_15`
- `state_before_u32`
- `state_after_u32`
- optional static `caller`

Every row must be a valid CRT LCG transition, `value_15` must derive from the
after-state, and consecutive rows must form one contiguous chain. A gap is an
incomplete capture, not replay input.

The caller is diagnostic attribution. Equal values and states with different
callers produce a caller-attribution diagnostic, not an RNG behavior mismatch.

### `timing_samples`

Every tick has a non-empty timing set with exactly one `gpur_enter` row. Its
`frame_dt_f32` equals `replay_step.dt`, its `frame_dt_ms_i32` equals the
enclosing `dt_ms_i32`, and its `mode_fn` identifies
`gameplay_update_and_render` for finalized Frida captures.

## Producers

The intended comparison set is:

1. Frida capture format 22 finalized into CDT v2/schema 15.
2. Python CRD v16 replay recording.
3. Zig CRD v16 replay recording.

All emit the same durable channel semantics. A producer may keep additional
diagnostics before finalization, but it may not add aliases or optional channel
shapes to CDT.

## Diff contract

`dbg diff` compares ticks in deterministic channel order:

1. `replay_step`
2. `checkpoint`
3. `rng_stream`
4. `sim_state`
5. `entity_samples`
6. `timing_samples`

The JSON report exposes:

- `mismatch`: the earliest divergent tick and all behavioral channel
  mismatches at that tick
- `channel_first_mismatches`: the first behavioral mismatch for every channel
  across the selected range
- `channel_first_diagnostics`: the first non-behavioral diagnostic for every
  channel, including RNG caller-only differences

Strict field mismatches name the path and include expected/actual values.
Finite float mismatches additionally include numeric delta, expected and actual
f32 hex encodings, and f32 ULP distance.
