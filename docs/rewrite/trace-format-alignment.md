---
tags:
  - rewrite
  - differential-testing
  - formats
---

# Trace format alignment

The debugging pipeline has one current contract shared by the two producers
used for parity work:

1. Python recording of replays through
   `crimson-re/src/crimson_re/dbg/record.py`.
2. Zig replay recording through `crimson-zig/src/cdt_trace.zig`.

Once a run becomes a `.cdt`, all consumers see the same typed tick data and no
producer-specific aliases.

## Current-only contract

| Artifact | Current version | Authority |
| --- | ---: | --- |
| CDT container | 2 | `crimson-re/src/crimson_re/dbg/schema.py` |
| CDT payload schema | 19 | `crimson-re/src/crimson_re/dbg/schema.py` |
| CRD replay | 29 | `src/crimson/replay/types.py` |

These artifacts are throwaway debugging data. Readers require exactly these
versions; they do not translate, normalize, or salvage an older recording.
Re-record a trace when a version changes.

## Canonical tick

Every `TickRecord` contains:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `channels`

Schema 19 and CRD 19 add packed input bit 17, `fire_bullets_key_down`, for the
native fixed G-key shortcut. Playback only honors the shortcut with
`preserve_bugs` enabled.

Quest keeps its scaled simulation timeline and uses stage `0.0` outside Quest.
Entity generations count allocations rather than sampled active transitions.

Schema 19 requires every channel on every tick:

- `replay_step`
- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples`

The core channel types live in
`crimson-re/src/crimson_re/dbg/canonical_channels.py`; Zig mirrors the same wire schema in
`crimson-zig/src/cdt_trace.zig`.

### Replay-driving evidence

`replay_step` is the first channel because it records what drove the tick, not
only what existed after the tick:

- `dt`: the exact f32 frame delta used by replay
- `inputs`: one input row per player with movement, aim, and flags
- `prelude`: ordered native frame-RNG advances and perk operations applied
  between ticks, outside the tick RNG trace
- `postlude`: perk-menu generation applied after simulation while tick RNG
  tracing remains active
- `commands`: replay commands (perk and Typ-o) applied as part of the tick

Replays step a fixed 60 Hz schedule, so their traces report
`dt = float32(1/60)`, tick rate 60 and empty `prelude` and `postlude`. There is
no separate `replay_inputs` field in the raw tick contract.

`TraceMeta.status` carries the run's unlock indices and weapon usage counts with
every other status field zero.

### Movement state

Each player in `sim_state` preserves the movement and aim state needed to
localize a control or integration mismatch:

- `heading`
- `move_speed`
- `move_phase`
- `aim`
- `aim_heading`

These fields complement the input intent in `replay_step`: input differences
identify the cause before simulation, while state differences show their
effect.

## Strict invariants

The owned formats fail at the first contract violation:

- unknown typed fields are rejected
- CDT tick indices are strictly increasing and unique
- tick, checkpoint, timing, mode, and player counts must agree
- `replay_step.inputs` and `timing_samples` must be non-empty
- every tick has exactly one `gpur_enter` timing sample
- `gpur_enter.frame_dt_f32` equals `replay_step.dt`
- `gpur_enter.frame_dt_ms_i32` equals `TickRecord.dt_ms_i32`
- RNG rows use one-based call indices and valid CRT state transitions

## Producer boundaries

### Python recorder

Python records the replay step, checkpoint, simulation state, entity, RNG, and
timing evidence while it executes a CRD replay. Metadata identifies the source
fingerprint and implementation, and is validated through the same typed
`TraceMeta` contract.

### Zig replay recorder

Zig writes the same CDT v2/schema 19 chunks and channel payloads for CRD
replays. Use
`crimson-zig dbg record <replay.crd> --out <trace.cdt>` to record and
`crimson-zig dbg verify` to check that its compiled schema and replay versions
match the owned contract.

## Differential workflow

Run `dbg verify` after changing any owned format; it prints the complete current
CDT, replay, and checkpoint version matrix, then checks the Python and Zig source
declarations, tick-boundary field order, required channels, and
replay/checkpoint payload ceilings for drift.

Run `dbg health` on both traces before interpreting a diff. Health validates the
tick records, reports tick spans and gaps, counts rows per channel, and exits
nonzero when the selected window is not ready for parity analysis.

`dbg diff` then compares the driving step before post-tick state:

1. `replay_step`
2. `checkpoint`
3. `rng_stream`
4. `sim_state`
5. `entity_samples`
6. `timing_samples`

The top-level mismatch remains the earliest divergent tick. The report also
contains `channel_first_mismatches`, so one run exposes the first bad tick for
each channel instead of hiding downstream evidence behind the earliest one.
`channel_first_diagnostics` carries non-behavioral evidence.

RNG caller labels are attribution metadata. If draw values and state
transitions match but caller labels differ, the result is an
`rng_caller_attribution_mismatch` diagnostic, not behavioral divergence.

Strict numeric mismatches include the numeric delta, both f32 bit patterns, and
the f32 ULP distance. This makes one-bit precision drift distinguishable from a
different simulation decision without returning to producer logs.

Use `dbg bisect` to bound the earliest bad tick and `dbg focus`, `dbg tick`,
`dbg entity`, or `dbg query` to inspect the relevant channel and entity history.
