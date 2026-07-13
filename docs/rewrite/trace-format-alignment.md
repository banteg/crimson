---
tags:
  - rewrite
  - differential-testing
  - formats
---

# Trace format alignment

The debugging pipeline has one current contract shared by the three producers
used for parity work:

1. Original executable capture through Frida JSONL, finalized by
   `src/crimson/dbg/frida_finalize.py`.
2. Python replay recording through `src/crimson/dbg/record.py`.
3. Zig replay recording through `crimson-zig/src/cdt_trace.zig`.

Frida JSONL remains a producer-private transport. Once a run becomes a `.cdt`,
all consumers see the same typed tick data and no producer-specific aliases.

## Current-only contract

| Artifact | Current version | Authority |
| --- | ---: | --- |
| Frida raw JSONL | 22 | `scripts/frida/gameplay_diff_capture.js` |
| Frida evidence sidecar | 2 | `src/crimson/dbg/frida_finalize.py` |
| CDT container | 2 | `src/crimson/dbg/schema.py` |
| CDT payload schema | 15 | `src/crimson/dbg/schema.py` |
| CRD replay | 16 | `src/crimson/replay/types.py` |

These artifacts are throwaway debugging data. Readers and finalizers require
exactly these versions; they do not translate, normalize, or salvage an older
recording. Regenerate an original capture with the current Frida script when a
version changes.

## Canonical tick

Every `TickRecord` contains:

- `tick_index`
- `elapsed_ms`
- `dt_ms_i32`
- `mode_id`
- `channels`

Schema 15 requires every channel on every tick:

- `replay_step`
- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples`

The core channel types live in
`src/crimson/dbg/canonical_channels.py`; Zig mirrors the same wire schema in
`crimson-zig/src/cdt_trace.zig`.

### Replay-driving evidence

`replay_step` is the first channel because it records what drove the tick, not
only what existed after the tick:

- `dt`: the exact f32 frame delta used by replay
- `inputs`: one input row per player with movement, aim, and flags
- `prelude`: ordered native frame-RNG advances and perk operations applied before simulation
- `postlude`: perk-menu generation applied after simulation while tick RNG
  tracing remains active
- `commands`: Typ-o commands applied as part of the tick

The generated `.crd` sidecar and replay-recorded `.cdt` both derive from this
same payload. There is no separate `replay_inputs` field in the raw tick
contract.

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
- Frida run-local and session-global tick indices are contiguous
- tick, checkpoint, timing, mode, and player counts must agree
- `replay_step.inputs` and `timing_samples` must be non-empty
- every tick has exactly one `gpur_enter` timing sample
- `gpur_enter.frame_dt_f32` equals `replay_step.dt`
- `gpur_enter.frame_dt_ms_i32` equals `TickRecord.dt_ms_i32`
- RNG rows use one-based call indices and valid CRT state transitions
- a Frida stream must close every run; EOF after `run_end` is complete

An `error`/`run_error`, truncated lifecycle, out-of-sequence row, or mismatched
counter invalidates the capture. Partial-run finalization would turn missing
evidence into an apparent behavior difference, so it is intentionally not
supported.

## Producer boundaries

### Frida original capture

Capture format 22 emits typed lifecycle rows and canonical tick channels. The
finalizer validates them, writes one CDT/CRD pair per completed run, and writes
a sibling typed evidence sidecar containing the producer-only rows used to
explain how canonical values were derived. The CDT, CRD, RNG report, and typed
evidence sidecar publish as one rollback-safe artifact bundle.

Run-start creature-pool residue is copied into the replay header when present.
That preserves original state which survives the native reset and avoids
reconstructing it from the first post-tick snapshot.

### Python replay recorder

Python records the same replay step, checkpoint, simulation state, entity, RNG,
and timing evidence while it executes a CRD replay. Metadata identifies the
replay fingerprint and implementation, and is validated through the same typed
`TraceMeta` contract.

### Zig replay recorder

Zig writes the same CDT v2/schema 15 chunks and channel payloads. Use
`crimson-zig dbg record <replay.crd> --out <trace.cdt>` to record and
`crimson-zig dbg verify` to check that its compiled schema and replay versions
match the owned contract.

## Differential workflow

Run `dbg verify` after changing any owned format; it prints the complete current
Frida, evidence, CDT, replay, and checkpoint version matrix, then checks the
Python, Frida, and Zig source declarations, tick-boundary field order, required
channels, and replay/checkpoint payload ceilings for drift.

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
