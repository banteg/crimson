---
tags:
  - rewrite
  - parity
---

# Delta Time Parity Reference

This page is the source of truth for delta-time semantics used by Python/Zig rewrites and parity tooling.

## Runtime timing model overview

- `frame_dt`: per-tick seconds-domain delta (`float`/`f32`) used for simulation math.
- `frame_dt_ms`: per-tick integer cadence (`i32`) used by integer timer/cooldown logic.
- In native flow, both are observed across the gameplay frame path; integer cadence is derived from second-domain dt via `__ftol`-equivalent truncation.
- Rewrite contract: store canonical timing in seconds, derive integer cadence only through helper conversion.

## Mutation timeline within one gameplay tick

1. Outer-loop `REFLEX_BOOSTED` scaling applies first.
2. `gameplay_update_and_render` applies gameplay-pass scaling and re-derives `frame_dt_ms`.
3. `player_update` remaps to player-local dt and restores on exit.
4. Function-end restore returns global timing state to expected post-tick values.
5. Zeroing/gating paths may force zero dt under specific pause/slow/guard conditions.

Ordering is parity-critical: scaling, remap, integer re-derive, and restore must occur in the same sequence.

## Static reference anchors

- `__ftol` at `0x00461054` contains the control-word save/restore sequence.
- Instruction `0x00461063` applies the round-control override (`| 0x0c`) used
  for truncation before conversion.
- `gameplay_update_and_render` at `0x0040aab0` contains the explicit zero gate
  that clears both `frame_dt_ms` and `frame_dt`.

## Conversion contract (`__ftol`)

- Crimsonland parity requires truncation/chop semantics (round toward zero), not bankers rounding and not nearest integer.
- Tie examples:
  - `+0.5 -> 0`
  - `+2.5 -> 2`
  - `-1.5 -> -1`
- Canonical helper for cadence conversion: `ftol_ms_i32(dt_seconds)` where milliseconds are `float32(dt_seconds * 1000.0)` before truncation.

Equivalent forms:

```python
# Python parity helper shape
def ftol_ms_i32(dt_seconds: float) -> int:
    return int(float(f32(dt_seconds * 1000.0)))
```

```zig
// Zig parity helper shape
fn ftolMsI32(dt_seconds: f32) i32 {
    return @intFromFloat(dt_seconds * 1000.0);
}
```

```cpp
// C++ parity intent
int ftol_ms_i32(float dt_seconds) {
    return (int)(dt_seconds * 1000.0f); // truncates toward zero
}
```

## Units and field semantics for rewrite

- `dt`: canonical per-tick seconds-domain value.
- `dt_sim`: simulation-domain dt after active gates/scales.
- `dt_player_local`: player-local dt used inside player update/remap windows.
- `dt_ms_i32`: integer cadence derived from `dt` via `ftol_ms_i32()`.
- `dt_sim_ms_i32`: integer cadence derived from `dt_sim` via `ftol_ms_i32()`.
- Replay rows:
  - `Replay.dt` is required and length-matched to `inputs`.
  - `*_ms_i32` values are derived on load/use, not stored as authoritative rows.

## Worked tick timeline example

Example tick with concrete numbers and call-order:

1. Outer frame loop starts from nominal `1/60 = 0.016666668`.
2. If `REFLEX_BOOSTED` outer scaling is active, apply `* 0.899999976` first:
   - `dt_entry = f32(0.016666668 * 0.899999976) = 0.015`
3. At `gameplay_update_and_render` entry, derive entry cadence:
   - `dt = 0.015`
   - `dt_ms_i32 = ftol_ms_i32(0.015) = 15`
4. With `time_scale_active_entry=true` and `reflex_boost_timer=0.5`:
   - `time_scale_factor = f32((1.0 - 0.5) * 0.699999988 + 0.300000012) = 0.65`
   - `dt_sim = f32(0.015 * 0.65) = 0.00975`
   - `dt_sim_ms_i32 = ftol_ms_i32(0.00975) = 9`
5. Player-local remap uses:
   - `dt_player_local = f32((0.600000024 / 0.65) * 0.00975) = 0.009000001`
6. If zero-gate triggers this tick:
   - keep entry cadence (`dt=0.015`, `dt_ms_i32=15`)
   - force sim cadence to zero (`dt_sim=0.0`, `dt_sim_ms_i32=0`)

## Consumer map

Seconds-domain consumers:

- Movement and kinematic integration.
- Physics-style position/velocity progression.
- Continuous interpolation-style logic.

Integer-ms cadence consumers:

- Survival/rush/quest timers and wave cadence.
- Cooldowns, durations, and countdown-style gameplay gates.
- Legacy timer codepaths expecting integer elapsed deltas.

## Replay/capture/debug semantics

- Replay records per-tick `dt` as authoritative timing input for deterministic reruns.
- Capture may include sub-tick `timing_samples` rows to preserve phase-level timing evidence.
- Frida replay-grade capture must include a `gpur_enter` timing sample, and JSONL tick timing must be sourced from that row rather than from fallback aliases.
- Finalize must preserve timing evidence into trace channels (not drop/flatten away).
- Diff/bisect must compare `timing_samples` and report first timing-phase mismatch when present.

## Porting pitfalls and invariants

Common drift causes:

- Mixing truncation and rounding rules across systems.
- Duplicated local dt-to-ms derivations with inconsistent semantics.
- Missing or reordered restore steps around player-local remap.
- Hidden fallback branches that ignore replay dt rows.

Required invariants:

- `run_replay` and `run_replay_info` consume equivalent replay timing rows.
- Replay codecs reject missing/legacy timing rows for current format version.
- Trace/finalize readers reject unsupported schema versions (no silent compatibility mode).
- Parity-critical dt-to-ms integer derivation uses only `ftol_ms_i32`.
- Recorder-produced replays always emit finite, non-negative `Replay.dt` rows and row count equals input ticks.
