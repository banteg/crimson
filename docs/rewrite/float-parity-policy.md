# Float parity policy

This project targets high-fidelity replay and deterministic simulation parity.
For gameplay code, float behavior is part of the contract.

## Default rule

In deterministic gameplay paths, prefer **native float32 fidelity** over source
readability:

- Keep decompiled float constants when they influence simulation outcomes.
- Keep native operation ordering when it changes rounding boundaries.
- Keep float32 store/truncation points where native stores to `float`.

Do not auto-normalize literals like `0.6000000238418579` to `0.6` in parity
critical code unless parity evidence shows the change is behavior-neutral.

For an expression-level lookup table (with decompile anchors), see
[float expression precision map](float-expression-precision-map.md).

## Why

Small float deltas can reorder branch decisions and collision outcomes, then
amplify into RNG drift and deterministic divergence over long runs.

## Concrete findings about original x87 usage

The original executable is x87-heavy in gameplay hot paths, but persistent
gameplay state is still mostly float32.

### Gameplay runs with x87 precision control at 24 bits

Although CRT startup sets `PC_53`, the Direct3D 8 device init does not pass
`D3DCREATE_FPU_PRESERVE`, so D3D drops the x87 control word to single
precision before gameplay ever runs. In gameplay code every x87 add/mul/div
therefore rounds to f32 per operation, while `fsin`/`fcos`/`fpatan` still
evaluate in extended precision internally (their rounding lands in the first
downstream arithmetic op).

Validated empirically against v14 capture `vel`/`move_speed` channels: the
creature velocity chain (`creature_update_all` 0x426dab) reproduces native
bit-exactly only when each multiply is rounded to f32 (152/154 survival and
12/12 rush walker-ticks); a double-precision chain with a single final
rounding flips ~5% of components by 1 ulp. This is why the rewrite's
f32-after-every-op idiom works, and it is the default model for any
newly-ported expression.

### Address-keyed static evidence

- CRT startup explicitly sets x87 precision-control to 53-bit (`PC_53`):
  - `_start` at `0x00463026` calls `crt_run_initializers` at instruction
    `0x004630cb`.
  - `crt_run_initializers` at `0x00462eb0` invokes `FUN_00460cb8` through
    `data_47b160` at `0x0047b160`.
  - `FUN_00460cb8` calls `sub_4636e7`, which returns
    `sub_469e81(0x10000, 0x30000)` (`0x00460cb8`, `0x00460cc7`, and
    `0x004636f8`).
  - In the CRT mapping helper, `arg1 & 0x30000 == 0x10000` sets CW precision
    bits to `0x200` (53-bit mode) around `0x00469f8e`–`0x00469f9e`.
  - IDA function names align with this path:
    `__setdefaultprecision -> __controlfp`:
    `analysis/ida/raw/crimsonland.exe/functions.json` lines around `13692`,
    `13687`.
- Trig and atan paths are emitted as x87 transcendental ops with `float10`
  temporaries:
  - `angle_approach` at `0x0041f430` is called from creature movement.
  - Heading/direction math uses `fpatan` + `fcos/fsin` with `float10` casts:
    see `player_update` at `0x004136b0` and `creature_update_all` at
    `0x00426220`.
  - Player movement/aim branches repeatedly compute
    `fcos(heading - 1.5707964)` / `fsin(heading - 1.5707964)` via `float10`.
- Those results are then spilled back to `float` state fields at explicit
  assignment points, for example:
  - assignments into `move_dx`/`move_dy` and velocity slots in `player_update`
    and `creature_update_all`;
  - similar float spills in the low-health effect direction path in
    `player_update`.
- Binary Ninja HLIL shows the same pattern as `fconvert.t(...)` (widen) and
  `fconvert.s(...)` (spill to float32), confirming “extended intermediate,
  float32 storage” rather than all-float64 storage.

### What this means (non-handwavy)

- The game is **not** “everything in 80-bit all the way down”.
  - Startup default precision is `PC_53`, so “x87 intermediate” is not
    equivalent to “always full 80-bit precision.”
  - Intermediates in many arithmetic/trig expressions are x87-extended.
  - Authoritative long-lived state slots (player/creature/projectile fields)
    are float32 stores.
- Therefore parity errors come from two specific failure modes:
  1. wrong trig/atan evaluation behavior around branch boundaries,
  2. wrong placement of float32 spills (too early or too late).

### Differential evidence this matters in practice

- Session notes repeatedly show divergence movement when arithmetic order or
  spill points differ:
  - `docs/frida/differential-sessions/session-18.md`:
    decompile-order `angle_approach` fix moved first mismatch from `7722` to
    `7756`.
  - `docs/frida/differential-sessions/session-19.md`:
    tighter float32 spill behavior in creature heading/tau-boundary handling
    cleared the remaining `quest_1_8` capture.

### Implementation consequence

Treat native math as:
- x87-like trig/atan intermediates where possible,
- explicit float32 store boundaries in gameplay state,
- no blanket “upgrade everything to f64” and no blanket “truncate every op”.

## Rewrite math model (current)

Deterministic gameplay math follows three rules:

1. Use `f32` as the gameplay-domain type (positions, headings, timers, speeds,
   projectile scalar state) unless a value is truly boundary-only.
2. Widen only at boundaries (replay decode, serialization, diagnostics), then
   immediately spill back to `f32` at the native-equivalent store point.
3. Route parity-critical trig/angle helpers through shared native-style math
   helpers, not ad-hoc per-module implementations.

### Zig runtime implementation

- Canonical helpers live in `crimson-zig/src/runtime/native_math.zig`.
- Native constants are sourced from exact `f32` bit patterns (`pi`, `half_pi`,
  `tau`, turn-rate scale), not simplified decimal literals.
- `roundF32(...)` is the canonical spill helper for boundary/store truncation.
- `sinNative/cosNative/atan2Native` behavior:
  - use `sinl/cosl/atan2l` when `c_longdouble` is wider than `f64`,
  - otherwise use `sin/cos/atan2`,
  - freestanding builds fall back to `std.math`.
- Shared angle helpers (`wrapAngle0Tau`, `headingFromDeltaNative`,
  `headingAddPiNative`) encode decompile/native corner-case behavior in one
  place.
- `crimson-zig/src/runtime/math.zig` dispatches by type:
  - `f32` uses the native helper path,
  - `f64`/`comptime_float` remain available for non-domain/boundary use.

## Allowed normalization

Literal simplification is acceptable when all of the following are true:

1. The path is non-deterministic or presentation-only (not gameplay simulation).
2. Differential evidence (capture + verifier) shows no behavior change.
3. A test or session note records that evidence.

If any condition is missing, keep the native-looking float behavior.

## Implementation guidance

- Prefer a single shared helper source over local math wrappers:
  `runtime/native_math.zig` + `runtime/math.zig`.
- Keep gameplay-domain state in `f32`; avoid repeated `f64 -> f32 -> f64`
  churn inside hot loops.
- Use explicit spill points (`roundF32`) where native would store to `float`.
- Prefer parity captures and focused traces over intuitive “cleanup”.
- Document any intentional float deviation in the differential session docs:
  `docs/frida/differential-sessions.md` and the relevant
  `docs/frida/differential-sessions/session-*.md`.
