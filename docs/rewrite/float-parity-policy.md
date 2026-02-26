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

### Evidence in decompile artifacts

- Trig and atan paths are emitted as x87 transcendental ops with `float10`
  temporaries:
  - `angle_approach` callsites in creature movement:
    `analysis/ghidra/raw/crimsonland.exe_decompiled.c` (`0x0041f430`,
    lines around `21767`).
  - Heading/direction math uses `fpatan` + `fcos/fsin` with `float10` casts:
    same file, lines around `12248`, `12226`, `12230`, `21754`, `21771`, `21775`.
  - Player movement/aim branches repeatedly compute
    `fcos(heading - 1.5707964)` / `fsin(heading - 1.5707964)` via `float10`.
- Those results are then spilled back to `float` state fields at explicit
  assignment points, for example:
  - `(float)(fVar17 * ...)` assignments into `move_dx/move_dy` and velocity
    slots (same file, lines around `12227-12233`, `21772-21778`).
  - similar float spills in low-health effect direction math (`11961-11962`).
- Binary Ninja HLIL shows the same pattern as `fconvert.t(...)` (widen) and
  `fconvert.s(...)` (spill to float32), confirming “extended intermediate,
  float32 storage” rather than all-float64 storage.

### What this means (non-handwavy)

- The game is **not** “everything in 80-bit all the way down”.
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
