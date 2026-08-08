---
tags:
  - rewrite
  - parity
  - float-precision
---

# Float expression precision map (decompile-derived)

Purpose: fast lookup for Python + Zig parity work. This map classifies common
expression families by the precision model they need in deterministic gameplay
paths.

Use this with [float parity policy](float-parity-policy.md).

## Precision classes

- `F32_STORE`: expression result should be stored/kept as float32 state.
- `X87_INTERMEDIATE_THEN_F32`: compute with x87-like widened intermediate, then
  spill to float32 at the native-equivalent store point.
- `F64_BOUNDARY_ONLY`: f64/double is acceptable at formatting/IO boundaries,
  but should not drive gameplay state evolution.

Runtime assumption for this map:
- CRT startup sets x87 precision-control to 53-bit (`__controlfp(_PC_53,
  _MCW_PC)` equivalent path), so “x87 intermediate” here means x87-shaped
  evaluation under `PC_53` unless a function locally overrides CW.
  Evidence: `crt_set_default_precision` returns the control-word mapping call at
  `0x004636f8`; the helper applies the `0x10000` precision selector around
  `0x00469f8e`–`0x00469f9e`.

## Decompile-wide signal counts (for confidence)

Historical Ghidra whole-view scan:

- `float10` occurrences: `1496`
- `(float10)fcos/(float10)fsin/(float10)fpatan`: `270`
- explicit `(float)(...)` casts: `996`
- explicit `(double)` casts: `31` (mostly CRT/vararg boundaries)

Historical IDA whole-view scan:

- `fcos/fsin/fpatan/fsqrt`: `62/60/15/36`
- `fld/fstp/fmul/fadd/fsub/fcomp/fnstsw`: `1094/897/704/363/259/296/296`

## Expression lookup table

| ID | Expression family | Class | Native pattern (decompile) | Required model | Example anchor |
|---|---|---|---|---|---|
| `E01` | Heading from delta (`atan2` path) | `X87_INTERMEDIATE_THEN_F32` | `(float10)fpatan((float10)dy,(float10)dx)` then `(float)` store | Widen for `atan2`, spill to `f32` immediately when writing heading | `player_update` @ `0x004136b0` |
| `E02` | Direction from heading (`cos`) | `X87_INTERMEDIATE_THEN_F32` | `(float10)fcos((float10)heading - (float10)1.5707964)` | Widen for trig op, then `f32` spill into velocity/move components | `player_update` @ `0x004136b0` |
| `E03` | Direction from heading (`sin`) | `X87_INTERMEDIATE_THEN_F32` | `(float10)fsin((float10)heading - (float10)1.5707964)` | Same as `E02` | `player_update` @ `0x004136b0` |
| `E04` | Creature steering trig+spill | `X87_INTERMEDIATE_THEN_F32` | `fpatan` target heading; `fcos/fsin` heading-to-vel; `(float)` assignments | Keep transcendental intermediates widened; persist `heading/vel_*` as `f32` | `creature_update_all` @ `0x00426220` |
| `E05` | Projectile angle step trig | `X87_INTERMEDIATE_THEN_F32` | `(float10)angle - half_pi`; `fcos/fsin` in per-substep motion | Widen trig/intermediate multiply chain; spill to `f32` locals/state at native stores | `projectile_update` @ `0x00420b90` |
| `E06` | Length / distance compare | `X87_INTERMEDIATE_THEN_F32` (branch-sensitive) | `SQRT(dx*dx + dy*dy) < threshold` | Preserve op order and compare boundary behavior; treat as branch-sensitive | `creature_update_all` @ `0x00426220` |
| `E07` | Vec2 length helper return | `F32_STORE` | `return SQRT(v[1]*v[1] + *v * *v);` | API return is `f32`; avoid carrying widened value past the return boundary | `vec2_length` @ `0x00417660` |
| `E08` | Normalize via reciprocal sqrt | `X87_INTERMEDIATE_THEN_F32` | `(1.0 / SQRT(a)) * ...` assigned into vector components | Keep rsqrt/sqrt intermediate precision; write normalized components as `f32` | `vec2_normalize_safe` @ `0x00455587` |
| `E09` | Angle wrapping/approach arithmetic | `F32_STORE` | add/sub/abs/clamp around `tau`; no transcendental | Keep exact operation order and `f32` store cadence; no need for boundary `f64` promotion | `angle_approach` @ `0x0041f430` |
| `E10` | Timers/cooldowns/speeds state updates | `F32_STORE` | `state = state +/- frame_dt * k`, clamp to bounds | Keep state as `f32`; avoid accidental long-lived `f64` accumulators in gameplay paths | `player_update` @ `0x004136b0` |
| `E11` | Float-int conversion hotspots (`__ftol` family) | `X87_INTERMEDIATE_THEN_F32` (int boundary) | explicit `__ftol()` calls in movement/effects code | Route through native-compatible helper; treat conversion semantics as parity-sensitive | `projectile_update` @ `0x00420b90` |
| `E12` | Formatting/vararg conversion | `F64_BOUNDARY_ONLY` | `crt_sprintf(..., (double)f32_value)` | `double` here is boundary formatting ABI, not simulation precision policy | `mods_menu_update` @ `0x0040e9a0` |

## Binary Ninja cross-check pattern

Binary Ninja HLIL repeatedly shows the same model:

- `fconvert.t(...)` before transcendental/extended arithmetic
- `fconvert.s(...)` at storage boundaries

Example: `gameplay_update_and_render` at `0x00409e1d` widens the projectile
heading through `fpatan` before the float32 call boundary.

## Practical implementation guidance

- Python gameplay domain:
  - Keep long-lived runtime state in `np.float32`/explicit `f32` wrappers.
  - For `E01..E06/E08/E11`, run native-style helper path then spill to `f32` at
    the native-equivalent assignment point.
  - Do not keep replay-decoded `f64` values live in gameplay state.
- Zig gameplay domain:
  - Keep state fields as `f32`.
  - Use shared native math helpers for trig/atan/angle routines; call
    `roundF32`-style spill helpers at explicit store points.

## Fast lookup recipes

- Resolve the function and current tool snapshots:
  - `just analysis-function player_update`
- Search live Binary Ninja HLIL:
  - `bn search text 'fconvert\\.(t|s)|fpatan|fcos|fsin' --view hlil --target crimsonland.exe.bndb`
- Save a reusable function artifact:
  - `bn bundle function player_update --target crimsonland.exe.bndb --out /tmp/player_update.json`
