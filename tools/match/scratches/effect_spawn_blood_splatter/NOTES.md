# effect_spawn_blood_splatter

Native target: `crimsonland.exe` at `0x0042eb10` (361 bytes).

The emitter respects the no-violence setting, then creates two effect-7 blood
particles opposite the supplied hit angle. Each receives a randomized visual
angle, 1..8-pixel extent, independent speed components from 100..163 projected
onto the reversed direction, and positive growth from 0.10 through 3.91.

All 82 native instructions and all 27 static references match. The reversed
direction is materially an extended-precision `double`: VC6 rounds it back
into the float angle argument used for per-particle rotation, but keeps the x87
value live across both cosine and sine projections. A plain float direction
has identical gameplay behavior but spills and reloads instead of emitting the
native `fld st(0)` pair.

The original particle API passes positions as `vec2_t`; the lowered matching
boundary and saved Binary Ninja prototype therefore use `const vec2f_t *`.
This type-only recovery preserves all 82 instructions and 27 references.

The emitter now writes the shared template through its canonical `velocity`
and `half_extent` aggregates. This remains exact at 82/82 instructions and
27/0/0 references.
