# survival_spawn_creature

High-value recovery for the 1,973-byte survival-mode random creature builder
at `0x00407510`.

The source follows the live Binary Ninja evidence from allocation through final
color clamping: experience-tier type selection, randomized base size/heading,
type-specific speed and health, experience-driven tint ramps, three rare color
variants, two rarer boss variants, and final health/reward/color normalization.

The exact VC6 shape reveals two aggregate member operations: a two-float
velocity and a four-float RGBA tint. The scratch now uses the canonical
`creature_t` directly, including its `velocity` and `color` overlays, instead
of maintaining a second padded 0x98-byte creature layout. The temporary
constructors and final color pointer are source-level object operations, not
scheduling constraints. Ordinary signed `%` expressions also recover the
native negative-remainder correction for the two-way type roll.

Its input is likewise a read-only `vec2f_t`. Source and the saved Binary Ninja
prototype now render `pos->x`/`pos->y`; the aggregate recovery preserves all
517 instructions and 85 references.

Focused result: **100.00%**, 517/517 instructions and 85/0/0 references. The
anti-fakematch validator passes; there are no volatile operations, synthetic
references, dead expressions, or register-forcing constructs.

## Port parity

The exact instruction stream also fixes Python's survival stat staging. Native
stores `size * 0.0952381f` at PC24/f32 precision, builds reward left-to-right as
random base plus speed, contact damage, and health terms, then rounds the final
`* 0.8f`. Each tint arithmetic instruction likewise runs at PC24 precision.
The old Python builder kept those expressions as doubles; some rewards differed
after their eventual f32 store, and the baseline green tint was one ULP high.
Zig stored f32 values but associated reward from health back toward the random
base; seed 10 exposed a one-ULP final reward difference. Both ports now follow
the recovered left-to-right PC24 chain, with bit-exact contact, reward, and tint
regressions.

The allocated creature now receives the caller's coordinates through the
canonical `creature_t::position` aggregate rather than two scalar aliases.
VC6 emits the same exact 517/517 instructions and 85/0/0 references.
