# `quest_build_alien_dens`

Native target: `crimsonland.exe` at `0x00436720` (249 bytes).

Live Binary Ninja evidence recovers five template `0x08` alien dens. Two
corner dens spawn at `(256, 256)` and `(768, 768)` at 1500 ms; the center den
spawns at `(512, 512)` at 23500 ms with the player count; and the remaining
corners `(256, 768)` and `(768, 256)` spawn at 38500 ms. All other counts are
one, and the function returns five entries.

The native allocates one eight-byte position temporary and copies each pair of
float constants into the 24-byte records. A small `quest_vec2_t` constructor
plus direct metadata assignments preserves that source evidence, emits the
same 60 instructions, keeps template `8`, count `1`, and the active trigger in
the same registers, and resolves the player-count reference.

The residual is independent-store scheduling: VC6 groups several position and
metadata stores across adjacent records rather than retaining the native
per-entry order. Whole-entry setters, split metadata setters, folded builder
calls, `pos.set(x, y)`, explicit local-order variants, and reversed metadata
order were checked. They either remove the proven position temporary, swap the
long-lived trigger/count registers, or lower the score. The 68.33% candidate is
kept as an honest WIP without artificial dependencies.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
