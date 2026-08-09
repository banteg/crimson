# `angle_approach`

Native target: `crimsonland.exe` at `0x0041f430` (299 bytes).

The MSVC 6.5 `/O2 /GB` candidate is exact: 101/101 instructions, all 299
weighted bytes, and references 11/0/0.

## Corrected return type

The decompilers type this helper as `void`, but the native function returns the
clamped shortest angular distance as a `float`. Every exit deliberately leaves
that value in `st(0)`, while both callers at `0x00426c9b` and `0x00426d93`
immediately discard it with `fstp st(0)`. The analogous exact
`player_heading_approach_target` helper returns the same quantity.

## Exact tail ownership

The native performs the arc and direction comparisons before forming the turn
step separately inside the selected arc. Writing each arc update as a
conditional expression reproduces that ownership: VC6 keeps the direction
status live while calculating `frame_dt * amount * rate`, then tail-merges the
two subtract paths. This is also the conditional-expression style used by the
exact neighboring player-heading helper.

Earlier structured forms assigned a shared partial-product local before the
direction condition. VC6 hoisted that product ahead of the second comparison,
leaving a 16.36-byte residual. The arc-owned conditional expressions remove
that residual without aliases, volatile state, or register forcing.
