# ui_element_layout_calc

Native target: `crimsonland.exe` at `0x0044fb50` (288 bytes).

The routine skips dedicated element slots 26 and 27. For all other elements it
translates the four interaction-bound floats, then derives a tightened hit box
from vertices zero and two: the leading edge is inset by 54% horizontally and
28% vertically, while the trailing edge is inset by 5% and 10%.

When `direction_flag` is set, it walks the active vertex count in pairs and
swaps their U coordinates. The recovered 28-byte vertex layout is
`x, y, z, rhw, color, u, v`; eight vertices fill the element's former opaque
`+0x3c..+0x11b` region, and the count follows at `+0x120`.

The scratch now consumes the authoritative `ui_element_t` layout directly.
Named `pos`, hover-bound, vertex, `vertex_count`, and `direction_flag` fields
replace the former 0x318-byte shadow record and its three opaque padding
regions. This agrees with Binary Ninja's live type at every accessed offset,
including the 0x1c-stride `ui_element_vertex_t` records.

Keeping ordinary two-float reference views for the vector operators improves
the exact prefix from 16 to 34 instructions without changing the 86-instruction
body or its six resolved references. Snapshotting `direction_flag` after the
trailing-bound aggregate copy also recovers the native early byte load and
raises the score from 95.35% to 96.51%.

The remaining three changed instructions are independent scheduling choices:
the native starts the width subtraction before committing the second
`hover_min` component and loads `direction_flag` between the two aggregate
`hover_max` stores. Moving the width calculation or splitting the aggregate
copy materially worsens the candidate, so the stronger typed source is
retained without volatile state or artificial dependencies.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**96.51%**, 86/86 instructions, prefix 34, and `6/0/0` references. Its two
regions contain only the three documented store/load scheduling differences;
all bounds translations, inset constants, skip cases, direction handling,
vertex count, and U-coordinate swaps agree with the native routine.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
