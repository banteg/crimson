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

The current MSVC 6.5 reconstruction is an honest 95.35% WIP: it has the same
86 instructions and all six references, with only two commutative x87 add
operand orders differing. No padding operations or other fakematch constructs
are used to hide that remaining source-expression uncertainty.
