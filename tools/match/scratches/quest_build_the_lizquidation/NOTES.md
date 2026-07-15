# `quest_build_the_lizquidation`

Native target: `crimsonland.exe` at `0x00437c70` (245 bytes).

Live Binary Ninja evidence recovers ten paired template `0x2e` lizard waves
from the right and left edge midpoints. Each wave uses count `wave + 6` and
trigger `wave * 8000 + 1500`. Wave four also emits one template `0x2b` alien
at `(terrain_width + 128, terrain_width / 2)`, trigger 1500, count 2. The
result contains 21 entries.

The candidate preserves the native base-plus-count record builder, integer to
float coordinate conversions, 24-byte record stride, loop arithmetic, branch,
and output count. It compiles to the same 79 instructions with all references
resolved. The remaining score is a VC6 allocation and scheduling split: the
candidate cycles the loop, trigger, and entry-pointer registers and fills x87
latency slots with independent metadata stores in a different order.

Cursor-based storage, an inlined `next()` method, whole-vector and all-fields
setters, declaration/lifetime variants, `msvc6.5pp`, `msvc6.6`, `msvc7.0`,
`/G6`, and `/O1` were checked. None reproduced the native shape, and several
made it materially less plausible. This remains an honest WIP rather than
adding dummy dependencies or volatile state to steer the compiler.
