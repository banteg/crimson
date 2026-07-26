# `quest_build_the_lizquidation`

Native target: `crimsonland.exe` at `0x00437c70` (245 bytes).

Live Binary Ninja evidence recovers ten paired template `0x2e` lizard waves
from the right and left edge midpoints. Each wave uses count `wave + 6` and
trigger `wave * 8000 + 1500`. Wave four also emits one template `0x2b` alien
at `(terrain_width + 128, terrain_width / 2)`, trigger 1500, count 2. The
result contains 21 entries.

The candidate preserves the native base-plus-count record builder, integer to
float coordinate conversions, 24-byte record stride, loop arithmetic, branch,
and output count. VC6 6.5 `/O2 /G6` compiles to the same 79 instructions with
all three references resolved and scores 49.37%, improving the default `/GB`
profile by 37.22 fuzzy-weighted bytes (34.18% to 49.37%). The remaining score
is a VC6 allocation and scheduling split: the candidate cycles the loop,
trigger, and entry-pointer registers and fills x87 latency slots with
independent metadata stores in a different order.

Cursor-based storage, an inlined `next()` method, whole-vector and all-fields
setters, and declaration/lifetime variants were checked. A complete
6.5/6.5pp/7.0 optimizer matrix found `/G6` on VC6 6.5 to be the strongest
profile, though it does not reproduce the native shape exactly. Recovery is
semantic-complete; the residual is compiler register allocation and scheduling
rather than missing behavior. Dummy dependencies and volatile state are not
used to steer the compiler.
