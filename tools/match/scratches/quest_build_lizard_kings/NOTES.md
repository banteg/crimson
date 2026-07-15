# `quest_build_lizard_kings`

Native target: `crimsonland.exe` at `0x00437710` (254 bytes).

Live Binary Ninja evidence recovers three initial template `0x11` lizard
formations at `(1152, 512)`, `(-128, 512)`, and `(1152, 896)`, all at 1500 ms
with count one. They are followed by 28 template `0x31` lizards on a radius-256
ring centered at `(512, 512)`. The ring step is `0.34906587` radians, triggers
start at 1500 ms and advance by 900 ms, and heading is the independently
recomputed negative ring angle. The final count is 31.

The candidate reproduces the fixed-entry vector temporaries and the complete
native x87 ring stack: the integer index remains live below the positive angle,
cosine and sine consume the duplicated angle, and the original index is then
multiplied by the negative step for heading. `pos.set(x, y)` avoids a dynamic
vector temporary and raises the candidate to 78.20%, with 67 instructions
against 66 and all six constant references resolved.

The residual is one loop-invariant `mov edi, 0x31`. The native instead stores
the template as an immediate and consequently chooses the template field as
its pointer induction base. Direct position fields, an all-fields setter, a
metadata-only setter, `msvc6.5pp`, and `/G6` were checked. None removes that
allocation without degrading the proven x87 shape or adding an artificial
dependency, so this remains an honest WIP.
