# `quest_build_ghost_patrols`

Native target: `crimsonland.exe` at `0x00436200` (334 bytes).

Live Binary Ninja evidence recovers one opening template `0x2b` red alien at
the right edge, trigger 1500 and count two. Twelve template `0x19` ring patrols
then alternate x between -128 and 1152 at the vertical midpoint, beginning at
2500 ms and advancing by 2500 ms with count one. The tail adds a template
`0x2b` entry at `(-264, midpoint)` and trigger `(wave - 1) * 2500`, followed by
a template `0x18` entry at `(-128, midpoint)` and trigger
`(wave * 5 + 15) * 500`. The final count is 15. The Python and Zig ports agree
for the native 1024-square quest terrain.

The indexed `spawns[wave + 1]` source form reproduces the native biased ESI
induction pointer, signed `% 2` lowering, alternating immediate stores, signed
width halving, x87 conversions, loop variables, tail multiplication chains,
constant output count, and all five references. It compiles to the same 90
instructions, preserves a 14-instruction prefix, and scores 81.11%.

The residual is independent VC6 scheduling. Native advances the induction
pointer and wave before the midpoint conversion completes, then stores the
loop metadata through negative offsets; the candidate schedules those stores
before the x87 result. The tail count-one stores and epilogue arithmetic are
likewise reordered. A direct cursor, a post-incremented cursor, ternary float
selection, direct metadata fields, and explicit count-one lifetime were
checked. `msvc6.5pp` and `msvc6.6` are identical; `msvc7.0` regresses to 85
instructions. This remains an honest WIP without volatile or dependency-only
scheduler steering.
