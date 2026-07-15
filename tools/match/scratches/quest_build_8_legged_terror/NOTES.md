# `quest_build_8_legged_terror`

Native target: `crimsonland.exe` at `0x00436120` (213 bytes).

Live Binary Ninja evidence recovers the opening shock boss at
`(terrain_texture_width - 256, terrain_texture_width / 2)`, template `0x3a`,
1000 ms, count 1. It is followed by four-corner waves at `-25` and `1049`,
using template `0x3d`. Triggers run from 6000 while below 36800 in steps of
2200. The top-left and bottom-left entries use the player count; the other two
use count 1. The builder therefore emits 57 entries.

Keeping the cursor and emitted count together in the builder object prevents
VC6 from folding the final count and recovers the native count-register
increments. The entire repeated-wave loop matches instruction-for-instruction.
The candidate has the same 68 instructions and scores 92.65%; all residuals
are confined to scheduling in the one-time opening entry, where the far-edge
constant and three independent metadata stores move around the integer-to-float
`pos.y` conversion. No dependency is introduced to force that ordering.
