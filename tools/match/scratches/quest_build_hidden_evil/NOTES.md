# `quest_build_hidden_evil`

Native target: `crimsonland.exe` at `0x00435a30` (407 bytes).

Live Binary Ninja evidence recovers five fixed waves at the same dynamic map
edge: x is signed integer `terrain_texture_width / 2`, and y is
`terrain_texture_height + 64`, with both converted to float separately for
every entry. Heading is left untouched. The waves are:

- template `0x21`, trigger 500, count 50;
- template `0x22`, trigger 15000, count 30;
- template `0x23`, trigger 25000, count 20;
- template `0x23`, trigger 30000, count 30;
- template `0x22`, trigger 35000, count 30.

The candidate reproduces the exact 101-instruction body and all ten audited
global references, scoring 97.03%. Every instruction after entry zero matches.
The sole residual is VC6 scheduling of its three independent metadata stores:
the candidate fills x87 conversion latency with them, while the native body
emits them after both position stores. A combined position-and-metadata setter
produces the same candidate, so the simpler repeated vector assignment remains
the strongest plausible source shape.
