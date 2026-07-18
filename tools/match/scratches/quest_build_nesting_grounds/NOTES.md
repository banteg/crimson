# `quest_build_nesting_grounds`

Native target: `crimsonland.exe` at `0x004364a0` (626 bytes).

Live Binary Ninja evidence recovers twelve fixed quest entries. Entries 0, 4,
5, 10, and 11 repeatedly recompute the same dynamic position from signed
integer `terrain_texture_width / 2` and `terrain_texture_height + 64`; the
remaining entries form a fixed nest pattern around the map. Heading is left
untouched. The entries are:

- template `0x1d`, trigger 1500, count `player_count * 2 + 6`;
- template `0x09` at (256, 256), trigger 8000, count 1;
- template `0x09` at (512, 512), trigger 13000, count 1;
- template `0x09` at (768, 768), trigger 18000, count 1;
- template `0x1d`, trigger 25000, count `player_count * 2 + 6`;
- template `0x1d`, trigger 39000, count `player_count * 3 + 3`;
- template `0x09` at (384, 512), trigger 41100, count 1;
- template `0x09` at (640, 512), trigger 42100, count 1;
- template `0x09` at (512, 640), trigger 43100, count 1;
- template `0x08` at (512, 512), trigger 44100, count 1;
- template `0x1e`, trigger 50000, count `player_count * 2 + 5`;
- template `0x1f`, trigger 55000, count `player_count * 2 + 2`.

The recovered two-field spawn metadata setter is the same source idiom that
matches `quest_build_two_fronts` and `quest_build_zombie_masters` exactly.
Using it consistently here raises the honest match from 94.93% to 97.10% while
preserving the exact 138-instruction body and all fifteen audited references.
In particular, it eliminates both late metadata interleavings from the x87
position conversions rather than constraining those stores artificially.

Three independent scheduling clusters remain: the template-register load and
`edi` save are swapped, VC6 hoists the shared `768.0f` load across one metadata
setter, and one player-count result trades places with the next fixed position.
The values, addresses, conversions, and final count are otherwise exact.
Attempts to model the positions as vector temporaries introduce 42 extra
instructions; fixed-position setters retain the same score while regressing
other scheduling. The direct position fields plus shared metadata setter are
therefore the strongest plausible source shape without artificial dependencies
or register forcing.
