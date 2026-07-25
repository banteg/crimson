# `quest_build_evil_zombies_at_large`

Native target: `crimsonland.exe` at `0x004374a0` (244 bytes).

Live Binary Ninja evidence recovers ten waves of four template `0x41` zombie
spawns, starting at 1500 ms and advancing by 5500 ms. Each wave enters from
the right, left, bottom, and top edge midpoints. The per-entry count starts at
four and advances through thirteen, producing 40 entries in total.

The exact source shape keeps the entry cursor and emitted count together in a
small builder and tests `spawn_count - 4 < 10`. That expression explains the
native shifted induction test (`lea eax, [esi-4]` followed by `cmp eax, 10`),
while direct integer-to-float coordinate assignments reproduce the x87 store
schedule. The VC6 candidate matches all 81 instructions exactly.

The builder cursor now uses the canonical `quest_spawn_entry_t` and its flat
`pos_x`/`pos_y` fields directly. Removing the private layout duplicate is
byte-neutral: the exact 81-instruction body and reference audit are unchanged.
