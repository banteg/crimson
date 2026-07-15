# `quest_build_surrounded_by_reptiles`

Native target: `crimsonland.exe` at `0x00438940` (242 bytes).

Live Binary Ninja evidence recovers two five-step lines of paired template
`0x0d` spawns. The first line places entries at x=256 and x=768 while y is
`line_offset * 0.2 + 256`, with triggers 1000 through 4200 in steps of 800.
The second line transposes the construction, using y=256 and y=768 with
triggers 8000 through 11200. `line_offset` starts at zero in each line and
advances by 512, yielding a 102.4-coordinate step. All entries have count 1;
the final count is 20.

The exact source shape uses a cursor/count builder, advances the line offset
after both entries, and orders the second entry's count increment before its
cursor increment. This reproduces the shared live x87 axis value, paired
`fst`/`fstp` stores, second-loop cursor reconstruction, and all register
lifetimes. The VC6 candidate matches all 68 instructions exactly.
