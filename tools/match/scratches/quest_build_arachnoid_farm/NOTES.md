# `quest_build_arachnoid_farm`

Native target: `crimsonland.exe` at `0x00436820` (382 bytes).

Live Binary Ninja evidence recovers three horizontal spawner lines. The first
two contain `config_player_count + 4` template `0x0a` entries, starting at
`(256, 256)` and `(256, 768)` with an x step of 102.4. Their triggers start at
500 and 10500 ms and advance by 500 ms. The middle line contains
`config_player_count + 7` template `0x10` entries at y=512, uses an x step of
64, and advances triggers from 40500 ms in 3500 ms steps. Every entry has
count one, so the normal one-player table contains 18 entries.

The exact source uses three guarded `do/while` loops. Whole-vector construction
reproduces the native 12-byte frame, x87 conversion spills, fixed-y hoists, and
record-store schedule. The separate line indices share one stack slot, while a
single append count owns every emitted entry. The positive third-line path
writes the output count and returns, preserving the native dual epilogue.

The structured loop spelling is material to VC6 allocation. Equivalent
`while` loops reproduce all semantics and instruction counts but choose seven
different operand bytes across the line preheaders: the first two entry-base
calculations exchange EAX and EDX, and the third bound uses `lea eax` instead
of destructively adding seven to EDX. Expressing the already guarded loops as
`do/while` recovers all three native choices without artificial dependencies or
register forcing.

The candidate is exact: all 112 instructions and 382 bytes match, including
the complete 112-instruction prefix and all ten static references.
