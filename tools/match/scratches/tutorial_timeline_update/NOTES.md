# `tutorial_timeline_update`

Native target: `crimsonland.exe` at `0x00408990` (2,907 bytes).

Live Binary Ninja evidence, corroborated against the checked-in Ghidra and IDA
decompilations, recovers the complete tutorial coordinator. It advances the
prompt transition timer, owns the ten prompt strings and seven bonus-hint
strings, clamps both overlays, and dispatches tutorial stages zero through
seven. The stage logic covers movement and fire input across both player
records, three point-bonus placements, creature-wave progression, perk gating,
and completion of the tutorial timeline.

The bonus-hint handoff is also explicit. A dead inactive carrier with creature
flag `0x400` supplies two signed packed words from its link-index fields. The
function records those as the tutorial bonus id and amount, advances the hint,
and applies the native one-frame negative fade before subsequent frames fade
back in. The corresponding latch is a byte-sized C++ `bool`; its two payload
globals are mapped at `0x004712f4` and `0x004712f8`.

Stage five alternates left and right creature formations, optionally adds a
bonus carrier through wave five, assigns the five packed bonus drops, and adds
the blue spider on wave four. Both formation branches join at the third green
alien spawn exactly as shown by the native CFG. The repeated bonus-pool scans
and player-key bounds retain the native signed pointer comparisons. The three
stage-one point bonuses also preserve the otherwise easy-to-miss reload of
bonus zero's `time_left` into bonuses one and two's `time_max` fields.

The current honest VC6.5 result is 63.71%: 695 target instructions versus 702
candidate instructions, with references `153/0/4`. The stack frame is the
native `0x5c` bytes. Remaining differences are dominated by prompt-alpha CFG
tail sharing, register scheduling after the stage-one point-bonus stores,
reusable vector stack-slot assignment, and switch-case block placement. The
structured source keeps exact runtime behavior; no volatile qualifiers, dummy
references, fake externals, artificial dependencies, inline assembly, or
register constraints are used to hide those residuals.

At entry, native VC6 loads and stores `tutorial_stage_timer` first while
keeping `quest_spawn_timeline` live across construction of the two local text
tables. The compiler schedules these independent compound assignments in
reverse source order, so placing the timeline update first recovers all four
timer references without changing behavior, instruction count, frame size, or
the total similarity score. The three remaining data mismatches are the
already-recovered point-bonus X/Y copies using different value registers; the
fourth is the stage-five local jump table.
