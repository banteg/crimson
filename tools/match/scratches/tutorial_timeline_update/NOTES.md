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
back in. The Python port previously selected the fade direction from the newly
set latch and therefore faded upward one frame too early; it now selects the
direction from the entry latch and has a regression for the negative handoff
frame. The corresponding latch is a byte-sized C++ `bool`; its two payload
globals are mapped at `0x004712f4` and `0x004712f8`.

Stage one does not call `bonus_spawn_at`. At `0x00408e26..0x00408f0c` it
overwrites bonus slots 0, 1, and 2 directly with Points amounts 500, 1000, and
500; each slot gets both timer fields set to `100.0f`, state byte zero, and its
fixed position before a 12-particle `effect_spawn_burst` call. The second and
third max-timer stores deliberately reload slot zero's 100-second timer. Both
ports previously reused the ordinary constructor and therefore assigned only
10 seconds. They now expose a fixed-slot tutorial seed operation, preserve the
100-second lifetime and overwrite policy, and retain only the native 12-particle
burst.

Stage five alternates left and right creature formations, optionally adds a
bonus carrier through wave five, assigns the five packed bonus drops, and adds
the blue spider on wave four. Both formation branches join at the third green
alien spawn exactly as shown by the native CFG. The repeated bonus-pool scans
and player-key bounds retain the native signed pointer comparisons. The three
stage-one point bonuses also preserve the otherwise easy-to-miss reload of
bonus zero's `time_left` into bonuses one and two's `time_max` fields.

The current honest VC6.5 result is 64.60%: 695 target instructions versus 692
candidate instructions, with references `153/0/4`. The stack frame is the
native `0x5c` bytes. Remaining differences are dominated by prompt-alpha
default-store placement, register scheduling after the stage-one point-bonus
stores, reusable vector stack-slot assignment, and switch-case block placement. The
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

The neutral prompt-transition state (`-1`) uses alpha `1.0` directly in the
native CFG, while positive and earlier negative transitions scale milliseconds
by `0.001`. Initializing the source value to `1.0` and overriding it only for
those timer arms removes the candidate's artificial `1000.0 * 0.001`
conversion, drops one instruction, and raises the score from `63.71%` to
`63.75%`. VC6 still sinks the native default store later than the candidate;
forcing that final placement would require source-level control-flow steering.

The global carrier handle at `0x004808ac` is now persisted as `creature_t *`.
That type is proven by the two assignments from `creature_spawn_template` and
the subsequent active, health, flags, and packed link-index accesses. Applying
it removes all raw `+0x24`, `+0x78`, `+0x7a`, and `+0x8c` expressions from this
native function.

Stages two, five, and seven now express their 16-slot bonus-pool emptiness test
as an indexed loop. VC6 strength-reduces the typed index into the native
record pointer while retaining the count in a separate register, reproducing
all three native scan CFGs. The former hand-written pointer loop hoisted slot
zero out of each loop and emitted nine extra instructions overall; replacing
it raises the honest total from 63.75% to 64.60% while preserving behavior,
the native frame, and the reference audit.
