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
flag `0x400` supplies the signed `bonus_id` and `duration_override` halfwords
from its canonical `creature_t::bonus_args` overlay. The function records
those as the tutorial bonus id and amount, advances the hint, and applies the
native one-frame negative fade before subsequent frames fade back in. The
Python port previously selected the fade direction from the newly set latch
and therefore faded upward one frame too early; it now selects the direction
from the entry latch and has a regression for the negative handoff frame. The
corresponding latch is a byte-sized C++ `bool`; its two payload globals are
mapped at `0x004712f4` and `0x004712f8`.

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

The current honest VC6.5 result is 66.57%: 695 target instructions versus 693
candidate instructions, with references `154/0/4`. The stack frame remains the
native `0x5c` bytes. Remaining differences are dominated by prompt-alpha block
placement, register scheduling after the stage-one point-bonus stores, branch
stack-slot coalescing, and switch-case block placement. The structured source
keeps exact runtime behavior; no volatile qualifiers, dummy references, fake
externals, artificial dependencies, inline assembly, or register constraints
are used to hide those residuals.

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
by `0.001`. Giving all three branches their value directly removes the
unsupported eager `1.0` store from the candidate. Keeping the negative cases
together is the best honest expression found: a positive-first equivalent
regressed to 64.46%, while this form raises the prior 64.60% baseline to
65.71%. VC6 still places the native positive fallthrough differently; forcing
that final block order would require source-level control-flow steering.

The creature-spawn workspace has separate source lifetimes in stages three,
four, five, and six. Naming a local vector in each branch lets VC6 coalesce
those non-overlapping values while retaining the native frame, and raises the
result again from 65.71% to 66.57% with one additional aligned reference.
Keeping a single function-wide vector obscured those lifetimes; a function-wide
three-vector array forced 8-byte stack alignment and an EBP frame, while three
function-wide vector locals enlarged the frame to `0x64`. Both alternatives
were rejected.

The global carrier handle at `0x004808ac` is now persisted as `creature_t *`.
That type is proven by the two assignments from `creature_spawn_template` and
the subsequent active, health, flags, and packed bonus-argument accesses.
Applying it removes all raw `+0x24`, `+0x78`, `+0x7a`, and `+0x8c`
expressions from this native function. The matching source now uses the same
canonical bonus-argument union instead of recreating its two signed halfwords
at every read and write.

Binary Ninja initially chose the union's ordinary `link_index` arm and rendered
the two packed values as anonymous halfword slices. The tutorial-specific
global therefore uses a `tutorial_bonus_carrier_binja_t *` presentation type.
That view retains the proven active, health, and flags offsets while naming
both reads and later writes as `bonus_args.bonus_id` and
`bonus_args.duration_override`; ordinary creature links keep their canonical
`link_index` interpretation elsewhere.

Stages two, five, and seven now express their 16-slot bonus-pool emptiness test
as an indexed loop. VC6 strength-reduces the typed index into the native
record pointer while retaining the count in a separate register, reproducing
all three native scan CFGs. The former hand-written pointer loop hoisted slot
zero out of each loop and emitted nine extra instructions overall; replacing
it raises the honest total from 63.75% to 64.60% while preserving behavior,
the native frame, and the reference audit.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja evidence retains every stage, prompt,
fixed-slot bonus, bonus-carrier handoff, spawn formation, and completion
transition. IDA and Ghidra independently report the same five-callee surface.
The candidate remains within two instructions of native at 693/695 with the
exact `0x5c` frame and `154/0/4` references; bounded mismatches are branch
placement for the prompt transition and VC6 register, stack-slot, jump-table,
and scheduling choices rather than missing behavior. The three fixed-slot
bonus anchors and the compiler-local stage jump table stay visible and
unaliased; their surrounding native operations are all present, so they do not
represent separate source-reference debt.

## Stage-one movement-key cursor sweep

A fresh region pass selected the stage-one input loop at
`0x00408d6b..0x00408de6`. Native VC6 keeps `esi` at
`player_state_table[0].input.move_key_backward`, reads the four movement keys
as `esi[-1]`, `esi[0]`, `esi[1]`, and `esi[2]`, advances the cursor by the
`0x360`-byte `player_state_t` stride, and compares it directly with the same
field in the past-end player record. The current whole-player source pointer
lets VC6 use the same interior cursor for the calls, but its source-level
whole-record bound introduces one address correction before the loop-back
comparison.

The tracked schema-1 menu tested a literal backward-key cursor, an equivalent
forward-key cursor, and a whole-player cursor with a matching-field bound. Both
field-cursor variants compiled byte-identically and decisively regressed the
whole function from `1935.207493/2907` weighted bytes at `66.570605%` to
`1880.753602/2907` at `64.697406%`. They kept 693 instructions but changed the
reference audit from `154/0/4` to `152/0/5`. VC6 rejected the matching-field
bound spelling. With no positive single there is no justified interaction
sweep, and `scratch.cpp` remains unchanged: the native interior register is
compiler allocation evidence, not enough evidence for a stronger original
source-lifetime claim. The complete three-variant result is recorded in
`experiments.jsonl`.

## Follow-up stage-five stopping audit

After the HUD and Quest priority passes reached stopping points, a bounded
live Binary Ninja audit revisited the largest tutorial mismatch region at
`0x00409171..0x0040934f`. Native retains both alternating left/right
formations, the repeat-count-gated bonus carrier, all three creature
placements, the blue-spider wave, and the five-way bonus ID/duration switch.
Those operations and branches are already present in `scratch.cpp`; the
remaining region difference is block placement, jump-table layout, and
scheduling. No new source discrepancy or honest mutation site was found, so
the scratch remains unchanged at `1935.207492795389/2907` weighted bytes
(`66.57060518731989%`), gap `971.792507204611`, 693/695 instructions, prefix
6, and `154/0/4` references.
