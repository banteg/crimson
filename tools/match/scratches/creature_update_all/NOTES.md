# creature_update_all

Native target: `crimsonland.exe` at `0x00426220` (5,330 bytes).

This is the central 384-slot creature simulation sweep. Live Binary Ninja
disassembly and the Ghidra hotspot recovery establish the complete gameplay
shape: freeze gating, damage-over-time flags, target selection, all nine AI
modes, movement and spawner roots, animation, ranged and contact attacks,
perk interactions, infection, death motion, corpse effects, blood bursts, and
final body culling.

## Binary Ninja control-flow retention

The saved database retained 197 native disassembly basic blocks but had
released LLIL, MLIL, and HLIL for this central simulation sweep. Its name-map
row now requests `never_skip` analysis. Together with the importer's explicit
advanced-analysis retention request, replaying the row restores the complete
creature AI, attack, infection, death, and corpse control flow before applying
the two recovered position cursor types. This is presentation-only recovery:
the matcher remains the honest 49.09% WIP described below.

## Recovered source shape

- The two-player retarget path indexes the other player directly as
  `1 - current_player`. Native `0x00426453..0x004264ae` addresses health
  separately, then forms one pointer to the adjacent `pos_x`/`pos_y` pair;
  the recovered local `alternate_pos` reproduces that shape and the native
  subtract-from-player-two addressing.
- The same block retargets on every update except multiples of 70, prefers the
  other player only while alive and closer, and always switches away from a
  dead current target. The Python runtime already preserved this policy; the
  Zig runtime now carries the native update counter and uses the selected
  player for AI, ranged distance, and contact behavior instead of player zero.
- Native computes both candidate distances with PC=24 `fsub`/`fmul`/`fadd`/
  `fsqrt` and compares the rounded float results at
  `0x0042641b..0x00426499`. Both ports now preserve the resulting strict tie:
  two mathematically distinct distances can round equal, in which case the
  current player remains selected.
- The adjacent auto-target replacement at `0x004264b0..0x00426532` uses the
  same rounded-distance staging. Python now preserves its strict tie as well,
  rather than replacing a slot based on host-double squared distances.
- In two-player mode the new-candidate side of that comparison is the
  `alternate_distance` local computed for `1 - current_player`, even when the
  alternate was farther and the creature did not retarget. The old-target side
  always starts from player zero, and the indexed write occurs before the dead
  current target is redirected at `0x00426544..0x0042655b`. Python bug mode now
  preserves all three pieces of staging on the assigned path; corrected mode
  measures both sides from the final live target. When the opposite player is
  dead, native leaves `alternate_distance` unassigned and consumes stack
  residue. Python explicitly uses a deterministic selected-player fallback for
  that unknowable first-use case rather than inventing native stack contents.
- This reevaluation completes before infection handling and the Evil Eyes
  comparison. Zig now preserves that ordering as well, so an Evil Eyes target
  still switches to a nearer live player before its remaining update is frozen.
- The lifecycle live/dead split also follows reevaluation. Both ports now let a
  creature killed by its periodic self-damage update its multiplayer target
  before corpse decay. Entries already fading at the start of the sweep also
  receive the unconditional dead-player redirect at `0x00426544..0x0042655b`;
  both ports now preserve the dormant player-two target in solo game-over state.
- Once the live arm is selected, native does not re-check lifecycle after the
  Plaguebearer timer or Mr Melee damage call. The current creature still
  completes contact, infection, and the size-30 self-kill tail; Mr Melee also
  does not receive an immediate corpse-decay step. Both ports now preserve this
  in-frame fallthrough.
- The same applies to the 1,000-point dead-link cleanup in tethered and guard
  AI modes: `creature_apply_damage` returns to the middle of the live arm, and
  movement plus the interaction tail still run. Both ports now avoid an
  invented immediate corpse step and loop `continue` there.
- The corpse-keeping death helper itself stores `lifecycle_stage - frame_dt`
  through x87 at `0x0041eb23..0x0041eb2c`. Python now rounds that store at
  PC=24 before later live-tail decrements, avoiding a one-ULP host-double drift.
- Spawn-slot owners tick their linked slot only in the ping-pong movement arm,
  after the owner's clamp/movement and inside the global Freeze gate. The Zig
  runtime now preserves that ordering, so Freeze pauses both the countdown and
  child spawning instead of advancing slots before the creature sweep.
- A fired slot calls `creature_spawn_template` with the native `-100.0f`
  random-heading sentinel, not the owner's heading. The Zig child templates
  now consume that heading roll between the allocation phase-seed draw and the
  template's transient base-heading draw, preserving both heading and RNG order.
- Linked AI modes use their live-link path as the native fallthrough, while
  dead links reset to orbit mode and the tethered variants apply 1,000 damage
  through fresh zero-vector temporaries.
- The phase angle deliberately performs separate `3.7` and pi multiplies,
  matching the two native x87 constants instead of folding them.
- The live-link orbit arm at `0x00426a8a..0x00426abf` keeps
  `orbit_angle + heading` on x87, duplicates it for `fcos`/`fsin`, and rounds
  only the multiply-by-radius and add-linked-position operations at PC=24.
  Python had combined the expression in host double, while Zig rounded the
  trig result before the multiply; both ports now preserve the native staging.
- The target-player distance at `0x00426f65..0x00426f9c` is computed once with
  PC=24 `fsub`/`fmul`/`fadd`/`fsqrt`, stored as a float local, and reused by the
  Radioactive (`100`), ranged (`64`), eat (`20`), and contact (`30`) gates.
  The ports now compare that stored scalar rather than substituting squared
  distance checks, which differ at strict float32 radius boundaries.
- Plaguebearer stores the decremented timer at `0x004265ac`, its `+0.5` wrap at
  `0x004265d0`, and the `-15` HP result at `0x004265df`. Radioactive similarly
  stores its `dt * 1.5` timer subtraction at `0x00426fda` and pulse damage at
  `0x0042702a`. Both ports preserve those PC=24 stores so repeated ticks keep
  the native pulse cadence instead of accumulating host-double residue.
- Infection damage and its lethal side effects complete at
  `0x00426599..0x00426649` before the Evil Eyes target comparison at
  `0x0042665f`. Zig now preserves that order, so Evil Eyes stops the target's
  movement and later interactions without making it immune to Plaguebearer.
- An entry that begins the sweep dead at lifecycle `16.0` is decremented by
  `frame_dt` at `0x004262cf` before periodic poison calls
  `creature_apply_damage`. That callee contributes its separate
  `frame_dt * 15.0` dead-entry decrement, followed by the ordinary
  `frame_dt * 28.0` corpse decay. Both ports now preserve this narrow ordering
  case instead of losing the prologue tick on poisoned corpses.
- Bounded spawner creatures and expired corpses are the native fallthrough
  arms. Reversing those high-level conditions recovers the large middle and
  tail control-flow blocks without layout-only gotos.
- Collision timer updates retain the freshly subtracted value, and heading
  updates add pi to the already-computed target heading. These ordinary local
  value shapes recover native x87 scheduling and constants.
- Damage and corpse-effect vector arguments use natural C++ temporaries bound
  by reference. VC6 therefore constructs the evidenced stack vectors at the
  call sites without fake references or dummy state.
- Live callsite inspection establishes that all five perk gates in this sweep
  call the singleton `perk_count_get` helper: Plaguebearer at `0x00426e00`,
  Radioactive at `0x00426fb7`, Mr Melee at `0x004272a6`, Toxic Avenger at
  `0x00427301`, and Veins of Poison at `0x0042731e`. The helper always reads
  player slot zero. Creature targeting, distance, shielding, contact damage,
  and damage ownership still use the selected player. Both ports now preserve
  that split in bug-compatible mode; corrected mode retains per-target contact
  perks and an any-player Radioactive gate. Plaguebearer was already slot-zero.
- The player table shares the entity prefix already recovered in the source
  header: active byte, phase seed, state and Plaguebearer bytes, collision
  timer, hit-flash timer, reserved/link fields, and AI mode. Applying those
  fields to the live `player_state_t` replaces the remaining
  `_reserved_prefix[9 + player * 0x360]` expression at `0x004273d9` with the
  named `plaguebearer_active` field. Refreshing the table data type is required
  for Binary Ninja to propagate the edited named structure into this existing
  function.
- The creature position cursor is the adjacent `pos_x`/`pos_y` pair and is
  reused through targeting, bounds clamping, movement, spawning, contact, and
  corpse handling. A `vec2f_t` view replaces 40 scalar `pos[0]`/`pos[1]`
  aliases with `x`/`y`; the alternate player position and the two-component
  add helper receive the same type. Binary Ninja now renders the native `edi`
  cursor as `vec2f_t *pos`. The full source rewrite is matcher-neutral at
  1,290 instructions, `49.09%`, and references `207/0/4`.
  The alternate-player branch now takes `player_state_t::position` directly,
  removing its last cast from `pos_x` with identical codegen. The native
  `lea edi, creature_pool[i].position` and branch-local
  `player_state_table[1-current].position` definitions are persisted as
  instruction-scoped `vec2f_t *` views in the replay map.
- The Energizer eat path reverts the just-applied movement with direct position
  subtracts at `0x00427161..0x00427176`; there is no bounds clamp. After its
  direct player-zero XP award and burst/SFX, native pushes `(creature_id, 0)`,
  stores `bonus_spawn_guard = 1` at `0x004271d8`, calls
  `creature_handle_death`, and unconditionally clears the guard at
  `0x004271e7`. The disassembly contains no intervening creature-owner store.
  Python and Zig preserve the off-world position, stale owner, and literal
  guard reset, with regression fixtures initialized to expose all three.
- `creature_handle_death(creature_id, 0)` returns at `0x004271e4`; native clears
  the guard and falls through rather than jumping to the loop tail. Contact is
  suppressed while Energizer is active, but the unconditional size-30 cleanup
  can still zero HP and decrement lifecycle on the now-inactive slot. Both ports
  now preserve that stale-slot write.

## Remaining mismatch

The complete natural reconstruction is an honest 49.09% WIP: 1,290 candidate
instructions against 1,338 native instructions, with masked references
`207/0/4`. The adjacent-position pointer removes two candidate instructions,
aligns one additional reference, and eliminates the player-two `pos_x`
reference mismatch. The residual is dominated by global register allocation:
native keeps the creature index in a scaled form and spills health, lifecycle,
and collision pointers into a `0x7c` frame, while VC6 coalesces the same source
values into a byte offset and a `0x60` frame. That changes repeated SIB
addressing, x87 cleanup, and alignment through the melee block. The four
remaining audit entries are sequence-alignment artifacts over otherwise
evidenced player coordinates, constants, and perk calls; there are no
unresolved references. No volatile state, dead expression, inline assembly,
register constraint, fake alias, or artificial stack padding is used.

## Position type recovery

The active creature position is now represented by one `vec2f_t *` cursor
through particle, projectile, effect, and panned-audio calls. This removes the
parallel raw-float alias and makes the aggregate boundary explicit without
changing the honest 49.09% WIP score, 1,290/1,338 instructions, or `207/0/4`
reference audit.

## Target-player type recovery

Native consistently loads `creature_t::target_player` with `movsx`, including
the initial multiplayer distance calculation and the later AI, ranged, and
contact paths. The canonical field is therefore an explicitly signed byte,
not an unsigned byte repeatedly reinterpreted through `(char)` casts. Recovering
that type removes seven scalar sign casts and the raw interior `char *` view;
the latter is now a direct `signed char *` to the named field. This source-shape
cleanup is matcher-neutral at 49.09%, 1,290/1,338 instructions, and `207/0/4`
references. The adjacent reset loop remains 99.02%, 307/307 instructions, and
`213/0/0` references.

## Creature aggregate recovery

The canonical `0x98`-byte creature now exposes the native aggregates used
throughout game code: position at `+0x14`, velocity at `+0x1c`, RGBA tint at
`+0x3c`, navigation target at `+0x50`, and linked-target offset at `+0x7c`.
Anonymous scalar aliases preserve all arithmetic-heavy access. Position,
velocity, tint, targeting, damage, spawn, death, perk, and render consumers can
now pass or copy named aggregates without first-float pointer casts. The live
Binary Ninja layout carries the same five types, and the full match/status pass
is required to keep every affected exact or WIP consumer honest.

Every direct player-position access in the sweep now also uses
`player_state_t::position`. This completes the aggregate boundary already
established for the active creature cursor and alternate-player value without
mislabeling either interior pointer. A whole-function shadow compile is
byte-neutral at 1,290/1,338 instructions, 49.09%, and `207/0/4` references.

The two linked-target AI arms now read the canonical
`creature_t::target_offset` components directly. This is byte-neutral at the
same 1,290/1,338 instructions, 49.09%, and `207/0/4` references. Applying the
same spelling-only cleanup to the navigation-target or velocity components
regresses the body to 48.78% and `203/0/4`: VC6 changes its alias/lifetime
choices even though the offsets are identical. Those arithmetic-heavy fields
therefore retain their scalar aliases here as an evidenced compiler-shape
constraint rather than forcing a prettier aggregate view.

## Compiler profile and opening-region probe

A fresh compiler/flags matrix finds no override above the canonical
49.0868%, 1,290/1,338-instruction, `207/0/4` result. VC6.0, VC6.5, and VC6.6
emit that same body under `/O2 /GB`; `/G5`, `/TP`, and `/GX` are byte-neutral.
The Processor Pack falls to 43.8189% and VC7 to 37.2594%, while the tested
`/G6`, `/O1`, and `/Oy-` variants do not improve the baseline.

The first native region keeps the creature index in a 19-unit scaled form and
uses it through `*8` SIB operands, while the candidate shifts that value into
a byte offset. Narrowing the source loop-index lifetime by declaring it in the
`for` initializer was tested against this exact region; VC6 emitted an
identical `0x60` frame and identical whole-function metrics. The native
`0x7c` frame and scaled-index allocation therefore remain a compiler residual,
not a missing loop operation.

## Recovery classification

The scratch is `semantic-complete` with a `compiler` residual. A
fresh live Binary Ninja check retains the full 5,330-byte function and the
recovered plague, spawn-slot, ranged/contact, Energizer, infection, death, and
corpse paths; the matcher still reports 1,290/1,338 instructions and
`207/0/4` references. Auditing each of those four aligned instructions against
the native disassembly confirms they are all downstream sequence-alignment
artifacts: zero versus `1000.0f`, player health versus the later shield timer,
the preceding panned-SFX call versus the Mr Melee perk query, and Toxic Avenger
versus the following Veins of Poison query. All referenced native objects are
present at their separately aligned callsites, so none is independent
reference debt; the visible mismatches remain unaliased.

## Infection collision-timer shape sweep

A fresh live Binary Ninja read from target
`3023:2:9499448411019345244` bounds the first infection timer block to native
`0x00426599..0x004265d0`. Native subtracts `frame_dt`, stores the result to
`collision_timer` with `fst` while retaining it on the x87 stack, compares that
same result with zero, and, on the negative branch, stores the retained value
plus `0.5f`. The current local-first source expresses exactly that data flow.

The schema-1 spec `collision-timer-shape-mutations.json` records five natural
spellings of that one block. Spec SHA-256 is
`f2d2faac8442a4b5f085f09edffb0b4cfa6992b4a202a5c04a1efc77e46277c8`;
the tested source SHA-256 is
`0928e121f84ed1937daeb86a57b9b0383bd0d3b2e35e395e4a491ce4bfe2eec3`.
The recorded sweep evaluated all 5/5 possible one-site variants without
truncation. The pointer-local spelling was byte-neutral at the 49.0868%
baseline, 1,290/1,338 instructions, and `207/0/4` references. The other four
spellings regressed by 0.3044 to 0.7426 percentage points and lost four to
seven aligned references. No single mutation improved, so no interaction
sweep was warranted and the native-grounded current source is retained.

## Target-distance product-order sweep

A final live Binary Ninja pass against target
`3023:2:9499448411019345244` identifies the first tractable expression-level
divergence after the known frame/index-allocation residual in the multiplayer
target-selection block. At native `0x0042641b..0x00426532`, the distance
calculations load `dx` and then `dy`, duplicate and multiply the `dx` value
first, and only then form the `dy` product. The canonical VC6 body presents
the equivalent x87 product schedule in the opposite order. The live disassembly
export SHA-256 is
`bc6ae07b525b4cfbee2fc6e70c5e168d73bb523750df40498f6304fc20b4ce97`;
the live HLIL export SHA-256 is
`1b1717b7d69680babfbd7e7dbff7e76f35a830b4c70d168222e20a5eb7728254`.

The schema-1 spec `target-distance-product-order-mutations.json` reverses the
two mathematically equivalent square addends independently in the current
player, alternate player, solo fallback, and auto-target comparisons. Spec
SHA-256 is
`5eee4eb403d9cbc0f68929c976749d9b3417c51333f15c5ca2efe0b1ad97ed23`;
the retained canonical source SHA-256 is
`0928e121f84ed1937daeb86a57b9b0383bd0d3b2e35e395e4a491ce4bfe2eec3`.
The recorded sweep exhausts all 15/15 non-empty combinations through four
simultaneous changes. Every single-site and interaction variant is byte-neutral
at 49.0868%, 1,290/1,338 instructions, `207/0/4` references, and 2,616.3242
weighted bytes. VC6 therefore canonicalizes these equivalent source spellings
before the observed x87 scheduling decision. No source change is retained.

## Native frame and target-player lifetime closure

A final live pass used the explicit `crimsonland.exe.bndb` target
`3023:2:9499448411019345244`. Native opens with a `0x7c` stack frame, retains
the creature index in 19-unit form for `*8` addressing, and materializes
separate health, lifecycle, collision, position, cooldown, and target-player
pointers. The canonical VC6 body opens with a `0x60` frame and converts the
index to a 152-byte offset. A stock-compiler matrix rules out a profile
explanation: VC6.0, VC6.5, and VC6.6 are identical under `/O2 /GB`, while
`/G5`, `/Ob1`, and `/Ot` are byte-neutral. `/G6` falls to
2,584.857251617815 weighted bytes (48.4964%, 1,289 instructions,
`ok=205/mismatch=4/unresolved=0`), and `/Oy-` falls to
2,554.675275351311 weighted bytes (47.9301%, 1,295 instructions,
`ok=207/mismatch=2/unresolved=0`).

Native-looking source lifetimes do not recover the allocation. A whole-slot
reference loses 44.619482496195 weighted bytes, ending at
2,571.704718417047 (48.2496%, 1,290 instructions,
`ok=204/mismatch=5/unresolved=0`). Hoisting the phase, AI, target-distance,
movement, animation, and corpse scalars is byte-neutral, as is naming the
AI-kind-7 frame delta.

Native reloads the target-player byte in the contact path at `0x0042721a`,
`0x004272db`, `0x0042733a`, `0x0042734b`, `0x00427380`, and `0x004273cd`.
The schema-1 spec `contact-target-player-reload-mutations.json` tests direct
reloads at the shield, damage, knockback, and infection sites. Spec SHA-256 is
`caab2e3593c5ebaa15b8b40ac43fd2c94a98968d74105b432a805374a56eb74f`.
All 15/15 non-empty combinations were evaluated. Infection alone is
byte-neutral because VC6 already reloads it. Every other combination changes
the wider register allocation and regresses: damage alone loses
505.473380615646 weighted bytes, knockback alone loses 523.264840182648,
shield alone loses 560.699200913242, and all four lose 569.442071635675.
A separate, semantics-preserving split between the initial selection byte and
the post-retarget byte similarly loses 478.656141665236 weighted bytes, ending
at 2,137.668059248006 (40.1063%, 1,295 instructions,
`ok=163/mismatch=6/unresolved=0`).

No source or compiler configuration change is retained. The canonical source
SHA-256 remains
`0928e121f84ed1937daeb86a57b9b0383bd0d3b2e35e395e4a491ce4bfe2eec3`,
with 2,616.324200913242 weighted bytes out of 5,330 (49.086757990868%),
1,290/1,338 instructions, zero prefix instructions, and
`ok=207/mismatch=4/unresolved=0`.

## Blood-splatter loop control-flow sweep

A new bounded tail audit covers native `0x00427575..0x0042762f`, where the
three corpse blood-splatter loops load `EBX` with 8, 6, and 5 and use the same
`call; dec ebx; jne` do/while shape. The candidate already has the same
counter register, trip counts, call order, and decrement branches. Its only
local differences are the established stack-frame displacement
(`[esp+0x2c]` versus native `[esp+0x38]`) and downstream labels caused by the
whole-function `0x60` versus `0x7c` frame allocation.

The schema-1 spec `blood-loop-counter-shape-mutations.json` has SHA-256
`809f2283bd26c8a130610a170cf9bc8de2144e01fdd84f39904050658f530407`.
Its recorded sweep exhausts all 26/26 one-, two-, and three-loop combinations
of equivalent `for` and prechecked `while` spellings, with no truncation.
Every single-site variant and every interaction produces the same regression:
16.225266362253 fewer weighted bytes, 49.086758% to 48.782344%, and four fewer
aligned references, while retaining 1,290 candidate instructions. This
confirms the current do/while source is the native-supported control-flow
shape and that rewriting the loops cannot recover the enclosing frame slots.

No `creature_update_all` source change is retained. Its canonical source
SHA-256 and metrics remain
`0928e121f84ed1937daeb86a57b9b0383bd0d3b2e35e395e4a491ce4bfe2eec3`,
2,616.324200913242/5,330 (49.086757990868%), 1,290/1,338 instructions,
zero prefix instructions, and `207/0/4` references.

## Corpse-queue argument-lifetime sweep

Live Binary Ninja target `3023:2:9499448411019345244` bounds the corpse queue
to native `0x0042748f..0x0042756a`. The native arms intentionally differ:
ping-pong, non-long-strip creatures enqueue effect 7, while the ordinary arm
enqueues the creature type. Both form the same centered position temporary and
join at the `fx_queue_add_rotated` call at `0x00427558`.

The schema-1 spec `corpse-queue-argument-lifetime-mutations.json` has SHA-256
`6f3dd90288214ac2fd030a15979ed6fef7f2bfa1e5159a298d9ea6b8f0cf8b15`.
It exhausts all 15/15 single-arm variants and cross-arm interactions for
field aliases, half-size staging, and named position temporaries. The winning
asymmetric interaction stages the effect-7 half-size while naming the ordinary
arm's type, size, and heading values. That is consistent with the native
right-to-left argument preparation and retains identical gameplay semantics.

The first-stage winner improves the whole body by 148.878989364009 weighted
bytes, from 2,616.324200913242/5,330 (49.086757990868%) to
2,765.203190277251/5,330 (51.879984808204%). The gap falls from
2,713.675799086758 to 2,564.796809722750 bytes, candidate instructions move
from 1,290 to 1,295 against 1,338 native, and the reference audit improves
from `207/0/4` to `217/0/3`.

The gain is a compiler-lifetime cascade rather than a falsely claimed local
exact match. Native `0x0042684c..0x00426a85` improves from 160.03125 weighted
bytes (28.125%, `11/0/1` references) to 284.5 (50.0%, `20/0/0`), and
`0x0042731d..0x004273df` gains 17.798165137615 weighted bytes. The enclosing
queue region `0x004273d3..0x0042757d` itself loses 8.644273685179 weighted
bytes while gaining one aligned reference. The change is retained because the
dominant native-aligned lifetime and reference improvements are explicit and
the source introduces no volatile state, dead work, fake aliases, or semantic
change.

The follow-up `corpse-type-arm-alias-subset-mutations.json` (SHA-256
`54065ab70ef20acdcb3203f9e2ec6f796725bcc1064e5e6eee02dd4a696edfe1`)
exhausts seven proper subsets of the ordinary arm's type, size, and heading
aliases while holding the effect-7 half-size staging fixed. Dropping only the
type-id alias gains another 25.351520968950 weighted bytes and removes one
candidate instruction. Every subset missing size or heading instead loses
131.603798411040 to 163.028285334285 weighted bytes and up to ten aligned
references, confirming that the paired float lifetimes are the operative
source shape.

The final result is 2,790.554711246200/5,330 (52.355623100304%), a
2,539.445288753800-byte gap and a total improvement of 174.230510332958
weighted bytes over the original 49.086758% baseline. It has 1,294/1,338
instructions, zero prefix instructions, and `217/0/3` references. The retained
source SHA-256 is
`a76c476f0c412e182f0fcc7d4d8aea08e7db1d49fe8887b6c707c2ada9d62a72`.

## Tethered-link distance-lifetime closure

The improved `0x0042684c..0x00426a85` alignment still differs in the live
tethered-link distance kernel: native retains both target deltas on x87, while
the candidate spills one delta. Two recorded specs close the ordinary
source-shape search around that exact expression.

`tethered-target-distance-lifetime-mutations.json` (SHA-256
`e1fd2a91b49f0b9445f1a81854e4e2b5c27a8619045d70a34b3e98a77473a862`)
tests four scoped, direct, vector, and assignment-in-condition forms. Scoped
delta scalars are byte-identical. The vector local loses
129.555639954425 weighted bytes and nine aligned references, while the direct
field expression loses 146.744572205876 weighted bytes, fourteen aligned
references, and adds one instruction. The assignment-in-condition spelling is
not accepted by this VC6 compile.

`tethered-target-product-order-mutations.json` (SHA-256
`6bb81aebaafef0471f34cfacdfa22a891d8167e54c5247c7b2539bca5da49989`)
records the remaining commuted product order; it is byte-identical. The
current `dx` plus named Y-delta source is retained, and the residual spill is
classified as backend lifetime scheduling rather than incomplete recovery.

## Spawn-slot aggregate, branch polarity, and animation factor order

Live Binary Ninja target `3023:2:9499448411019345244` bounds a fresh coherent
region from the ping-pong movement tail through animation advancement. Native
`0x00426cfd..0x00426d51` materializes the linked spawn-slot aggregate once,
updates its timer, loads count and limit, and branches with
`cmp edx,eax; jle` at `0x00426d38..0x00426d3d`.

The schema-1 spec `movement-spawn-slot-lifetime-mutations.json` has SHA-256
`5f162660d3f774ab293bd280a9a2a8207ea9c59365a0a1837f183803f27c7ba2`
and exhausts all 87/87 one- and two-site variants. All four natural pointer or
reference aliases for the repeated spawn-slot fields compile identically and
gain 89.103343465046 weighted bytes. The retained pointer spelling is the
simplest representation of the native aggregate lifetime. It moves the result
from 2,790.554711246200/5,330 (52.355623100304%) to
2,879.658054711246/5,330 (54.027355623100%), drops the gap from
2,539.445288753800 to 2,450.341945288754 bytes, and improves references from
`217/0/3` to `225/0/2` without changing the 1,294 candidate instructions.
The movement turn-rate and velocity factor-order variants are byte-neutral or
reduce that aggregate gain, so no movement spelling change is retained.

The follow-up `spawn-slot-branch-schedule-mutations.json` has SHA-256
`9514634c2a444ee5c60f8beee1f6807a6327317283493e5e2acbab441a5027eb`
and exhausts all 14/14 variants. Expressing the semantic condition as
`spawn_limit > spawn_count` gains another 4.050151975684 weighted bytes and
produces the native `cmp edx,eax; jle` polarity. Its negated equivalent is
byte-identical; the direct comparison is retained. Four natural count-store
and template-load schedules are all byte-neutral, leaving their residual
instruction ordering classified as backend scheduling.

Native animation arms at `0x00426e57..0x00426e77` and
`0x00426ed5..0x00426ef5` keep `anim_scale` on x87 while computing
`anim_rate * move_speed * frame_dt`, then merge them with `fmulp`. The
schema-1 `animation-factor-order-mutations.json` (SHA-256
`2e1c90f5f5f80708af37f59d3af83e535ccd584e45c56e180eb23793034a9af1`)
exhausts all 24/24 single-arm spellings and two-arm interactions. Every
natural grouped spelling gains 4.050151975684 bytes per arm; retaining
`anim_scale * (anim_rate * move_speed * frame_dt)` in both arms gains
8.100303951368 total and makes the local normalized x87 order match through
`fmul frame_dt; fmulp; fmul move_scale`.

The final result is 2,891.808510638298/5,330 (54.255319148936%), a
2,438.191489361702-byte gap and a total improvement of 101.253799392098
weighted bytes over this wave's 52.355623100304% baseline. Candidate
instructions remain 1,294/1,338, the prefix remains zero, and references are
`225/0/2`. The retained source SHA-256 is
`6418804572316ca99c8d7928d0b3f2810e32d89468ac7b982f80372db2bff5b2`.

## Interaction-distance and phase-setup saturation

Two fresh native-bounded sweeps test the highest-value unsaturated lifetimes
left outside the already-covered corpse queue, tethered link, movement/spawn,
and animation regions. Native `0x00426f65` computes the interaction distance
from the creature/player deltas. The schema-1
`interaction-distance-lifetime-mutations.json` plan has SHA-256
`92fd3bc86bca531c086c5fba198561e39b209a026e96308822987f685889d75f`
and evaluates all 7/7 scoped, product-order, direct-field, and named-copy
spellings. Five variants compile byte-identically. The direct-field form loses
8.100303951368 weighted bytes, and copying the X delta loses
16.200607902736; neither changes instruction or reference counts.

Native `0x0042664b..0x00426679` establishes the phase seed, forced target, and
movement scale. The schema-1 `phase-setup-schedule-mutations.json` plan has
SHA-256
`75510e34b3e745eac0e9ba70b5509cdbe9d490ad9744b34ec3bf4a5eb85b7573`
and evaluates all 6/6 ordinary statement schedules. Every variant compiles
byte-identically to the retained source.

Neither sweep has a winner, so the canonical source and metrics remain
unchanged. Together these results close the strongest remaining local
lifetime hypotheses in those two regions and leave the larger `0x7c` native
versus `0x6c` candidate frame allocation and scaled-index scheduling as
compiler/TU constraints rather than justification for another ordering-only
rewrite.

## SDK vector-expression style

The 2003 mod SDK provides direct source evidence for the original vector
idiom: `vec2_t::operator-` returns a temporary and `VEC2_Length(vec2_t &)`
accepts that result as a non-const reference. Its implementation computes a
reciprocal square root and returns the reciprocal, while optimized VC6 emits
the native inline `fsqrt` sequence.

Replaying that exact `VEC2_Length(player.position - creature.position)`
boundary for the first, long-lived current-player distance improves the
candidate from 2,891.808510638298/5,330 (54.255319148936%) to
2,908.743833017078/5,330 (54.573055028463%), a gain of
16.935322378789 weighted bytes. Candidate instructions move from 1,294 to
1,297 against 1,338 native instructions; references remain `225/0/2`.

The same boundary was tested independently at the alternate-player, solo
fallback, auto-target, forced-target, tethered-target, and later interaction
distance sites. Every additional application regressed alignment and several
lost resolved references, so only the first site is retained. This confirms a
specific native temporary-lifetime boundary rather than a type-wide rewrite.
