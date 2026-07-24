# creature_update_all

Native target: `crimsonland.exe` at `0x00426220` (5,330 bytes).

This is the central 384-slot creature simulation sweep. Live Binary Ninja
disassembly and the Ghidra hotspot recovery establish the complete gameplay
shape: freeze gating, damage-over-time flags, target selection, all nine AI
modes, movement and spawner roots, animation, ranged and contact attacks,
perk interactions, infection, death motion, corpse effects, blood bursts, and
final body culling.

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
