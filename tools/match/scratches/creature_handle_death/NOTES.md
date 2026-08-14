# `creature_handle_death`

Native target: `crimsonland.exe` at `0x0041e910` (834 bytes).

Current honest VC6.5 result: 89.49% normalized match, 6/204-instruction exact
prefix, 205/204 candidate instructions, and 85/0/0 reference audit.

Binary Ninja and the MSVC candidate establish:

- bonus-on-death arguments use the canonical `creature_t::bonus_args` union
  member: signed `bonus_id` and `duration_override` halfwords overlay
  `link_index`, and both bonus spawning and recent-death tracking run before
  the active guard;
- the overloaded `0x04` flag clears the linked spawn-slot owner;
- split-on-death allocates and copies two complete creature records, consumes a
  second phase-seed draw for each child, writes unwrapped `heading +/- pi/2`,
  leaves `target_heading` copied from the parent, and applies the native f32
  health/reward/size/speed/damage mutations;
- corpse policy precedes an XP award which is repeated while Double Experience
  is active, followed by the ordinary bonus-drop gate;
- Freeze emits eight shards and one shatter, then performs the native
  freeze-only kill-count increment, deactivation, and random queued effect.

The forced bonus call at `0x0041e930..0x0041e943` passes
`&creature->pos_x`, not a position copy. Its sole callee clamps that storage
before checking Rush mode and emits a dedicated 16-particle burst before the
ordinary random-drop gate. The Python port already preserved the visible
clamp and burst; its RNG tags are now the four native callsites. Zig now also
mutates the corpse position, bypasses `bonus_spawn_at_pos` spacing policy,
emits the forced burst, and feeds the clamped position to subsequent random
drop and Freeze effects.

Zig now also runs the complete native death prelude at every modeled entry:
forced bonus/clamp first, then recent-death history, then the active guard and
ordinary death body. This includes the inactive secondary-detonation re-entry
and the no-corpse projectile path; the latter intentionally retains native
active-corpse re-entry instead of adding an HP guard. Production deaths now
populate the three stored survival positions, advance the capped six-death
counter, and clear the two reward gates when the counter reaches three.

The indexed child-record form and direct freeze-effect arguments recover the
native copy/register and stack-argument shapes. Reading the opening flags
through `creature_pool[creature_id]` before binding the record pointer is also
intentional: native IL keeps the flags access as an indexed pool expression
while later fields use the recovered record pointer. This natural split raises
the normalized score from 84.73% to 87.96%, moves the exact prefix from 5 to 6
instructions, adds one candidate instruction, and clears the reference audit
from 80/0/1 to 82/0/0.

The authenticated target-era `game_t` layout proves that the three recent-death
positions and their count are adjacent members of the gameplay-state owner.
Restoring that ownership recovers both native count reloads and three additional
resolved references. The honest residual is now one opening compiler choice:
the candidate common-subexpressions the byte-scaled creature offset with `shl`,
where native retains the element index for two scaled memory operands. That one
extra instruction shifts all later branch labels.
MSVC 6.5pp, MSVC 7.0, `/G6`, and volatility experiments diverged elsewhere and
were rejected rather than retained as matching aids.

The recent-death write uses the canonical `vec2f_t` component names through the
shared gameplay-state aggregate. VC6 now emits the native mutable count reload
for each component and the increment.

An address-keyed Binary Ninja local type now preserves the `creature_t *`
induction result at `0x0041e91d`. The native death body consequently renders
named position, flags, size, and reward members through the scaled pool
expression instead of raw `+0x14`, `+0x8c`, `+0x34`, and `+0x64` offsets.

The XP path is also unambiguously player-zero-owned. This function receives no
owner argument, and both Bloody Mess / Quick Learner tests plus both ordinary
and Double Experience stores address `player_state_table[0]` directly at
`0x0041eb43..0x0041ebb0`. Python and Zig now retain that source and destination
in bug-preserving mode; corrected mode deliberately keeps last-hit-owner XP.

## Recovery classification and reference re-audit

The preceding native recovery accounts for every guard, call, RNG draw,
constant, record mutation, XP branch, and effect path. The focused mismatch
region reduces to the opening indexed-address common-subexpression.

Native stores centroid X to `survival_recent_death_pos` at `0x0041e958` and Y
to `survival_recent_death_pos+4` at `0x0041e968`, with a count reload between
them. The retained aggregate source gives the matcher enough ownership and
aligned context to pair all three accesses correctly, so the current reference
audit is clean at `85/0/0`.

Classification remains `RECOVERY=semantic-complete`,
`RESIDUAL=compiler`.

## Recorded mutation searches

`recent-death-index-lifetime-mutations.json` records four natural forms around
the two stored Survival coordinates. Named and separately scoped indices plus
aggregate assignment are byte-neutral. A named destination pointer restores
the 204-instruction count and an `81/0/0` reference audit, but worsens the
normalized score to 84.31%, so it is not retained over the direct indexed
source shown by native HLIL.

The new bounded searches record:

- 89 opening/call/recent-death lifetime variants in
  `opening-and-recent-death-mutations.json`; declaration, pointer, argument
  staging, and aggregate-copy forms were neutral, while pointer forms that
  force reloads regressed;
- three storage-layout variants in
  `recent-death-storage-layout-mutations.json`; against the retained opening
  source, modeling the adjacent 24-byte position array and count as one
  aggregate gains 12.72 weighted bytes, restores both count reloads, and adds
  three resolved references with no tradeoff. The shared full `game_t` owner is
  byte-identical to that focused aggregate and is retained;
- 24 inline-context variants in `opening-inline-context-mutations.json`; the
  direct pool flag read was the sole winner, adding 26.95 weighted bytes and
  clearing the audit;
- 14 post-retention combinations in
  `retained-opening-followup-mutations.json`; pointer/declaration ordering and
  aggregate position copying were neutral, while the reload-restoring pointer
  form lost 3.59 weighted bytes.

The two pre-retention opening specs intentionally preserve the source spans
used for their recorded historical sweeps. The post-retention spec is the
current reusable scaffold.

Four follow-up opening-address and direct-index owner searches confirm the
remaining boundary. Directly indexing all fields regresses to 72.82% and 208
instructions; moving or rebinding the record pointer after the bonus or
recent-death preludes also regresses. A C++ reference is byte-identical to the
retained pointer. No register coercion or artificial lifetime is kept.
