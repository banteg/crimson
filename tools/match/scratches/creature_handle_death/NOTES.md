# `creature_handle_death`

Native target: `crimsonland.exe` at `0x0041e910` (834 bytes).

Work in progress: 84.73% normalized match, 5/204-instruction exact prefix,
202/204 candidate instructions, and 80/0/1 reference audit.

Binary Ninja and the MSVC candidate establish:

- bonus-on-death arguments are the two signed halfwords packed in `link_index`,
  and both bonus spawning and recent-death tracking run before the active guard;
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
native copy/register and stack-argument shapes. The honest residual is confined
to the opening register allocation and two recent-death-count reloads that this
typed array candidate coalesces; their absence shifts later branch labels.
MSVC 6.5pp, MSVC 7.0, `/G6`, and volatility experiments diverged elsewhere and
were rejected rather than retained as matching aids.

The XP path is also unambiguously player-zero-owned. This function receives no
owner argument, and both Bloody Mess / Quick Learner tests plus both ordinary
and Double Experience stores address `player_state_table[0]` directly at
`0x0041eb43..0x0041ebb0`. Python and Zig now retain that source and destination
in bug-preserving mode; corrected mode deliberately keeps last-hit-owner XP.
