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

The indexed child-record form and direct freeze-effect arguments recover the
native copy/register and stack-argument shapes. The honest residual is confined
to the opening register allocation and two recent-death-count reloads that this
typed array candidate coalesces; their absence shifts later branch labels.
MSVC 6.5pp, MSVC 7.0, `/G6`, and volatility experiments diverged elsewhere and
were rejected rather than retained as matching aids.
