# player_apply_move_with_spawn_avoidance

The recovered C++ source matches all 131 native instructions and all eight
masked references with the global `msvc6.5 /O2 /GB` profile.

The match establishes these source-shape details:

- the function returns integer zero rather than `void`;
- the player table is indexed from its true record base, with `size` at
  `player_state_t+0x34`;
- movement is damped in place when Alternate Weapon is active, then applied
  before collision resolution;
- the native loop scans the fixed 32-entry spawn-slot pool and skips empty
  owner pointers;
- separation calculations reuse a local `vec2f_t`, which accounts for the
  eight-byte stack frame and the observed x87 spills;
- an overlap first rolls back both axes. If the old position is still inside
  the reduced combined radius, the full move is restored; otherwise the code
  retries X alone and then Y alone with strict native boundary directions.

Recovering the fixed slot scan also exposed a port bug: the Python runtime had
an unbounded append-only list, while Zig had a 384-entry monotonic pool. Both
ports now use the native 32-slot first-free allocator, overwrite the final slot
on exhaustion, and release owner pointers through the native death path.

The exact helper's Alternate Weapon query calls `perk_count_get`, so it reads
player slot 0 even while moving another indexed player. Preserve mode now uses
that slot-zero perk source in both ports; corrected mode remains per-player.
