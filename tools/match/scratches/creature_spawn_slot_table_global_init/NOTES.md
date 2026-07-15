# `creature_spawn_slot_table_global_init`

Native target: `crimsonland.exe` at `0x00412260` (45 bytes).

The CRT initializer constructs all 32 creature-spawn slots. It clears the
owner and current count, sets both the interval and countdown timer to 0.5
seconds, and uses `-1` for the unlimited spawn-count sentinel. The template id
is already zeroed by the PE BSS and is left untouched.
