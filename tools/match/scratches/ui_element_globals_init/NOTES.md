# `ui_element_globals_init`

Native target: `crimsonland.exe` at `0x004177f0` (662 bytes).

The CRT initializer constructs 41 contiguous menu/UI element objects followed
by the standalone perk-prompt element. The first two parent constructors are
inlined: each runs a two-entry no-op constructor over its hover bounds, seeds
the three 0xe8-byte template blocks, and clears the callback, active, and tail
state. VC6 then calls the recovered parent constructor for the remaining 39
menu objects and the perk prompt.

The final 8-byte stack temporary is the zero-valued vector assigned to the
global camera-shake offset. Modeling that value as a two-float object recovers
the native frame, store schedule, and copy without volatile data or artificial
dependencies. The result matches all 135 instructions and all 121 static
references exactly.
