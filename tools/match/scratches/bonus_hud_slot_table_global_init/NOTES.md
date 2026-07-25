# `bonus_hud_slot_table_global_init`

Native target: `crimsonland.exe` at `0x0041a7d0` (56 bytes).

Defining the 16-entry global C++ array makes VC6 emit the native inlined
default-constructor loop. Each slot starts inactive at x = 0 with the label
`"Empty"`, icon 1, scalar fields 1 and 5; the timer pointers retain their
static null initialization. The compiler-generated `_$E1` helper matches all
13 instructions and both static references exactly.

The constructor view now derives from the canonical `bonus_hud_slot_t` instead
of duplicating its active byte, padding, and slide block. This preserves the
original C++ construction boundary and remains exact at 13/13 instructions
with both references.
