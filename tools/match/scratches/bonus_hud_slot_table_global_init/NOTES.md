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

The two otherwise anonymous scalar members are write-only in the native
program: one is initialized to `1.0f`, the other to `5.0f`, and neither has a
runtime read. They are therefore named conservatively as `unused_one` and
`unused_five` rather than assigning unsupported gameplay semantics.
