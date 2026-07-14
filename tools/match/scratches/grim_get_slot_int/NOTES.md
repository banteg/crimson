# grim_get_slot_int

Native target: `grim.dll` at `0x100072d0..0x100072de` (14 bytes).

Live Binary Ninja shows an unchecked indexed load from `grim_slot_ints`.
Natural C++ reproduces all three VC6.5 instructions exactly. No shaping
constructs are used.
