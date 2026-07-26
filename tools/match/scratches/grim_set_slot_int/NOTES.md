# grim_set_slot_int

Native target: `grim.dll` at `0x10007300..0x10007312` (18 bytes).

Live Binary Ninja shows an unchecked indexed store to `grim_slot_ints`.
Natural C++ reproduces all four VC6.5 instructions exactly. No shaping
constructs are used.
