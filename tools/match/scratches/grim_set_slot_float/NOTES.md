# grim_set_slot_float

Native target: `grim.dll` at `0x100072e0..0x100072f2` (18 bytes).

Live Binary Ninja shows an unchecked indexed store to `grim_slot_floats`.
Natural C++ reproduces all four VC6.5 instructions exactly, including the x87
load/store sequence. No shaping constructs are used.
