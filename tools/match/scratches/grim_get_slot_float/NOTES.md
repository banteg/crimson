# grim_get_slot_float

Native target: `grim.dll` at `0x100072c0..0x100072ce` (14 bytes).

Live Binary Ninja shows an unchecked indexed load from `grim_slot_floats`.
Natural C++ reproduces the three VC6.5 instructions exactly, including the
x87 float return. No shaping constructs are used.
