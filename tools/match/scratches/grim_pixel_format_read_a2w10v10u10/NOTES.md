# `grim_pixel_format_read_a2w10v10u10`

Native target: `grim.dll` at `0x1001a0eb` (211 bytes).

This A2W10V10U10 vtable reader sign-extends and normalizes three packed 10-bit
vector components through `1/512`, expands the unsigned 2-bit alpha through
`1/3`, and applies the active color key to the completed row.

MSVC 7.0 reproduces all 70 instructions and all four references, including the
compiler's signed-`fild` plus `2^32` correction for the unsigned alpha value.
VC6.5 processor-pack preserves the same component logic but chooses a qword
`fild` conversion instead (80%), so the compiler profile is evidence-driven.
