# `grim_pixel_format_read_ar16`

Native target: `grim.dll` at `0x1001a348` (224 bytes).

This 64-bit AR16 vtable reader expands packed A16B16G16R16 words through
`1/65535` into RGBA floats and applies the active color key to the completed
row. The source's ordinary 64-bit right shift produces the native MSVC
`__aullshr` helper call for the first extracted component.
