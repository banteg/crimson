# `grim_pixel_format_quantize_color_key`

Native target: `grim.dll` at `0x100173dc` (204 bytes).

This shared ordinary-format vtable method temporarily presents a one-pixel
buffer with the neutral all-`0.5` dither pattern. When needed, it converts the
stored RGBA color key into the format's working space, then writes and reads the
pixel through the format-specific virtual methods so the key is snapped to the
exact representable value. All displaced pixel-buffer and conversion state is
restored before returning.

The policy-valid source produces the same 74 instructions and both native
references. Its remaining 95.95% delta is three instruction placements: the
native schedule preloads `slice_pitch` into ECX and advances one address
calculation across a stack save. VC6 `/O1` CPU, alias, scheduling, and ordinary
local-declaration variants do not reproduce those placements; the scratch does
not use volatility or register constraints to force them.
