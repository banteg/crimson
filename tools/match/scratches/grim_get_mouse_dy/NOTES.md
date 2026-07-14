# grim_get_mouse_dy

Native target: `grim.dll` at `0x100074e0`.

Live Binary Ninja shows a direct x87 load of `grim_mouse_dy`. The recovered
interface method matches all 2 instructions, full prefix, and references
`1/0/0` with the stock MSVC 6.5 profile.
