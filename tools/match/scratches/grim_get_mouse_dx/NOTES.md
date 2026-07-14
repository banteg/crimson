# grim_get_mouse_dx

Native target: `grim.dll` at `0x100074d0`.

Live Binary Ninja shows a direct x87 load of `grim_mouse_dx`. The recovered
interface method matches all 2 instructions, full prefix, and references
`1/0/0` with the stock MSVC 6.5 profile.
