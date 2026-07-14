# grim_get_mouse_dx_indexed

Native target: `grim.dll` at `0x100074f0`.

The index parameter is intentionally unused. Live Binary Ninja shows
`ECX=this`, a virtual call through slot `0x70`, and `retn 4`; natural C++
`return grim_get_mouse_dx();` matches all 3 instructions and full prefix.
