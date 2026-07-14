# grim_get_mouse_dy_indexed

Native target: `grim.dll` at `0x10007500`.

The index parameter is intentionally unused. Live Binary Ninja shows
`ECX=this`, a virtual call through slot `0x74`, and `retn 4`; natural C++
`return grim_get_mouse_dy();` matches all 3 instructions and full prefix.
