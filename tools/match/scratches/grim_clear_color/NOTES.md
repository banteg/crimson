# grim_clear_color

`grim_clear_color` is the vtable slot `0x2c` method at `0x10006cb0`. It exits
without touching the device while rendering is disabled or the device is not
ready. Otherwise it calls `IDirect3DDevice8::Clear` for
`D3DCLEAR_TARGET`, with no rectangles, depth `0.0f`, and stencil `0`.

The native channel conversion and pack order is exactly the Direct3D8
`D3DCOLOR_COLORVALUE(r, g, b, a)` macro. VC6 evaluates the expression as four
x87 multiply-by-255 conversions in `r`, `a`, `g`, `b` order and assembles the
result as `AARRGGBB`; no manual bit-expression or clamp is needed.

The recovered method matches all 45 native instructions and all 11 references
under MSVC 6.5 `/O2 /GB`.
