# grim_set_color_ptr

Native target: `grim.dll` at `0x10008040` (104 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 25/25
normalized instructions, full prefix, and masked references `12/0/0`.

## Recovered source shape

- The vtable slot and `retn 0x4` establish a C++ `__thiscall` member taking one
  pointer to four RGBA floats. The body does not otherwise read `this`.
- A four-byte union represents the packed color. Float channels are multiplied
  by 255 and converted directly into its alpha, red, green, and blue bytes;
  this method performs no clamping.
- VC6 keeps the input pointer in `ESI` and reuses its now-dead parameter home as
  storage for the four-byte local. That register allocation explains the
  native byte stores without any source-level argument aliasing.
- The packed value is first stored in color slot 0, then propagated to slots 1
  through 3 with the same chained assignment recovered in `grim_set_color`.

No inline assembly, dummy references, or layout-only branches are used.
