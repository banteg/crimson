# grim_bind_texture

Native target: `grim.dll` at `0x10007830` (58 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 20/20
normalized instructions, full prefix, and masked references `3/0/0`.

## Recovered source shape

- Negative handles return before indexing the texture-slot table.
- Null slots and null `+4` texture pointers also return without mutating D3D
  state or the current bound-handle global.
- A valid slot calls `IDirect3DDevice8::SetTexture(stage, texture)` through
  D3D8 vtable offset `0xf4`, then records the handle as currently bound.
- The slot uses the canonical recovered `GrimTexture` layout. Its leading
  dword is the texture name pointer, followed by the observed D3D texture
  pointer; ownership, dimensions, and backup-surface fields are recovered by
  the related texture lifecycle functions.
- The checked-in UI trace contains 44,536 binds, and the EXE has 66 static
  callsites across 22 functions.

No inline assembly, dummy references, or layout-only branches are used.
