# grim_begin_batch

Native target: `grim.dll` at `0x10007ac0` (94 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 27/27
normalized instructions, full prefix, and masked references `9/0/0`.

## Recovered source shape

- Rendering-disabled and already-active batches return immediately. Otherwise
  the active flag is set before device readiness is checked.
- A ready device begins a D3D8 scene and locks the dynamic vertex buffer with
  `D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK`.
- A failed lock clears the device-ready byte. The low 16 bits of the vertex
  count are reset after either lock result; they are not reset when the device
  was already unavailable.
- The D3D8 calls use their ordinary COM interfaces. The shared compatibility
  header only supplies two Win32 aliases absent from the bundled VC6 SDK.

No inline assembly, dummy references, or layout-only branches are used.
