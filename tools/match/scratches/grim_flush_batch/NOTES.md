# grim_flush_batch

Native target: `grim.dll` at `0x100083c0` (107 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 37/37
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- Rendering-disabled and inactive batches return immediately. Otherwise the
  current vertex buffer is unlocked and its low-word count is submitted as an
  indexed D3D8 triangle list, including the zero-count case.
- The vertex buffer is immediately relocked with
  `D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK` so batching can continue in the same
  scene.
- Only a successful relock resets the low 16 bits of the count. Lock failure
  leaves both the count and batch-active state unchanged.

No inline assembly, dummy references, or layout-only branches are used.
