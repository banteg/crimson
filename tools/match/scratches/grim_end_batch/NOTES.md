# grim_end_batch

Native target: `grim.dll` at `0x10007b20` (104 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 36/36
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- Rendering-disabled and inactive batches return immediately. An active batch
  unlocks the vertex buffer before checking device readiness.
- If the device is unavailable after unlock, the method returns without ending
  the scene or clearing the active flag, matching the native failure path.
- A nonzero low-word vertex count is submitted as indexed D3D8 triangle-list
  geometry with `count / 2` primitives. Zero vertices skip only the draw.
- The normal path ends the D3D8 scene and clears the active byte.

No inline assembly, dummy references, or layout-only branches are used.
