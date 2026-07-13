# grim_set_rotation

Native target: `grim.dll` at `0x10007f30` (85 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 19/19
normalized instructions, full prefix, and masked references `11/0/0`.

## Recovered source shape

- The input radians are stored, then offset by the native `0.7853982f`
  constant before ordinary `cos` and `sin` calls are narrowed to float.
- Seven scalar globals hold the input angle, cosine, sine, and row-major matrix
  `{cos, sin, -sin, cos}`.
- Writing the matrix in source order `m00`, `m01`, `m10`, `m11` naturally gives
  the native VC6 x87 schedule and EAX/EDX allocation.
- Live Binary Ninja confirms `this` in `ECX`, one stack argument, and
  `retn 0x4`. The checked-in UI trace contains 53,352 calls, and the EXE has 65
  static calls across 17 functions.

No inline assembly, volatile state, dummy references, or layout-only
expressions are used.
