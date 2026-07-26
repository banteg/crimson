# grim_set_color

Native target: `grim.dll` at `0x10007f90` (166 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 42/42
normalized instructions, full prefix, and masked references `16/0/0`.

## Recovered source shape

- The vtable slot and `retn 0x10` establish a C++ `__thiscall` member with four
  float arguments. The body does not otherwise need to read `this`.
- Alpha alone is clamped to `[0, 1]`. RGB values are converted directly after
  multiplication by 255, matching the native x87 comparisons and four `_ftol`
  calls.
- The converted low bytes are packed as ARGB. The resulting value is first
  stored in color slot 0, then propagated to slots 1 through 3 with a chained
  assignment; this recovers the native store order exactly.
- The four packed slots are the same contiguous array consumed by the exact
  quad renderer reconstructions.

No inline assembly, dummy references, or layout-only branches are used.
