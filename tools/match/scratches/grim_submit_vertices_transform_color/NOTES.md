# grim_submit_vertices_transform_color

## Plausibility pass (2026-09-27)

The split `double`/`float` temporaries became the same `grim_rotate_point` and `grim_translate_point` helpers as the plain transform submitter, and the countdown became an indexed loop. The color is stored through a named `unsigned long *vertex`. That local shifts the helpers' inline-copy ids by one, which gives native's `y*m1 + x*m0` operand order (x87 sort keys compare ids mod 8, see [x87-scheduling.md](../../c2/compiler/x87-scheduling.md)). The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Native target: `grim.dll` at `0x100084e0` (218 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 72/72
normalized instructions, full prefix, and masked references `10/0/0`.

## Recovered source shape

- A render-disabled guard encloses the copy, transform loop, count update, and
  capacity check.
- `memcpy` copies `count * 0x1c` bytes into the current batch. Positive counts
  enter the seven-dword-stride matrix and offset loop.
- Scalar rotation accumulators recover the native x87 order for both output
  coordinates before the supplied XY translation is applied.
- Dword field 4 is overwritten through an integer pointer with one packed
  color. This corrects the earlier float-pointer prototype without relying on
  a bit-preserving float faketype.
- Static callers span both UI and effect rendering, while the checked-in UI
  trace records 7,202 transform-color submissions.
- The low-word batch count and capacity-triggered virtual flush match the
  other three recovered submitters.

No inline assembly, dummy references, or layout-only branches are used.

## 1.9.8 code-generation guard

1.9.8 recompiled this object with C2 9044. Its rotation keeps the same source,
but the x87 operand sort keys come from inline-copy ids, and the named
`unsigned long *vertex` local that 1.9.93 (8966) needs shifts them the wrong
way under 9044. Writing the color through a cast of `grim_vertex_write_ptr`
is exact under 9044 and 97.22% under 8966; the named local is the reverse.

Shared spellings searched without success: the color store through the named
local, a direct cast, `*(unsigned long *)&grim_vertex_write_ptr[4]`, a
`packed` color local with or without the vertex local, the vertex local
declared before the loop, `i` declared before the loop, a `point` local passed
to either helper, split or reordered rotation temporaries, and direct
`point[n] += offset[n]` translation. The guard keeps only the color store
different.
