# grim_submit_vertices_transform

## Plausibility pass (2026-09-27)

The split `double` multiply-accumulate temporaries became two inline helpers, `grim_rotate_point` (compute x, store y, store x) and `grim_translate_point`. Each takes `grim_vertex_write_ptr` as its argument, which explains native's pointer reloads: one per helper and one for the stride. The countdown became an indexed loop. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Native target: `grim.dll` at `0x100085c0` (192 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 64/64
normalized instructions, full prefix, and masked references `9/0/0`.

## Recovered source shape

- A render-disabled guard encloses the entire copy, transform, count update,
  and capacity check.
- `memcpy` copies `count * 0x1c` bytes into the current batch. Only positive
  counts enter the seven-dword-stride adjustment loop.
- Scalar rotation accumulators recover the native x87 sequence for
  `x' = y*m[1] + x*m[0]` and `y' = y*m[3] + x*m[2]`; the results are then
  translated by the supplied XY offset.
- The global write pointer advances once per transformed vertex. The method
  finally updates the low 16 bits of the batch count and flushes through the
  virtual `0xec` slot when capacity is reached.
- The checked-in UI trace records 13,940 transform submissions, making this a
  high-coverage native path rather than an unused wrapper.

No inline assembly, dummy references, or layout-only branches are used.

## 1.9.8 code-generation guard

1.9.8 loads the second rotation product as `fld [matrix+8]; fmul [point]`
and the x translation as `fld [point]; fadd [offset]`, the reverse of
1.9.93. Unlike the color submitter, 8966 and 9044 compile every tried
spelling of this function to the same code, so no shared spelling can give
both images: the x87 operand order follows the inline-copy ids alone. With
`grim_rotate_point(matrix, point)` and a translate helper that adds the
offsets directly, both compilers are exact on 1.9.8.

Shared spellings searched without success: translate written directly,
with only an x or y local, with both locals first, as `a = a + b` either
way round, or with swapped helper parameters; rotation with a y temporary,
a renamed or predeclared x, operands swapped in the source, point or matrix
aliased through a local, or reordered stores; `i` declared before the loop
or outside the guard; a named vertex local, a byte-count local or a
`count16` pointer; and one helper doing both rotation and translation, in
all six parameter orders. Any extra used local moves other operand pairs.
