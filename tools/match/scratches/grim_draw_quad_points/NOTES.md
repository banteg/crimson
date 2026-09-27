# grim_draw_quad_points

## Plausibility pass (2026-09-27)

The `float point[2]` staging array and its `*(GrimPoint *)` pun became a `GrimPoint` local assigned field by field and copied as a struct. Native's 8-byte stack slot and paired integer copy are unchanged. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Native target: `grim.dll` at `0x10009080` (554 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 130/130
normalized instructions, full prefix, and masked references `59/0/0`.

## Recovered source shape

- Live Binary Ninja disassembly establishes a C++ `__thiscall` member: `this`
  arrives in `ECX`, eight float arguments are removed by `retn 0x20`, and the
  begin/flush paths dispatch through vtable slots `0xe8` and `0xec`.
- One reusable two-float stack temporary receives each explicit X/Y pair. An
  aggregate copy then writes that pair into the current vertex before the
  grouped Z/RHW and UV values and the packed per-corner color.
- Four explicit vertex writes recover the native load/store order and advance
  the global write pointer by four 28-byte vertices.
- The batch counter is maintained through its low 16 bits. The method flushes
  once the zero-extended count reaches the configured capacity.

The recovered method uses ordinary C++ aggregates and the same global vertex
layout independently established by `grim_draw_quad`. No inline assembly,
dummy references, or layout-only branches are used.
