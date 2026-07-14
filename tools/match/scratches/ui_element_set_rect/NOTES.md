# ui_element_set_rect

Native target: `crimsonland.exe` at `0x00419ba0..0x00419cfc` (348 bytes).

This is an evidence-backed WIP reconstruction, not an exact match. Microsoft
Visual C++ 6.5 with `/O2 /GB /W3 /GR-` produces 92 normalized instructions
against 91 native instructions, with 43.72% similarity and masked references
`4/0/0`. The same code generation is observed with the available MSVC 6.0,
6.5pp, 6.6, and 7.0 profiles.

## Recovered source shape

- The first argument is the `0xe8` quad payload also accepted by
  `ui_element_load`, not the much larger runtime `ui_element_t` inferred by
  the old decompiler type. Eleven native callers pass menu/sign template
  blocks with this layout.
- Each `0x1c` slot is a transformed vertex: XY position, adjacent Z/RHW
  floats, packed color, and UV. Grouping Z/RHW as a two-float aggregate is
  supported independently by the effect and Grim2D vertex surfaces and
  recovers the native loop's ESI/EDI constant copies.
- The first four positions form a one-pixel-inset rectangle: `(1,1)`,
  `(width-1,1)`, `(width-1,height-1)`, and `(1,height-1)`. UVs apply the same
  one-texel inset using `1/width` and `1/height`.
- All four vertices receive white (`0xffffffff`), `z = 0.5`, and `rhw = 1.0`,
  then the supplied two-float offset is added to every XY position.
- Native x87 stores establish the source assignment order for the bottom
  vertices as slot 3 followed by slot 2. That order keeps the candidate's
  floating-point evaluation and store schedule closest to the executable.

## Remaining mismatch

The residual is compiler allocation rather than behavior. Native VC6 reserves
12 local bytes and gives `1/height` a dedicated stack slot; the candidate
reserves 8 bytes and reuses the dead first-argument home. This shifts the
otherwise corresponding temporary slots. The candidate also schedules one
UV/depth temporary copy differently, leaving one extra normalized instruction.
Natural scalar fields, nested vector fields, direct block access, named and
temporary depth aggregates, alternate vertex orders, an inverse-size vector,
and every available compiler profile were tested. None explains the native
stack-home decision without introducing artificial address-taking or volatile
state.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only arithmetic is used. The scratch remains WIP until the allocator
residual can be explained by plausible source.
