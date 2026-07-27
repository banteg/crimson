# ui_element_layout_calc

Native target: `crimsonland.exe` at `0x0044fb50` (288 bytes).

The routine skips dedicated element slots 26 and 27. For all other elements it
translates the four interaction-bound floats, then derives a tightened hit box
from vertices zero and two: the leading edge is inset by 54% horizontally and
28% vertically, while the trailing edge is inset by 5% and 10%.

When `direction_flag` is set, it walks the active vertex count in pairs and
swaps their U coordinates. The recovered 28-byte vertex layout is
`x, y, z, rhw, color, u, v`; eight vertices fill the element's former opaque
`+0x3c..+0x11b` region, and the count follows at `+0x120`.

The scratch now consumes the authoritative `ui_element_t` layout directly.
Named `pos`, hover-bound, vertex, `vertex_count`, and `direction_flag` fields
replace the former 0x318-byte shadow record and its three opaque padding
regions. This agrees with Binary Ninja's live type at every accessed offset,
including the 0x1c-stride `ui_element_vertex_t` records.

Keeping ordinary two-float reference views for the vector operators improves
the exact prefix from 16 to 34 instructions without changing the 86-instruction
body or its six resolved references. Snapshotting `direction_flag` after the
trailing-bound aggregate copy also recovers the native early byte load and
raises the score from 95.35% to 96.51%.

Live disassembly then showed that native retains the complete leading position
before beginning the width subtraction. The recorded
`hitbox-scheduling-mutations.json` sweep tested both hit-box aggregates and
found one improving ordinary lifetime: naming `position + vertex_0`, computing
the width, and only then publishing the aggregate. The retained form raises
the score to **97.67%** and cuts the fuzzy gap from 10.05 to 6.70 bytes while
keeping 86/86 instructions and `6/0/0` references.

`hitbox-store-order-mutations.json` subsequently evaluated all 19 single and
pair component-store refinements. Every one regressed sharply, generally
disturbing the vector helper lowering from the start of the function. The two
remaining differences are therefore left as honest store/load scheduling
choices without volatile state or artificial dependencies.

## Recovery classification audit

A fresh focused `--regions` run after the retained mutation reports **97.67%**,
86/86 instructions, prefix 32, and `6/0/0` references. Its remaining regions
contain only the documented aggregate-store and direction-load scheduling
differences; all bounds translations, inset constants, skip cases, direction
handling, vertex count, and U-coordinate swaps agree with the native routine.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Exact-tail audit (2026-07-27)

Live Binary Ninja reconfirmed both remaining regions as aggregate-store,
direction-load, and x87 scheduling only. MSVC 6.0, 6.5, and 6.6 reproduce the
same **97.67%** result; Processor Pack falls to 80.00%, and VC7 does not
compile this source. The bounded flag matrix likewise found no exact profile.

`aggregate-lifetime-mutations.json` evaluated five default-constructor and
predeclared-minimum combinations. The three compile-valid forms are
byte-identical; the two partial forms correctly fail because they omit the
required default constructor. The recorded `predeclared-minimum-confirmation`
probe is neutral at 86/86 instructions and `6/0/0` references. No canonical
source change was retained; baseline and final remain **97.67%**, prefix 32.

## Native-scheduled residual matrix (2026-07-27)

Fresh live Binary Ninja evidence localized the residual to exactly two
instruction-order differences. In the leading-bound sequence, native publishes
`hover_min.x` before completing the adjacent x87 store while the candidate
delays that integer copy. In the trailing-bound sequence, native loads
`direction_flag` before the adjacent x87 store while the candidate delays the
byte load. The calculations, constants, fields, references, and control flow
remain identical.

Four recorded, non-truncated mutation sweeps tested 111 native-grounded
variants:

- `assignment-helper-mutations.json`: 4/4 explicit assignment-operator forms
  regressed sharply by changing helper lowering from the function prologue.
- `residual-lifetime-mutations.json`: 63/63 width, height, publication, and
  direction-snapshot lifetime combinations were neutral or worse.
- `explicit-native-vector-mutations.json`: 35/35 native-ordered aggregate and
  component-store forms were neutral or worse; component stores disturbed
  alias-driven lowering from the start of the function.
- `vector-type-shape-mutations.json`: 9/9 class, constructor, copy, return,
  inline, and inherited-vector shapes were byte-identical to the baseline.

No source mutation was retained. The final result remains **97.67%**
(`281.3023/288` weighted bytes, 6.6977-byte gap), 86/86 instructions, prefix
32, and `6/0/0` references. The recorded negative evidence strengthens the
existing `RECOVERY=semantic-complete`, `RESIDUAL=compiler` classification.
