# `ui_menu_assets_init`

Native target: `crimsonland.exe` at `0x00419dd0` (551 bytes).

Live Binary Ninja evidence recovers the three JAZ resources and placements,
the 0xe8-byte template copy topology, slot duplication, UV bands, vertical
offsets, and the eight-slot horizontal translation. Modeling the translation as
the inlined C++ `vec2 += (-84, 0)` operation reproduces the native loop,
including its otherwise-surprising `y` self-copy.

The six contiguous 0xe8-byte subtemplates are modeled as one array view, and
the slot type retains the empty user-defined constructor established by
`ui_menu_template_pool_init`. That ordinary object model prevents VC6 from
hoisting the first `-100` calculation across the block-01-to-block-02 copy.
The candidate now aligns all 110 normalized instructions with a 110-instruction
prefix and scores 100.00%.

This remains an honest WIP because two static references still differ
(`refs=64/0/2`). For the first two `+124` adjustments, native reloads copied
destination slots 4 and 5 (`0x0048fdec`, `0x0048fe08`), while VC6 propagates
the equal source values from slots 3 and 2 (`0x0048fdd0`, `0x0048fdb4`). The
full-vector `+= (0, 124)` spelling forces the native references but emits eight
non-native x self-copies; `memmove` forces the references but emits calls.
Neither is retained, and no volatile or artificial dependency is used.

An address-level audit confirms that every other masked reference resolves.
The two differing loads are the compiler's equal-value propagation described
above, not wrong globals or record offsets, so recovery is classified
`semantic-complete` with a `compiler` residual. MSVC 6.5 `/GX` and `/Ob1`
variants are byte-identical; MSVC 6.5pp, `/Oy-`, `/G6`, `/O1`, and MSVC 7.0
profiles all regress the instruction match without resolving the pair.

## Bounded residual audit (2026-07-27)

The two mismatches are now pinned to native instructions 67 and 70, at
`0x00419f1c` and `0x00419f2e`. Native loads copied destinations
`0x0048fdec` and `0x0048fe08`; the candidate loads the equal source fields at
`0x0048fdd0` and `0x0048fdb4`. The surrounding instructions and all 64 other
masked references agree.

`alias_lifetime_mutations.json` tests six natural spellings around only the two
copies and adjustments:

- destination references created before and after the copy, destination
  pointers, and a base-slot pointer all compile identically to the baseline;
- interleaving each copy with its adjustment and mutating the assignment-result
  lvalue both regress to 97.27%, move the first mismatch to instruction 63, and
  increase reference mismatches from two to five.

The complete sweep is recorded in `experiments.jsonl`; it has four neutral and
two degrading variants, with no improving winner. Reproduce it with:

```sh
uv run crimson match mutate tools/match/scratches/ui_menu_assets_init \
  --spec tools/match/scratches/ui_menu_assets_init/alias_lifetime_mutations.json \
  --max-variants 6 --jobs 6
```

A five-profile matrix closes the remaining installed compiler gap. VC6 builds
8168 (`msvc6.0`), 8966 (`msvc6.5`), and 9782 (`msvc6.6`) all produce the same
110-instruction, `refs=64/0/2` result. The Processor Pack and VC7 regress.
In particular, build 9782 is the exact compiler family supported by the EXE's
Rich records, so the residual is not explained by having tested only the
default 8966 backend. Further work needs a different recovered type/TU
constraint or the missing historical source context, not another generic flag
or alias sweep.

## Address-neighbor TU audit (2026-07-28)

The native address island immediately around this function is:

- `ui_element_set_rect` at `0x00419ba0`, exact at 91/91 instructions and
  `refs=6/0/0`;
- `ui_element_load` at `0x00419d00`, exact at 67/67 instructions and
  `refs=10/0/0`;
- `ui_menu_assets_init` at `0x00419dd0`;
- the exact `j___cfltcvt_init_3` / `__cfltcvt_init_3` initializer pair at
  `0x0041a000` / `0x0041a010`;
- `ui_cursor_render` at `0x0041a040`, on the far side of that initializer pair
  and still a WIP.

Two reproducible source probes test the useful parts of the neighbor
hypothesis. `probe_shared_ui_quad.cpp` applies the nested depth/UV
`vec2`/vertex/quad shape recovered from exact `ui_element_set_rect` to this
function while retaining the empty constructors required by the native copy
schedule. It is byte-for-byte neutral: 110/110 instructions and
`refs=64/0/2`.

`probe_neighbor_translation_unit.cpp` compiles the exact predecessor island as
one object in native address order. It deliberately keeps each function's
independently recovered local types so the test isolates translation-unit
presence instead of changing source shape. Rechecking every symbol from that
object gives:

- `ui_element_set_rect`: 91/91, `refs=6/0/0`;
- `ui_element_load`: 67/67, `refs=10/0/0`;
- `ui_menu_assets_init`: 110/110, `refs=64/0/2`.

The shared type and exact-neighbor co-compilation hypotheses are therefore
falsified for the two destination-load references: neither changes VC6's
equal-value propagation, while both exact neighbors remain exact in the
combined object. The initializer pair is a natural stopping boundary, so the
non-exact `ui_cursor_render` was not mixed into the controlled probe. Do not
promote this island to a modeled TU cluster yet; it would preserve the same
two-reference audit residual without adding exact coverage.

Reproduce the target probes with:

```sh
.venv/bin/crimson match probe \
  tools/match/scratches/ui_menu_assets_init \
  --source tools/match/scratches/ui_menu_assets_init/probe_shared_ui_quad.cpp
.venv/bin/crimson match probe \
  tools/match/scratches/ui_menu_assets_init \
  --source tools/match/scratches/ui_menu_assets_init/probe_neighbor_translation_unit.cpp
```

The probe results, including source hashes, are recorded in
`experiments.jsonl`. A future exit now needs a source-level constraint that
changes the two copied-slot loads without regressing the surrounding 110
instructions; mere address adjacency, a shared layout, or another compiler
profile is not evidence for one.

## Copy and helper-boundary experiments

Two final mutation menus test whether the missing constraint lives in an
implicit special member or a tiny vertical-offset helper:

- `copy-assignment-type-mutations.json` evaluates eleven `vec2` and vertex
  copy-assignment definitions and interactions. Every user-defined assignment
  destroys the native `rep movsd` copy shape, falling to 44.01--47.58% with
  159--176 candidate instructions and at least five reference mismatches.
  Implicit assignment is therefore required.
- `vertical-offset-helper-mutations.json` evaluates two natural `add_y`
  signatures and their call interactions. Definitions alone and both valid
  calls are byte-for-byte neutral at 110/110 instructions and audit `64/0/2`;
  the call without a definition correctly fails to compile.

These results bound the unresolved equal-value propagation across both
implicit assignment and method boundaries without weakening the exact
instruction match. Recorded spec SHAs:
`eff1958c90910624530b41deddd0415f953fc272bb98223a3250b5d34a4f95e1`
and
`f91146bee0d22e3a2148c1d076c15007fb6744be4e8d452a3f52beb5df65fdd4`.
