# `mods_menu_update`

Native target: `crimsonland.exe` at `0x0040e9a0` (2,607 bytes, 648
normalized instructions).

Live Binary Ninja disassembly and decompilation recover the complete native
Mods browser callback:

- a refresh-gated `mods\*.dll` enumeration with 31 usable rows and the native
  `+ more` sentinel in slot 31;
- parallel filename, display-name, and scrollbar-label tables;
- the selected plugin's title, version, author, filename, and API
  compatibility panel;
- launch gating on API version 3, plugin loading, and transition to the plugin
  runtime state;
- transposition of both players' eleven input bindings into the mod API key
  configuration, plus the pick-perk and reload bindings; and
- Main Menu behavior, which rearms the DLL scan.

The reconstructed source preserves the native two-stage vector expression.
Writing `position = position + offset` exposes the VC6 return temporary seen
in the opening x87 sequence. Keeping the three table accesses directly indexed
also reproduces the native enumeration loop. The scrollbar item count is
evaluated before the renderer used for the scrollbar-label color is captured.
VC6 then batches the aggregate stores, matching the native loads at
`0x0040ec6e..0x0040ec74` and the renderer's use at `0x0040ecbc`.

Current MSVC 6.5 `/O2 /GB` result:

```txt
match=94.44% prefix=0/648 target_insns=648 candidate_insns=648 refs=184/0/0
first_target=sub esp, 0x144
first_candidate=sub esp, 0x160
```

Recovery is semantic-complete. The remaining differences are compiler lifetime
and scheduling residue. Native and candidate both overlap ended `_finddata_t`
metadata storage with later locals, but choose different storage offsets; the
native function also reuses its opening vector-return slot for `button_origin`.
The natural candidate retains a frame 28 bytes larger. Recovering the nested
measure/draw expressions and direct filename indexing closes the remaining
semantic scheduling clusters without manufacturing local layout. The source
deliberately does not use unions, volatile state, dead expressions, forced
addresses, inline assembly, or fake aliases to manufacture native local layout.

The function-local scrollbar, Main Menu button, Launch button, shared
constructor guard, and all three `atexit` cleanup thunks are mapped. Each
cleanup thunk is separately verified as the native one-byte `ret` function.

## Scrollbar column-initialization sweep (2026-07-26)

Live Binary Ninja localized one compact constructor mismatch at native
`0x0040ec34..0x0040ec61`. The native static-scrollbar guard zeroes
`column_offsets[0]` before `column_offsets[1]`, using a freshly cleared `ecx`;
the current object at function-relative `0x294..0x2bf` emits the two stores in
the opposite order and reuses the already-zero `edi`. This is downstream of
the documented frame-size divergence and independent of the previously
improved renderer capture.

The recorded one-site sweep in
`scrollbar-column-init-mutations.json` tested five ordinary C++ spellings:
separate integer and floating-point stores, both reverse-chain constant types,
and a zero-then-copy form. MSVC 6.5 canonicalized every single to the same
matcher result as the baseline: **83.53%**, 645 candidate instructions, prefix
0, `168/0/0` references, and exactly zero weighted-score delta. There were no
positive singles, so no interaction was eligible. The complete sweep is
recorded in `experiments.jsonl`; no source variant was applied.

## Render-pair lifetime and profile wave (2026-07-27)

The live Binary Ninja target
`3023:2:9499448411019345244` and function bundle SHA-256
`5dd60c0305a41f8147a0d9753ad0fd8c20347b7fc6605c86d571c25dd5234aef`
show two adjacent per-pair renderer lifetimes that were imprecise in the
source. For the selected mod's numeric version, native loads the Grim object
at `0x0040ee17`, captures its virtual-call state at `0x0040ee27`, measures at
`0x0040ee40`, and draws at `0x0040ee5c`. The `"version"` column label repeats
the same pair at `0x0040ef0a`, `0x0040ef1a`, `0x0040ef2e`, and
`0x0040ef4b`. Both pairs keep one interface value across their measure and
draw calls.

`render-pair-interface-lifetime-mutations.json` exhaustively evaluated all
15 nonempty combinations across the version value, version label, author,
and filename pairs. Capturing the interface only for the first two pairs is
the clean winner:

```txt
83.5266821% -> 85.2281516%
weighted 2177.540603/2607 -> 2221.897912/2607
gap 429.459397 -> 385.102088 bytes
instructions 645/648 -> 645/648
references 168/0/0 -> 169/0/0
```

The gain is 44.357309 weighted bytes, or 1.701469 percentage points, without
unresolved or mismatched references. The author-only capture regresses by
4.032483 bytes, and every filename-capture combination regresses sharply.
Only the two native-supported pair captures are retained. The spec SHA-256 is
`80265c35e5450db967867297a3613d369eaacde435e069f8cf1fb1442f8dd065`.

The other complete recorded sweeps bound the adjacent alternatives:

- `right-aligned-text-schedule-mutations.json` evaluated all 80 possible
  one- through four-site variants. Naming the four right edges before the
  width calls regresses. Its only fuzzy-positive single names the author
  pointer, but introduces one reference mismatch. Spec SHA-256 is
  `8c08117328266c8d6ca89f79402e26541a8454b907f4e3dadb5350258c2d30d2`.
- `author-pointer-shape-mutations.json` evaluated five ordinary pointer
  spellings before and after the retained pair captures. All ten evaluations
  compile identically: the improved baseline gains 7.480864 weighted bytes
  but changes the author cluster to `168/0/1`. Native keeps the interface
  vtable in `esi` through this region, while that candidate assigns `esi` to
  the author pointer. The source remains unchanged to preserve the clean
  reference schedule. Spec SHA-256 is
  `4be622383ba85e3b7b095b403a89c3145c311102625ab87fc6339e7258dc2bd4`.
- `author-pair-lifetime-combined-mutations.json` evaluated pointer-only,
  renderer-only, and combined forms from the improved source. Renderer-only
  loses 4.032483 bytes; the combined form loses 66.885528 bytes and still has
  a mismatch. Spec SHA-256 is
  `9abf23320be91e48b020e1df470f641927e55096497c067421d608335cca4c0c`.

Together with the earlier five-variant scrollbar sweep, the six-record
`experiments.jsonl` contains 113/113 evaluated variants, no truncation, and
SHA-256
`cd01ed0666435921b0cd1aa4dc4b929ae38e1f8b50361e220a4e5e7fe7c02eba`.

A separate 30-cell profile matrix covered MSVC 6.5 and 6.6 across 15 flag
sets. `/O2 /GB`, `/O2 /G5`, `/O2` without an explicit CPU switch, `/Ob1`,
`/Ob2`, `/Ot`, and `/Zp8` tie the canonical score on both compilers. Explicit
decomposed `/Og /Oi /Ot /Oy /Ob1|2` also ties instruction bytes but leaves
16 references unresolved. `/G6`, `/Op`, `/Oy-`, `/Oi-`, `/Os`, and `/O1`
regress. No profile override is retained.

## Scrollbar bounded-loop recovery

The earlier five-variant constructor sweep did not cover loop source forms.
`scrollbar-column-loop-mutations.json` adds four complete bounded-loop
variants. The two-entry `for`, `while`, and `do` forms compile identically,
adding one candidate instruction, 22.46 fuzzy-weighted bytes, and three
resolved references without debt. The pointer-range form adds two
instructions but loses 3.43 bytes. The canonical `for` loop is retained.

The current result is 86.09%, 646/648 instructions, and `172/0/0`
references. Final source SHA-256 is
`1c8cc300b4ba25e154269845eab1901e3c1a53448fe2ea5308b63dda29579f9b`;
the complete experiment ledger SHA-256 is
`64ce1cf1b3cfbb4fe5accc57cfb9b3ab77647990cc81cebca10f24fa2adacfc4`.
The frame remains `0x15c` versus native `0x144`; the remaining gap is still
classified `RESIDUAL=compiler`.

## Nested measure/draw recovery (2026-07-30)

Live disassembly showed that all four right-aligned metadata values evaluate
`grim_measure_text_width(...)` as a nested argument of
`grim_draw_text_small_fmt(...)`. That source shape lets VC6 prebuild the draw
arguments, retain the shared vtable in `esi`, call the measurement slot, and
then finish the x87 subtraction before the draw slot. The named `text_width`
temporary used by the prior source prevented that schedule.

Four complete bounded sweeps recovered the natural source shape:

- `inline-measure-draw-mutations.json` evaluated all 15 combinations of the
  four render pairs. Inlining the author and filename measurements together
  gains 40.293663 weighted bytes and four resolved references without debt.
  The version pairs require a different interface lifetime. Spec SHA-256 is
  `db3a0c12b9b728f99f865542ab8dadf5b2b891a61ce2d88b153b4e3d49ab85b9`.
- `nested-measure-interface-mutations.json` evaluated all 15 direct and mixed
  interface-lifetime combinations for the version value and label. Direct use
  of `grim_interface_ptr` for both outer draws and nested measurements is the
  clean winner: +113.145601 weighted bytes, +2 instructions, and +5 resolved
  references. This reaches the native 648-instruction count. Spec SHA-256 is
  `c63f02bc1b8fd3e26652928a67f32c7048f8f0db41bef4b7a2b3a989c2821b28`.
- `filename-expression-schedule-mutations.json` evaluated four pointer/index
  spellings. Direct indexed expressions, first-element expressions, and a
  named index compile identically; the simplest direct form is retained. It
  gains 60.347222 weighted bytes and two resolved references without changing
  the exact instruction count. Spec SHA-256 is
  `a432cd6061782da35ef34388502454422d0117841c514b175e324bbb58040837`.
- `scrollbar-count-renderer-schedule-mutations.json` evaluated four natural
  orderings for the only remaining non-stack-looking load pair. All four are
  compiler-identical and score-neutral, bounding that residual. Spec SHA-256
  is `a0086b22c2db8ca631a1c84f98f43c7a62c266517d945e8a3c30a42b9f80af7d`.

Together these changes improve the canonical result from 86.09% to **94.29%**,
reduce the fuzzy gap from 362.642968 to **148.856481 weighted bytes**, reach
**648/648 instructions**, and improve references from `172/0/0` to
**`183/0/0`**. Every remaining localized region is either a stack displacement
from the different local-storage allocation or the neutral scrollbar load
ordering above. The final frame is `0x160` versus native `0x144`, so the honest
residual remains `RESIDUAL=compiler`.

The complete ledger now contains 11 sweeps and 155 evaluated variants with
zero errors. Final source SHA-256 is
`74d6204d7290c5c6470ea924eb79b364dd017143530488a50abf219fc333e6e7`;
ledger SHA-256 is
`1ca81e6bad2175fafeb8e6e6bc0c11fec92601c0a2befbd6b3fa62a2ae1f3ddd`.

## Local-storage allocation boundary (2026-07-30)

The remaining stack map is more specific than a simple missing lexical scope.
Native places `_finddata_t` at `esp+0x3c` and its `name` at `esp+0x50`;
the candidate uses `esp+0x58` and `esp+0x6c`. Later, native places the
16-byte version text at `esp+0x44`, while the candidate places it at
`esp+0x50`. Both compilers therefore reuse part of the ended enumeration
storage, but their global slot assignments differ.

`local-storage-lifetime-mutations.json` evaluates explicit block and
single-iteration `do` scopes around the enumeration metadata and version text,
including all four cross-site interactions. All eight variants are
byte-identical at 94.29%, 648/648 instructions, and `183/0/0` references.
This falsifies lexical braces as the missing reuse signal. Spec SHA-256 is
`7de42c038b9d43eb917c09259c270d4f08af3603e3e13c0591a93a335a7c5154`.

Native also writes the opening vector-return temporary and the later
`button_origin` into the same `esp+0x34..0x3b` slot, while the candidate keeps
them at `esp+0x30..0x37` and `esp+0x38..0x3f`. The seven complete variants in
`opening-vector-storage-mutations.json` cover declaration hoisting, split
initialization, copy/component constructors, and component assignment. Four
forms are byte-identical and the other three regress by 8.05 to 106.81
weighted bytes; none changes the frame or improves the match. Spec SHA-256 is
`85e6d2c1ecced7552e0db7d5ea88a96d1c340a216e4f67a0d24e5bca8e83dbc5`.

The canonical source is unchanged. The ledger now contains 13 sweeps and 170
evaluated variants with zero errors; its SHA-256 is
`0c639139588928c444359cc739477de7dc53e7733016e63378702eae99a82431`.
Further progress needs a recovered shared type/TU constraint or another
whole-function ownership fact, not more local scope syntax.

## Scrollbar aggregate publication order (2026-08-09)

A fresh focused region pass separated one non-frame mismatch at native
`0x0040ec5c..0x0040ec99` from the surrounding stack-allocation residue. Native
loads `mods_menu_entry_count` into `edx` at `0x0040ec6e`, then captures
`grim_interface_ptr` in `ecx` at `0x0040ec74`, before publishing the scrollbar
item pointer, count, and visible-row fields. The prior source declared the
renderer before all three field expressions, reversing those two global loads.

Placing the renderer capture between the item-count and visible-row
assignments gives VC6 the native evaluation/publication schedule without an
extra temporary: it loads the count, captures the renderer, and then batches
the three aggregate stores. The complete region becomes exact. The retained
result improves from **94.290123%** to **94.444444%**, reduces the fuzzy gap by
**6.1 weighted bytes** (148.856481 to **142.756481**), preserves the exact
**648/648** instruction count, and improves references from `183/0/0` to
**`184/0/0`**. The remaining localized regions are the documented stack-slot
and frame-size residue. Current source SHA-256 is
`58f6b7611309ee0c9275c67a83b117952fd85824dfab0d9bd58e152a01044fdf`.
