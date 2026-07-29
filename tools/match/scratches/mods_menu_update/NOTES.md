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
also reproduces the native enumeration loop. The renderer used for the
scrollbar-label color is captured before the scrollbar fields are populated,
matching the native load at `0x0040ec74` and its use at `0x0040ecbc`.

Current MSVC 6.5 `/O2 /GB` result:

```txt
match=86.09% prefix=0/648 target_insns=648 candidate_insns=646 refs=172/0/0
first_target=sub esp, 0x144
first_candidate=sub esp, 0x15c
```

Recovery is semantic-complete. The remaining differences are compiler lifetime
and scheduling residue. The
native function reuses the ended `_finddata_t` metadata area for the later
16-byte version string and places a vector return temporary eight bytes later;
the natural candidate retains a frame 24 bytes larger. Capturing the renderer
at its recovered source lifetime removes the prior static-scrollbar scheduling
mismatch and reduces the fuzzy gap by 12.10 bytes. The source deliberately does
not use unions, volatile state, dead expressions, forced addresses, inline
assembly, or fake aliases to manufacture native local layout.

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
