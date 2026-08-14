# `quest_failed_screen_update`

Exact recovery for the 1,261-byte quest-failure screen at `0x004107e0`.
The scratch reconstructs the complete native screen flow and matches all
292 instructions and 151 audited references.

## Recovered source shape

- clears the reflex-boost timer and conditionally starts Shortie Monk on entry;
- renders the gameplay world, UI elements, perk prompt, and reaper banner;
- recovers the native chained-vector anchor
  `position + vertex + (180, 40)`, including VC6's hidden first-addition
  temporary;
- loads the high-score table on phase `-1`, snapshots the rank, copies the game
  mode into the active record, and flushes stale input;
- selects all six retry messages, including the native `rewared` typo;
- renders high-score text input with the active record and one-based rank;
- advances the evolved layout cursor by 98 pixels for the button stack instead
  of incorrectly resetting it from the initial panel origin;
- lazily constructs the Play Again, Play Another, and Main Menu buttons;
- implements all three native transition/audio action paths; and
- always renders the cursor after the phase-gated body.

## Static-object evidence

The native constructor blocks initialize `quest_failed_play_again_button`
(`0x00482680`), `quest_failed_play_another_button` (`0x00482698`), and
`quest_failed_main_menu_button` (`0x004824f0`) under bits 1, 2, and 4 of
`quest_failed_screen_flags` (`0x004825d8`). Live Binary Ninja xrefs show their
`atexit` callbacks at `0x00410d10`, `0x00410d00`, and `0x00410cf0`.

The VC6 object relocation table proves the corresponding local symbols:
`$E2` is adjacent to `play_again_button`, `$E3` to `play_another_button`, and
`$E4` to `main_menu_button`. `REFERENCE_ALIASES` therefore scopes all three
button objects, the function-local guard, and the three empty destructor thunks
to those proven native identities.

## Former compiler residual

The recovered cumulative `xy.y += 98.0f` update makes the panel slot naturally
available for the text-input vector, collapsing the candidate from a 32-byte
frame to the native 24-byte frame. Together with the chained-vector expression,
the function now has the native 292 instructions and all 151 references, at
99.32%.

The last two differing instructions were VC6 storing and reloading the hidden
first-addition Y temporary at `[esp+0x20]` in the target and `[esp+0x10]` in
the candidate. Earlier declaration and initialization menus retained that
stack-coloring choice or worsened scheduling.

The panel expression now uses the recovered UI element and vertex position
aggregates. Extending only the working `xy` vector's lifetime across the
single-iteration body gives VC6 the native `[esp+0x20]` allocation without
changing behavior.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**99.32%**, 292/292 instructions, prefix 30, and `151/0/0` references. Its
single region differs only in the hidden first-addition Y temporary using
`[esp+0x10]` instead of native `[esp+0x20]`; every surrounding x87 operation
and all six references align. The render, phase, score-entry, retry-message,
button, transition, audio, and cursor paths are complete.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Recorded opening-vector sweep

`opening-vector-lifetime-mutations.json` evaluated 11 constructor,
copy-then-add, and panel-chain lifetime variants. None improved the score,
instruction count, or reference audit. No stack-slot coercion was retained;
the two-instruction compiler residual remains visible.

## Opening stack-lifetime bounds

Three follow-up matrices exhaust the nearby natural declaration and
initialization choices for the hidden first-addition temporary:

- `opening-input-lifetime-mutations.json` evaluated all seven input-vector
  declaration/reuse variants. The three valid combined forms were
  byte-identical; isolated partial transformations failed compilation.
- `opening-banner-lifetime-mutations.json` evaluated all seven banner-vector
  declaration/assignment variants. All six complete forms were
  byte-identical, while the isolated assignment correctly failed compilation.
- `opening-offset-lifetime-mutations.json` evaluated all five offset/result
  forms. Three named or staged forms were byte-identical. Initializing the
  live cursor directly lost 117.46 weighted bytes, four instructions, five
  resolved references, and introduced one reference mismatch.

All 19 variants completed without budget truncation. None moves the native
`[esp+0x20]` temporary to the candidate's `[esp+0x10]` slot, so no source
change is retained and the residual remains honestly classified as compiler
stack coloring. The scratch remains **99.32%**, 292/292 instructions, a
30-instruction exact prefix, and reference audit 151/0/0.

Recorded spec SHA-256 values are
`ecf000b7aef50bb8942d73df60274b515c84a20c26d77306cdd54c2a846702fb`
(input),
`2f111db0111c4481809e0b3f1b5ee93937894857a2b01a9cb6ca7efd21c8b020`
(banner), and
`b2375c37b131052def17d74ac924399d4d6c29133a96253e8aa53c86eba52091`
(offset/result). The unchanged source SHA-256 is
`7da4fdcf4cdf3729128fa1d272e811ae1f7871f37dfb72023a2b18da0a30f4c5`;
the `experiments.jsonl` SHA-256 at that earlier checkpoint was
`dc0c47e25016a70a97210dda06cbe9f38b686efc0c55aa16812762cb71fa3047`.

## Exact-tail audit (2026-07-27)

Live Binary Ninja still shows only the first chained-vector Y temporary at a
different stack slot. MSVC 6.0, 6.5, and 6.6 reproduce the baseline;
Processor Pack falls to 88.66% with a reference mismatch, and VC7 falls to
78.32% with unresolved and mismatched references. No tested flag profile is
exact.

`outer-vector-lifetime-mutations.json` evaluates 15 function-scope input and
banner declaration/reuse combinations. Five complete forms are byte-neutral;
moving the real input vector out of its inner lifetime falls to 97.60%; invalid
partial transformations fail compilation. A recorded
`canonical-vector-add-confirmation` probe is neutral. No source change was
retained; baseline and final remain **99.32%**, 292/292, prefix 30,
`151/0/0`. After these appended records, `experiments.jsonl` is
`43f42db83c3ed24eada717d441ea1ae565d39ca2438a43e19fdedbf61b0ca618`.

## Exact lifetime recovery (2026-07-27)

`panel-working-lifetime-mutations.json` evaluated four bounded lifetime
placements for the panel working vector. Three variants are exact. The
smallest retained change declares only `xy` immediately before the
single-iteration `do` body and assigns `panel_xy` inside it. This is the
native-supported source explanation for the final stack-coloring difference:
the hidden chained-add Y temporary moves from `[esp+0x10]` to native
`[esp+0x20]`.

The retained `working-before-do` variant is **100.00%**, 292/292 instructions,
prefix 292, and `151/0/0` references, improving the weighted score by
8.636986 bytes. Its source SHA-256 is
`78a8bc5e989487bcdc8fbede7b31323210f4886f7601a58bf9227ede24171932`;
the recorded spec SHA-256 is
`67e09f4bd65f16ecba15be49b9fd260e4f523e1d4a60a22b99bb6f58dfafb40e`.
The former compiler-residual classification is removed.

## Original button constructor recovery (2026-08-14)

The recovered 2003 `gdiButton_t` constructor spells its adjacent force flags
as `forceSmall = forceBig = false`. The complete three-variant
`original-button-constructor-mutations.json` sweep maps that to
`force_small = force_wide = false` and keeps this function exact at 292/292
instructions with `151/0/0` references. Reversing the chain, or using separate
small-first stores, preserves the masked byte score but creates six reference
mismatches, so neither was retained.

Source SHA-256 is
`12f093230d3ebb8ffdc14b6782864774c7ef7d04df4dbb5b1f3479765e25f199`;
spec SHA-256 is
`76a16f9d972be8d6ce684316670cb98df682916a901b120ce589c63d204121fb`;
the experiment ledger SHA-256 is
`ec98a6055474cb04dabd79f62e5cd8246e3ba4a57cdc876f414f8cac33fff145`.
