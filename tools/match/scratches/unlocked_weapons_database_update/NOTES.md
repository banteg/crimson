# `unlocked_weapons_database_update`

Native target: `crimsonland.exe` at `0x00440110` (2,086 bytes).

Live Binary Ninja evidence recovers the complete unlocked-weapons database
callback:

- derives the list panel from UI element 09, draws the centered title and
  separator, and counts unlocked weapon ids 1 through 63;
- handles Up/Down focus movement, clamps the two focus regions, builds the
  frame-local list of unlocked weapon-name pointers, and feeds ten visible rows
  to the function-local scrollbar;
- maps the scrollbar's compact hovered row back to the real weapon id;
- lazily constructs the scrollbar and Back button under the native two-bit
  guard, with both native `atexit` destructor thunks identified separately;
- returns to Statistics through the Back button or Escape; and
- renders the selected weapon's native id, name, icon, fire rate (including
  the ammo-class-1 `n/a` case), reload time, and clip size, including the
  narrow-screen horizontal adjustment.

The natural `msvc6.5 /O2 /GB` reconstruction now matches 99.81% of 523 target
instructions with all 523 candidate instructions, a 74-instruction exact
prefix, the exact native `0x118`-byte frame, and `157/0/0` audited references. All
object, guard, function, string, and gameplay-data references resolve. The two
former unresolved alignments were constant-pool effects of vector-temporary
ownership. The retained shared-panel forms now align both native UI-field
reads without introducing aliases or reference overrides.

The frame and control-flow improvement comes from source-supported structure:
the title separator and three panel anchors have their native disjoint
lifetimes, and the Back button receives the scoped copied coordinate pair
visible before the native call. The native `20 + 10`, `20 + 8`, `16 + 4`, and
weapon-icon `22 + 26` vertical spacings remain separate operations, the
compact-to-real-id mapping uses its native post-increment test, and the
fire-rate branches place the RPM path before the ammo-class-1 `n/a` path.

An older caller-local scrollbar replica typed its tab-column offsets as
`float[8]` and scored 85.74% with `143/0/2` references. Live
`ui_scrollbar_update` disassembly proves those fields are `int[8]`: the helper
multiplies integer entries and the highscore caller stores raw integers 10, 30,
and 44. Reverting to the known 85.74% result would reintroduce the incorrect
float type. The correctly typed constructor now initializes its two active
columns with a bounded loop. VC6 unrolls that loop to the native two stores and
recovers nine additional aligned references; ordinary chained, separate, and
integer-literal zero initializers all compile identically at the former lower
score.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 99.81%, 523/523 instructions, and
`157/0/0` references before and after classification. There are no mismatched
or unresolved references. As in the sibling perks callback, the retained
chained opening-panel expression removes the former slot-09 entry and extends
the exact prologue; the direct back-panel owner and named chained detail-panel
temporary remove the remaining slot-33 alignment debt.

No data-map or scrollbar/UI layout correction is supported. The sole remaining
byte region swaps two independent instructions after the title-separator
coordinates are stored: native loads the virtual-table slot before converting
the integer width to float, while the candidate schedules them oppositely.
`RESIDUAL=compiler` records that conclusion.

## Shared-class source-shape recovery

The sibling perks callback supplied four source constraints that were retested
independently here:

- `scrollbar-zero-initializer-mutations.json` evaluates all eight ordinary
  constructor forms. The two-entry loop is the sole improvement, adding 187.64
  fuzzy-weighted bytes and nine resolved references while retaining 522/523
  instructions and the exact prefix.
- `back-button-position-lifetime-mutations.json` evaluates eight copied,
  component-wise, constructed, scalar, order, and scope variants. The scoped
  component/scalar pair adds 11.98 bytes without a metric tradeoff; the typed
  component form is retained.
- `opening-panel-position-mutations.json` evaluates six copy/order forms. The
  direct x-before-y order is byte-neutral but removes one aligned reference
  mismatch, so it is retained.
- `detail-panel-position-lifetime-mutations.json` evaluates six wider scope
  and final-coordinate forms. Its fuzzy-positive variants reduce resolved
  references or increase reference debt; the only clean form is byte-neutral,
  so no detail-panel change is retained.
- `opening-position-owner-mutations.json` evaluates four source-supported
  shared-panel forms. The chained UI-vector sum with separate x adjustments
  adds 55.89 fuzzy-weighted bytes, extends the exact prefix from nine to 29
  instructions, and resolves two additional references without debt. Moving
  the y adjustment before the final x subtraction reaches a 67-instruction
  prefix but loses 23.95 weighted bytes relative to the retained winner.
- `hovered-row-loop-latch-mutations.json` evaluates four bounded loop forms.
  The pretested `while` and bounded `for` forms both reproduce the native
  backedge orientation, adding 7.98 fuzzy-weighted bytes with unchanged
  instruction and reference counts. The sibling-consistent `while` is
  retained.
- `back-panel-position-owner-mutations.json` evaluates five owner and
  adjustment-order forms for the Back-button anchor. The direct chained owner
  with separate x adjustments adds 19.96 weighted bytes and clears the last
  unresolved reference without changing the instruction count or prefix.
- `detail-panel-chained-owner-mutations.json` evaluates five ordinary
  detail-panel ownership forms. The direct form scores higher but drops one
  resolved reference; the retained named chained temporary instead adds 7.98
  weighted bytes with all 152 references aligned.
- `back-panel-final-adjustment-order-mutations.json` places the Back-panel y
  adjustment before the final x subtraction, adding 7.98 weighted bytes and
  one aligned reference without changing the instruction count or prefix.
- `detail-panel-adjustment-order-mutations.json` tests five broader ownership
  and adjustment schedules. Every positive variant loses a resolved reference,
  so none is retained.
- `back-button-copy-form-mutations.json` retests the perk callback's
  constructor breakthrough across five ordinary forms. All are byte-for-byte
  neutral here, bounding that sibling-specific constraint.
- `detail-panel-expression-order-mutations.json` separates the render-offset,
  panel-x, and constant adjustments in native order, adding 23.95 weighted
  bytes and one aligned reference without debt.
- `weapon-icon-position-mutations.json` recovers the native `22 + 26`
  vertical split around the 32-pixel x adjustment. It adds the missing
  candidate instruction, 25.96 weighted bytes, and two aligned references,
  collapsing every downstream branch-displacement residual.
- `opening-title-interaction-mutations.json` evaluates all 17 single and
  two-site combinations of the native final-adjustment order and eight
  title-separator ownership forms. The constructed-temporary interaction adds
  3.99 weighted bytes, extends the exact prefix from 29 to 74 instructions,
  and aligns one more reference.
- `title-separator-call-schedule-mutations.json` evaluates eight ordinary
  interface-owner, width-local, and half-width spellings against the final
  four-byte gap. All compile byte-identically, bounding the remaining
  scheduling residual.

The installed compiler matrix reinforces that boundary: VC6.6 reproduces the
same four-byte gap, Processor Pack and VC7 regress decisively, and `/G5`,
`/Ob1`, and `/Ob2` are byte-neutral under VC6.5. `/G6`, `/Oy-`, and `/O1`
all regress.

Together the retained changes move the fresh baseline from 82.87% to 99.81%,
from 522 to 523 candidate instructions, and from `140/0/2` to `157/0/0`
references. The complete append-only evidence is in
`experiments.jsonl`
(`sha256:e7e3ab1da70186ffd58ac71d971dde1df2fdf427c9ff34e5da686481d88b37f4`).

## Unlock-loop mutation audit

Live disassembly bounds the two localized unlock scans. The database count at
`0x0044026e` zeroes only `esi`, walks the unlocked byte with an `eax` cursor in
`0x7c`-byte steps, and stops at `0x004d996c`. The hovered-row map at
`0x00440471` loads the hovered index once into `esi`, advances the compact row
with the native `mov ebp, edx; inc edx; cmp ebp, esi` post-increment sequence,
and walks the weapon id and table cursor together.

The recorded schema-1 sweep
`unlock-loop-shape-mutations.json`
(`sha256:62d22a707f69541c9629c69647bdee476df6965309bab1b8fff5b802cb8bf857`)
tested four semantic source shapes against the fresh 82.870813% baseline:

- caching the hovered index explicitly and spelling the count as a bounded
  index `for` loop are byte-for-byte neutral;
- an explicit count cursor falls to 79.923151%, 518/523 instructions, and
  `126/0/5` references; and
- an explicit hovered-row cursor falls to 79.731028%, 518/523 instructions,
  and `127/0/5` references.

No single-site mutation improves the whole-function result, so no interaction
sweep is justified and `scratch.cpp` remains unchanged. The compiler already
recovers the native pointer walks from the current indexed source; spelling the
cursors explicitly perturbs broader allocation and reference alignment without
adding native behavior.

## Title-separator dispatch interaction boundary

The remaining four weighted bytes are exactly one scheduler inversion:
native loads the interface dispatch pointer before converting the measured
title width, while the candidate performs the `fild` first. A final complete
19-variant sweep crossed three ordinary `vec2` constructor bodies with four
pointer/reference dispatch-owner spellings, including every pair. All
variants are byte-for-byte neutral at 99.8088%, 523/523 instructions, prefix
74, and audit `157/0/0`.

The current constructor and direct interface call are therefore not hiding a
recoverable source interaction. Combined with the neutral call-schedule and
compiler-profile menus, the residual is bounded compiler scheduling debt.
Recorded spec SHA:
`8f19a54a08f880ced92ea608dc6349ee8de611beccf3e7dec9dd69e525787be5`.

## Native-order neighboring TU boundary

The final higher-level hypothesis is also falsified. The adjacent native
island is weapons update, its two local-static destructor thunks, perks update,
then its two destructor thunks. `probe_neighbor_translation_unit.cpp` compiles
both canonical callbacks in exactly that order with one guarded definition of
the shared `database_vec2_t`, `database_scrollbar_t`, and `database_button_t`
classes.

Scoring the weapons symbol from that combined object is byte-for-byte neutral:
99.8088%, 523/523 instructions, prefix 74, and `157/0/0` references. Thus
neither the sibling callback nor shared class identity changes the dispatch
load / integer-width conversion schedule. The independently compiled source
remains canonical; promoting this WIP island to a translation-unit cluster
would add no exact coverage.

The recorded probe SHA is
`d4530894e70ee9d8386b4776815877b16faadb39fec1333d04588819cedb64bf`.
