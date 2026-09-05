# `unlocked_perks_database_update`

Native target: `crimsonland.exe` at `0x00440960` (2,064 bytes).

Live Binary Ninja evidence recovers the complete unlocked-perks database
callback:

- derives the list panel from UI element 09, draws the centered title and
  separator, and counts the byte-sized availability flags for perk ids 1
  through 127;
- handles Up/Down focus movement, clamps the two focus regions, builds the
  frame-local list of available perk-name pointers, and feeds ten visible rows
  to the function-local scrollbar;
- maps the scrollbar's compact hovered row back to the real perk id;
- lazily constructs the scrollbar and Back button under the native two-bit
  guard, with both native `atexit` destructor thunks identified separately;
- returns to Statistics through the Back button, focused Enter, or Escape; and
- renders the selected perk's native id, centered name and separator, optional
  prerequisite name, and wrapped description, including the narrow-screen
  horizontal adjustment.

The natural `msvc6.5 /O2 /GB` reconstruction now matches 99.80% of 511 target
instructions with all 511 candidate instructions, a 74-instruction exact
prefix, the exact native `0x218`-byte frame, and `148/0/0` audited references.
All object, guard, function, string, and gameplay-data references resolve. The
two former unresolved alignments were constant-pool effects of
vector-temporary ownership. The retained shared-panel forms now align both
native UI-field reads without introducing aliases or reference overrides.

The improved source shape keeps both separator temporaries, the back-button
position, and the later panel vectors in their native disjoint lexical
lifetimes. The opening anchor uses the same chained-vector expression recovered
in the exact victory-screen callback, followed by the native separate x
adjustments. The button uses the directly constructed copied coordinate pair
visible before the native call instead of mutating the shared panel position.
The scrollbar constructor initializes its two active columns with a bounded
loop; VC6 unrolls that loop
to the native two stores while recovering five additional aligned references.
The source also preserves the native `20 + 8` and `16 + 4` vertical spacings
and compact-row post-increment test. Selected-perk rendering performs the
native direct metadata reads instead of decompiler-style cached name and
prerequisite locals.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 99.80%, 511/511 instructions, and
`148/0/0` references before and after classification. There are no mismatched
or unresolved references. The retained chained opening-panel expression
removes the former slot-09 entry and extends the exact prologue; the direct
back-panel owner and named chained detail-panel temporary remove the remaining
slot-33 alignment debt.

The sole remaining byte region is one independent instruction swap after the
title-separator coordinates are stored: native loads the virtual-table slot
before converting the integer width to float, while the candidate performs
the same two operations in the opposite order. No map or layout correction is
supported, so `RESIDUAL=compiler` remains the honest classification.

## Recorded lifetime and constructor recovery

Bounded mutation sweeps document the current source-shape recovery:

- `detail-separator-lifetime-mutations.json` found the scoped detail
  separator, adding 12.16 fuzzy-weighted bytes;
- `title-separator-lifetime-mutations.json` found the scoped title separator,
  adding 16.21 bytes, recovering the exact frame, and extending the exact
  prefix to nine instructions;
- `back-button-position-lifetime-mutations.json` found the scoped
  component-wise button-position copy visible in native, adding two
  instructions and 20.76 bytes without disturbing that prefix; and
- `scrollbar-zero-initializer-mutations.json` evaluated all eight ordinary
  initializer shapes. Its two-entry loop added 64.72 bytes and five resolved
  references while preserving the exact two-store behavior;
- `opening-panel-position-mutations.json` evaluated six copy/order forms. The
  direct x-before-y order is byte-neutral but removes one aligned reference
  mismatch in both database callbacks; and
- `detail-panel-position-lifetime-mutations.json` evaluated six scope and
  final-coordinate forms. Keeping the panel x live through the direct final-x
  expression adds 4.05 bytes without a metric tradeoff;
- `opening-position-owner-mutations.json` evaluated nine complete ownership
  and expression shapes. The chained UI-vector sum with separate x
  adjustments adds 56.63 fuzzy-weighted bytes, extends the exact prefix from
  nine to 29 instructions, and resolves two more references without debt; and
- `opening-final-adjustment-order-mutations.json` records the remaining local
  scheduling boundary. Moving the y adjustment before the final x subtraction
  extends the prefix to 67 instructions and resolves one more reference, but
  loses 24.27 fuzzy-weighted bytes across the function, so it is not retained;
  and
- `hovered-row-loop-latch-mutations.json` evaluates eight bounded loop forms.
  The pretested `while` and bounded `for` forms both reproduce the native
  backedge orientation, adding 8.09 fuzzy-weighted bytes without changing the
  instruction count, exact prefix, or reference audit. The simpler `while`
  form is retained;
- `back-panel-position-owner-mutations.json` evaluates eight owner, scope, and
  adjustment-order forms for the Back-button anchor. The direct chained owner
  with separate x adjustments adds 20.23 weighted bytes and clears the last
  unresolved reference without changing the instruction count or prefix; and
- `detail-panel-chained-owner-mutations.json` evaluates eight ordinary
  detail-panel ownership forms. Chaining the final vector into the named
  temporary adds another 8.09 weighted bytes with all 144 references still
  aligned;
- `back-panel-final-adjustment-order-mutations.json` places the Back-panel y
  adjustment before the final x subtraction, adding 8.09 weighted bytes and
  one aligned reference without changing the instruction count or prefix;
- `back-button-copy-form-mutations.json` recovers the native direct
  two-argument vector construction. It adds the missing candidate instruction
  and 58.68 weighted bytes; its temporary one-reference tradeoff is cleared by
  the following detail-panel correction;
- `detail-panel-expression-order-mutations.json` separates the render-offset,
  panel-x, and constant adjustments in native order, adding 16.16 weighted
  bytes and aligning three additional references with no remaining debt; and
- `opening-shared-panel-expression-mutations.json` retests six
  source-supported forms borrowed from exact sibling callbacks. The
  prefix-extending forms lose at least 36.37 weighted bytes, so none is
  retained; and
- `opening-title-interaction-mutations.json` evaluates all 17 single and
  two-site combinations of the native final-adjustment order and eight
  title-separator ownership forms. Neither change wins alone, but their
  constructed-temporary interaction adds 4.04 weighted bytes, extends the
  exact prefix from 29 to 74 instructions, and aligns one more reference;
- `title-separator-call-schedule-mutations.json` evaluates eight ordinary
  interface-owner, width-local, and half-width spellings against the final
  four-byte gap. All compile byte-identically; and
- `title-separator-dispatch-interaction-mutations.json` crosses three ordinary
  `vec2` constructor bodies with four pointer/reference dispatch-owner
  spellings, including every single-site and two-site combination. All 19
  variants are byte-identical to the baseline.

Together these retained changes move the fresh baseline from 85.38% to 99.80%,
from 508 to 511 candidate instructions, and from `135/0/2` to `148/0/0`
references. The complete append-only evidence is in `experiments.jsonl`
(`sha256:3565d3d645eddbdd8937aeac7e2da012f8eab097be17eb6c5b8c3517260c9786`).

## Title-separator dispatch interaction boundary

The final 4.04 weighted bytes are exactly one scheduler inversion shared with
`unlocked_weapons_database_update`: native loads the interface dispatch
pointer before converting the measured title width, while the candidate
performs the `fild` first. The complete 8-variant call-schedule sweep and
19-variant constructor/dispatch interaction sweep leave the candidate
byte-for-byte unchanged at 99.8043%, 511/511 instructions, prefix 74, and
audit `148/0/0`.

The installed compiler matrix reinforces that boundary: stock MSVC 6.0, 6.5,
and 6.6 reproduce the same four-byte gap, while the Processor Pack falls to
89.96% and VC7 to 75.39%. Under VC6.5, `/G5`, `/Ob1`, and `/Ob2` are
byte-neutral; `/G6`, `/Oy-`, and `/O1` regress to 85.32%, 74.36%, and 32.25%
respectively.

The current constructor and direct interface call are therefore not hiding a
recoverable source interaction. The independently recovered weapons sibling
reaches the same single inversion and remains neutral under the same specs, so
this residual is bounded compiler scheduling debt rather than missing gameplay
behavior. Recorded spec SHAs:
`ff1ff64a773f7c6930d593a0bd19b8487383d023c5c6ccd913dcb81ff8743e39`
and
`8f19a54a08f880ced92ea608dc6349ee8de611beccf3e7dec9dd69e525787be5`.

## Native-order neighboring TU boundary

`probe_neighbor_translation_unit.cpp` compiles the contiguous weapons and
perks callbacks in native address order, with one shared definition of their
three database UI helper classes. The perks function stays byte-for-byte at
99.8043%, 511/511 instructions, and prefix 74. VC6 numbers its later
function-local guard and destructor thunks as `$S4`, `$E5`, and `$E6`; the
translation-unit aliases in `scratch.conf` prove the combined object still
audits at `148/0/0` references rather than treating that numbering shift as
recovery debt.

Same-object compilation therefore does not repair the shared scheduler
inversion. The standalone source remains canonical, and there is no honest
reason to promote this WIP island into the native translation-unit manifest
until a new compiler or source constraint changes the four weighted bytes.

The recorded probe SHA is
`763c886a313691f3934a38782b035b4e3ab981cfb001eb9cd1cac72a157c2e56`.

## Original `gdiListBox_t` constructor recovery (2026-08-14)

The recovered original `Crimson.h` identifies the function-local scrollbar as
the historical `gdiListBox_t` layout and supplies its exact constructor:
`memset(columnWidth, 0, 8)`. The header SHA-256 is
`41fa136d8de7cd17c69b10f428ec78e37763d98896ca34990a061015801c8fda`.
This explains why only the first two integer column widths are initialized;
the literal eight-byte length is source behavior, not a decompiler guess.

Live native initialization zeroes the same two dwords while publishing the
local-static guard and destructor. Replacing the previously recovered
two-entry loop with the literal original `memset` is byte-identical at 99.80%,
511/511 instructions, prefix 74, and `148/0/0` references, so the original
expression is retained. `sizeof(int) * 2` is also byte-identical, while the
tempting whole-array clear falls to 90.78%, moves the first mismatch to
instruction 15, and leaves `140/0/0` references. The complete replay is in
`original-listbox-constructor-mutations.json` (SHA-256
`3e870ed0db01b516070ab5695cf9e4192d064ec9d5d89759fb9ca6cd0a94de8f`).

## Batch 05 focused value boundaries (2026-09-05)

`batch-05-focused-value-boundaries-mutations.json` records 3 complete, compiling
controls against the 99.804305% baseline. The source forms are
`separator-dimensions-value`, `separator-width-value-reference`,
`separator-renderer-reference`.

No control improves the retained baseline without a metric tradeoff. These are measured
source shapes; any scope-generated static name changes must be verified against COFF
before treating unresolved references as substantive debt. Canonical source and
configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.

## Exact-match follow-up (2026-09-05)

Six ordinary vector-member and free-function separator helpers tested integer/float
width and renderer ownership. All reproduce the same single dispatch-load/integer-
conversion inversion.

exact-followup-value-interactions-mutations.json records all 6 complete, compiling
controls. No source change is retained. These outcomes bound the tested inputs and
interactions, not the function's matchability.
