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
  exact prefix from 29 to 74 instructions, and aligns one more reference.

Together these retained changes move the fresh baseline from 85.38% to 99.80%,
from 508 to 511 candidate instructions, and from `135/0/2` to `148/0/0`
references. The complete append-only evidence is in `experiments.jsonl`
(`sha256:9a221ab3fc9d21b04b62b78f7fe3dd8f00995cf5ffb2b6347d6ca863193ecd4f`).
