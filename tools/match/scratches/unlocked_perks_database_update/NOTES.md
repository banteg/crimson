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

The natural `msvc6.5 /O2 /GB` reconstruction now matches 93.83% of 511 target
instructions with 510 candidate instructions, a 29-instruction exact prefix,
the exact native `0x218`-byte frame, and `143/0/1` audited references. All
object, guard, function, string, and gameplay-data references resolve. The two
former reference mismatches were constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow.

The improved source shape keeps both separator temporaries, the back-button
position, and the later panel vectors in their native disjoint lexical
lifetimes. The opening anchor uses the same chained-vector expression recovered
in the exact victory-screen callback, followed by the native separate x
adjustments. The button uses the copied x/y pair visible before the native call
instead of mutating the shared panel position. The scrollbar constructor
initializes its two active columns with a bounded loop; VC6 unrolls that loop
to the native two stores while recovering five additional aligned references.
The source also preserves the native `20 + 8` and `16 + 4` vertical spacings
and compact-row post-increment test. Selected-perk rendering performs the
native direct metadata reads instead of decompiler-style cached name and
prerequisite locals.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 93.83%, 510/511 instructions, and
`143/0/1` references before and after classification. The sole entry is an
aligned mismatch; there are no unresolved references. The retained chained
opening-panel expression removes the former slot-09 entry and extends the
exact prologue. The remaining entry pairs the native detail-panel field read
with a candidate constant-pool add from the differently scheduled vector
expression.

The UI field and candidate constant both occur in the recovered computation;
only their x87 ordering differs. No map or layout correction is supported, so
the residual is compiler scheduling only and `RESIDUAL=compiler` preserves the
honest mismatch.

## Recorded lifetime and constructor recovery

Eight bounded mutation families document the current source-shape recovery:

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
  loses 24.27 fuzzy-weighted bytes across the function, so it is not retained.

Together these retained changes move the fresh baseline from 85.38% to 93.83%,
from 508 to 510 candidate instructions, and from `135/0/2` to `143/0/1`
references. The complete append-only evidence is in `experiments.jsonl`
(`sha256:d44e1fd3b92dc5b0a0ebca14b80e2d721ba0538930f330901714080d303ef11b`).
