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

The natural `msvc6.5 /O2 /GB` reconstruction now matches 95.12% of 523 target
instructions with 522 candidate instructions, a 29-instruction exact prefix,
the exact native `0x118`-byte frame, and `151/0/1` audited references. All
object, guard, function, string, and gameplay-data references resolve. The two
former reference mismatches were constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow.

The frame and control-flow improvement comes from source-supported structure:
the title separator and three panel anchors have their native disjoint
lifetimes, and the Back button receives the scoped copied coordinate pair
visible before the native call. The native `20 + 10`, `20 + 8`, and `16 + 4`
vertical spacings remain separate operations, the compact-to-real-id mapping
uses its native post-increment test, and the fire-rate branches place the RPM
path before the ammo-class-1 `n/a` path.

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

A fresh corpus audit keeps the candidate at 95.12%, 522/523 instructions, and
`151/0/1` references before and after classification. The sole entry is an
aligned mismatch; there are no unresolved references. As in the sibling perks
callback, the retained chained opening-panel expression removes the former
slot-09 mismatch and extends the exact prologue. The remaining entry is
confined to the differently scheduled detail-panel vector expression.

No data-map or scrollbar/UI layout correction is supported. The residual is
compiler scheduling only, and `RESIDUAL=compiler` records that conclusion
without changing the two honest mismatches.

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

Together they move the fresh baseline from 82.87% to 95.12% and from
`140/0/2` to `151/0/1` references. The complete append-only evidence is in
`experiments.jsonl`
(`sha256:defd64ebc4d96b9a84fe745c9311908a8b3bd0a8332c322bc3da24a72ce31042`).

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
