# `demo_purchase_screen_update`

High-confidence recovery of the 2,642-byte demo purchase and rotating upsell
callback at `0x0040b740`. The current VC6 scratch matches **94.74%**
(`698` candidate instructions versus `691` native), reaches a 136-instruction
exact prefix, and resolves all `190` references without unresolved or
mismatched references.

## Recovered source shape

- exits an in-progress transition back to the main menu when a full-version
  install is detected, restoring presets and the Crimsonland theme;
- activates the purchase screen from primary fire, Escape, or Space and extends
  its timer to 16 seconds;
- lazily constructs the Maybe later and Purchase buttons under the native
  two-bit local-static guard;
- reproduces the entry/exit alpha envelope and the five rotating
  `Want more ...?` messages;
- renders the four-slot backplasma gradient, mockup, logo, complete feature
  list, footer, and both responsive-width button positions;
- preserves the native `sin((timer % 1000) * 2*pi)` pulse expression as
  emitted, including its unusual missing division by 1000;
- opens `http://buy.crimsonland.com` and requests shutdown from Purchase;
- implements both Maybe later paths, including the already-seen offer shutdown
  latch and the first-seen preset/audio restoration;
- advances the shared demo timeline, restarts demo mode at the strict timeout,
  and preserves the native shared y-local reuse when that restart deactivates
  the purchase screen mid-callback; and
- always finishes the surviving paths through UI-element and cursor rendering.

## Static-object evidence

Live Binary Ninja disassembly shows the Maybe later constructor guarded by bit
1 of `demo_purchase_screen_init_flags` and registering the empty thunk at
`0x0040c1b0`. Purchase is guarded by bit 2 and registers `0x0040c1a0`.
The VC6 object symbols prove `$E2` belongs to Maybe later and `$E3` to
Purchase. Both thunks are tracked separately as exact one-instruction matches.

## Remaining mismatch

Assigning the timeline-derived y value before the independent alpha default
recovers the native x87 store/pop/reload comparison sequence. Giving the active
panel its own naturally scoped vector recovers the native active-panel stack
scheduling. Those changes first reduced the fuzzy gap from `312.17` to
`237.76` bytes.

Keeping the post-panel vector, color, and width calculations in the
forced-inline `demo_purchase_render_message` helper then lets VC6 reuse the
ended active-panel slots. This recovers the native `0x2c` local frame, raises
the exact prefix from 1 to 136 instructions, and reduces the fuzzy gap again
from `237.76` to `176.89` bytes.

The remaining differences are the native cold placement of the five-message
selection ladder, seven candidate instructions, and x87 scheduling within the
message renderer. They are retained rather than forcing layout-only control
flow, stack overlays, volatile qualifiers, or other byte-shaping constructs.

The recorded `message-selector-shape/switch` variant raises the aggregate fuzzy
score by `12.49` weighted bytes and happens to equalize the instruction counts.
It is deliberately rejected: the regional diff shows VC6 emitting a jump table,
while live native disassembly at `0x0040c137..0x0040c185` is the recovered
comparison ladder. The higher aggregate score is therefore not matching
evidence for a source correction.

The native cold-tail layout is now bounded directly. Replacing the opening
active test with a forward guard and moving the comparison ladder after the
epilogue makes VC6 emit exactly `691` instructions and the observed backward
jump into the shared renderer, but it regresses the fuzzy score to `92.76%`
(`-14.28` weighted bytes) without changing the `187/0/0` reference result.
Preserving the original `if/else` entry while moving only the selector is
compiled back to the baseline object byte-for-byte. A complete 35-variant
interaction sweep with the natural renderer declaration/materialization
spellings finds no improving interaction: the cold-tail variants remain at
the same `92.76%`, while the remaining variants are neutral or worse.

These results are recorded by `message-cold-tail-mutations.json`,
`message-cold-tail-else-mutations.json`, and
`message-cold-tail-interaction-mutations.json`. They reject source order,
the natural guard spellings, and the already-identified renderer lifetimes as
independent levers. Further work needs a different recovered type/lifetime or
original-TU constraint rather than retaining a score-regressing layout rewrite.

## Message color-alpha publication order

Live Binary Ninja disassembly at `0x0040c022..0x0040c0c2` shows both message
rectangle passes publishing their color alpha before materializing the
corresponding Y coordinate. The first pass stores `alpha * 0.5f` before
forming `message_y - 4.0f`; after the draw call, the second pass computes
`alpha * 0.8f` before forming `position_y + 72.0f`.

The source previously stated each independent Y assignment before its alpha
assignment. Reordering those ordinary aggregate-field publications to match
the native ownership schedule removes the large x87/stack-lifetime regions at
`0x0040c022..0x0040c0cc`.

The retained source improves from **93.3045%** to **94.6004%**, adding
**34.2376 fuzzy-weighted bytes** and reducing the gap from **176.8942** to
**142.6566 bytes**. Instruction counts and the 136-instruction prefix are
unchanged, while the reference audit improves from `187/0/0` to `190/0/0`.

The remaining 4.83-byte region showed one further independent publication
order. Native stores the second rectangle's RGB fields before
`position.x = 64.0f`; the source stated X first. Moving that X publication
after RGB removes the region completely, adds another **3.8042 weighted
bytes**, and lowers the gap to **138.8524 bytes** without changing instruction
counts, prefix, or references. The final retained result is **94.7444%**, a
cumulative **38.0418 weighted-byte** improvement over the 93.3045% baseline.

## Current cold-tail replay and second-button lifetime (2026-08-12)

Because the original cold-tail searches predated the retained message color
publication order, the complete interaction matrix was rebuilt around the
current source. `current-message-cold-tail-interaction-mutations.json`
(SHA-256
`693dcbaeeeff556809cb1f62f1da2d948538d85b505154e7e5abfc1f774908e5`)
evaluates all 35 defined singles and interactions across the forward guard,
cold selector placement, message-width declaration, and current message-Y
publication. The width declarations are byte-neutral, the current Y
alternatives lose **13 weighted bytes**, and the paired cold-tail layout still
loses **14 weighted bytes**. The current source therefore does not revive the
previous score-regressing cold layout.

Live native comparison exposed an independent scheduling region at
`0x0040bf08..0x0040bf33`. For the Maybe later button, native starts converting
the X component, computes the integer Y base, and only then publishes X before
converting and publishing Y. The prior sequential field expressions forced the
X store before the Y calculation.

`current-second-button-position-mutations.json` (SHA-256
`ec81b950bf81ed7922c0667557a418f806e808fb6d86e4edc3cad13df6b297d4`)
evaluates all seven defined aggregate, scalar-pair, declaration, and
publication shapes. Naming the two float components before assigning the
shared vector is the sole improvement and removes that complete regional diff.
It raises the score from `2503.1475881929446/2642` (**94.744420%**) to
`2506.9517638588914/2642` (**94.888409%**), a gain of **3.804176 weighted
bytes**, while preserving the 136-instruction prefix, 698/691 instruction
count, and clean `190/0/0` references. Current source SHA-256 is
`a9300418e68160ba19c6191529d800bce74322661510da3aeea11991c531ac7a`.

The five-variant current-baseline confirmation in
`current-second-button-component-order-mutations.json` (SHA-256
`3e1625bc60a77193d55bf17f090defb6811be67905d81229ed7ef7d2ca099982`)
finds declaration, assignment, qualifier, and early-X-publication spellings
byte-neutral. Reversing the final component publications loses **26.629230
weighted bytes** and two references, confirming that the retained X-then-Y
publication boundary is material rather than a name-only score accident.

## Exact shared UI tail (2026-09-05)

Sharing the UI update and cursor tail, and guarding message rendering with the
live screen-active flag, recovers the native cold message branch and eliminates
the duplicated cleanup path. The flag is checked after the active branch because
starting the demo can change it. Existing purchase and dismissal returns retain
their original behavior.

`shared-ui-tail-mutations.json` records four source controls: the live global
guard reaches 100% (691/691 instructions, 198/0/0 references, 2642 bytes); local
flag variants and duplicated branch-local rendering do not. This supersedes the
previous compiler-residual classification.
