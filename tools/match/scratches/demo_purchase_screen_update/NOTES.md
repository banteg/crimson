# `demo_purchase_screen_update`

High-confidence recovery of the 2,642-byte demo purchase and rotating upsell
callback at `0x0040b740`. The current VC6 scratch matches **93.30%**
(`698` candidate instructions versus `691` native), reaches a 136-instruction
exact prefix, and resolves all `187` references without unresolved or
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
