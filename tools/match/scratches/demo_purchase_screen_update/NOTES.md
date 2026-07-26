# `demo_purchase_screen_update`

High-confidence recovery of the 2,642-byte demo purchase and rotating upsell
callback at `0x0040b740`. The current VC6 scratch matches **91.00%**
(`698` candidate instructions versus `691` native) with all `187` references
resolved and no unresolved or mismatched references.

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
panel and the post-panel message renderer their own naturally scoped vector
locals also recovers the native active-panel stack scheduling. Together these
changes reduce the fuzzy gap from `312.17` to `237.76` bytes.

The native function uses a `0x2c` local frame while VC6 reserves `0x34` for the
two semantic vector lifetimes in the reconstruction. The remaining differences
are stack-slot coloring, block placement, and instruction scheduling. They are
retained rather than forcing stack overlays, volatile qualifiers, or other
byte-shaping constructs.
