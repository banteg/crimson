# `game_state_set`

Native target: `crimsonland.exe` at `0x004461c0` (1854 bytes).

Live Binary Ninja and the audited UI data map recover the central state-entry
dispatcher. It resets transient UI state, records the previous/current state,
flushes input, configures the active UI elements and callbacks for every menu
state, initializes gameplay mode counters, and seeds the shared transition
timeline.

The main-menu path uses four temporary two-float atlas coordinates per branch
to retarget six menu elements into the item-text texture. That aggregate shape
is supported by the native 0x50-byte frame and its four 0x1c-stride XY copies;
the two config branches deliberately remain separate because the non-wide path
remaps the perk-selection row.

Those 0x1c-stride destinations are now recovered in the canonical
`ui_element_t` as the first four records of an eight-entry `overlay_vertices`
bank. The dispatcher writes each vertex's `u`/`v` pair at offsets `0x138`,
`0x154`, `0x170`, and `0x18c` and assigns the following texture handle at
`0x204`. This removes the former 0x208-byte partial UI mirror while preserving
the result below byte-for-byte. The same shared fields are consumed by
`ui_element_render`, independently confirming the full vertex interpretation
rather than a UV-only padding view.

Current MSVC 6.5 `/O2 /GB` result: **85.35%**, with an exact **166/399**
instruction prefix, 399 native instructions versus 393 candidate instructions,
the exact 0x50-byte frame, and reference audit **161 resolved / 1 unresolved /
0 mismatched**. Keeping the requested state in EBP and a distinct local atlas
row reproduces the native EBP/ESI/EDI allocation and raised the match from the
initial 46.26% switch-shaped reconstruction.

The remaining six-instruction size deficit is localized to the final two
game-mode counter branches. Native VC6 repeats a load/flag/increment/flag/store
sequence for both typo mode and the fallback mode; compiling the equivalent
plausible if/else source tail-folds their common flag stores and uses direct
memory increments. The controls-menu Vec2 assignment also has one independent
store-scheduling difference. No fake dependencies, volatile qualifiers, dead
expressions, or register constraints are used to defeat those optimizations.

The sole unresolved reference is the zero written at `0x00487260` on game-over
entry. Binary Ninja finds no other code or data xrefs, so the scratch retains a
descriptive local name without promoting an unsupported semantic name into the
shared data map.
