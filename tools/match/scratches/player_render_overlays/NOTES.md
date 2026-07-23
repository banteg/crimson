# `player_render_overlays`

Native target: `crimsonland.exe` at `0x00428390` (4,582-byte manifest extent,
1,148 instructions in the current Binary Ninja analysis).

This scratch is an evidence-led reconstruction of the complete per-player
render callback. It retains the early suppression and transition/state gates,
Radioactive aura, dead and alive trooper sprite passes, multiplayer tints,
shield layers, muzzle flash, and the final segmented target-trail branch.

The reconstructed control flow and constants are corroborated by live Binary
Ninja HLIL/disassembly and the retained IDA artifact. The modern world renderer
also independently carries the active aura, trooper, shield, and muzzle-flash
passes. The native callback uses a raw float at player offset `0x98` to gate the
target trail; the shared header currently gives that storage an integer-shaped
reserved name, so the scratch preserves the evidenced float view locally
instead of changing a broad ABI declaration from one use.

The target-trail selector is initialized to perk id zero by the native perk
database constructor and has no other writer in the executable. The branch is
therefore preserved as recovered native source shape, but deliberately not
given a speculative gameplay name or treated as a required modern-port feature.

With the standard `msvc6.5 /O2 /GB` profile, the complete candidate is an
`83.88%` WIP (`1,141/1,148` instructions, prefix `9/1,148`). The target and
candidate prologues are identical through the `sub esp, 0x2c` local-frame
allocation. Masked-reference auditing reports `326/0/0`: every aligned symbol
resolves and agrees without a speculative alias.

The muzzle-flash weapon-flag arms deliberately retain their identical
`grim_draw_quad` calls. Native reloads the player size in each arm and pushes
each arm's size and position arguments before tail-merging at the shared
virtual call; expressing the call once after the branch instead produces a
shorter, structurally different VC6 lowering. Recovering the branch-local
calls raised the candidate from `83.00%` and `1,134` instructions to `83.88%`
and `1,141` instructions.

The scoped `camera_offset:camera_offset_x` alias only identifies the scratch's
two-float vector declaration with the proven native x/y global pair. A tested
`msvc6.5pp` override fell to `70.34%`; the default VC6 backend is retained.
The remaining differences are honest x87 temporary placement, vector-expression
lowering, register scheduling across the long sprite pipeline, and the
target-trail loop's local-slot choices rather than omitted render branches or
unresolved references.
