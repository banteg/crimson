# perk_selection_screen_update

High-value recovery for the 1,347-byte perk-choice screen at `0x00405be0`.
Live Binary Ninja evidence identifies the complete choice-count policy, menu
layout, function-local static objects, cancel transition, and perk-application
tail.

## Recovered source shape

- renders the paused gameplay world and animated UI panel;
- builds the panel anchor with the native two-float `operator+` idiom and adds
  the `(180, 40)` layout offset through `operator+=`;
- draws the Pick a Perk banner and the Perk Expert/Perk Master sponsor text;
- selects five, six, or seven choices and preserves the native 19/18-pixel
  vertical spacing policy;
- lazily constructs the idle/hover colors and ten menu-item states;
- updates the hovered choice, draws its description, and constructs the unused
  Select button alongside the active Cancel button;
- handles the cancel transition; and
- applies the activated perk, decrements the pending count, and dirties the
  next generated choice list.

## Static-object evidence

The VC6 object relocation table proves the native local-static order and thunk
mapping: `$E2` is the idle color (`0x00406170`), `$E3` the hover color
(`0x00406160`), `$E4` the ten-item array (`0x00406150`), `$E5` the Cancel
button (`0x00406140`), and `$E6` the Select button (`0x00406130`). Live Binary
Ninja disassembly confirms that all five callbacks are single-instruction
empty destructor thunks. `REFERENCE_ALIASES` scopes the guard, objects, and
callbacks to those evidenced native identities.

## Remaining mismatch

The current source produces the same 314 normalized instructions and all 117
references align. It remains an honest 86.94% WIP because the native reserves
a 40-byte frame and coalesces the later Cancel-button position with a dead
two-float/spacing slot, while this natural VC6 reconstruction reserves 36
bytes and assigns that position a fresh slot. Direct scalar construction,
explicit vector copies, named field-value copies, and constructor variants
either retained that four-byte delta or worsened instruction order. No union,
volatile state, fake reference, or artificial register constraint is used to
force the native allocation.

The live Binary Ninja local listing independently confirms the native
40-byte frame and the overlapping two-float local roles. The remaining delta
is therefore classified as compiler allocation residue rather than missing
behavior.

The panel anchor now consumes the recovered `ui_element_t::pos` and
`ui_element_vertex_t::position` aggregates. This type-only cleanup preserves
the same 314 instructions, 86.94% score, and 117 resolved references.
