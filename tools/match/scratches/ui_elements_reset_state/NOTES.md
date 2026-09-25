# `ui_elements_reset_state`

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Exact 31-byte, 10-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align.

Live Binary Ninja shows this is called at the start of `game_state_set`. It
walks all 41 pointers in the table at `0x0048f168`, clearing only each
element's `active` byte and `hover_amount` at offset `0x2f8`. It does not clear
callbacks or the rest of the element, correcting the previous map comment.

The table ends immediately before the separately stored perk-prompt element at
`0x0048f20c`; that object is not included in this reset. The Python screens own
fresh per-view activity/hover state and already reset it on construction, so no
shared runtime reset was missing.
