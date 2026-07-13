# input_primary_is_down

Native target: `crimsonland.exe` at `0x004460f0..0x0044613a` (74 bytes),
cdecl `int()`.

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 24/24
normalized instructions, full prefix, and masked references `5/0/0`.
The explicit end is needed because the manifest's provisional extent includes
the alignment gap before the next function.

## Recovered source shape

- The function first calls vtable slot `0x58`,
  `grim_is_mouse_button_down(0)`. A nonzero result immediately returns one.
- Otherwise it calls vtable slot `0x80`, `grim_is_key_active`, with
  `player_state_table[0].input.fire_key` and then
  `player_state_table[1].input.fire_key`. Either nonzero byte returns one.
- If all three tests are false, the function returns zero. It does not read a
  player count, update an edge latch, or mutate any other state.
- The second native record doubles as the alternate keyboard binding in a
  one-player configuration. Structurally, however, both references are the
  same `fire_key` field at the two 0x360-byte player-record strides.
- Binary Ninja reports three callers: `ui_segmented_slider_update` and two
  sites in `ui_scrollbar_update`, consistent with a held-state drag predicate.

## Port relationship

The Python `_input_primary_any_down` helper accepts a clamped one-to-four
player count and checks only that many supplied fire codes. Its public
`input_primary_is_down` wrapper also updates the shared pressed-state tracker.
Those are useful port extensions, but they are not the literal native source
shape recovered here: the executable always checks its two fixed records and
this held-state helper is pure.

No inline assembly, volatile state, fake extern, dummy reference, forced
address, or layout-only control flow is used.
