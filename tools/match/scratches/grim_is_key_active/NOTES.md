# grim_is_key_active

Native target: `grim.dll` at `0x10006fe0..0x100071a8` (456 bytes).

This is an evidence-backed semantic-complete reconstruction, not an exact
match. Microsoft Visual C++ 6.5 with the stock `/O2 /GB /W3 /GR-` profile
currently reproduces 174 candidate instructions against 175 target
instructions: 73.93% normalized match, 2/175 prefix, and references `7/0/1`.

## Recovered source shape

- IDs at or below `0xff` forward to the raw keyboard-state query.
- `0x100..0x104` forward to mouse buttons `0..4`.
- A twelve-iteration loop maps `0x11f..0x12a` to joystick buttons `0..11`.
- `0x131..0x134` call the up, down, left, and right deadzone helpers.
- Six sparse axis IDs (`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and
  `0x155`) scale the corresponding `DIJOYSTATE2` value by `0.001f`, take its
  absolute value, and test it strictly above `0.5`.
- When the optional input provider exists, `0x16d..0x17b` are split into three
  consecutive groups of five actions and dispatched as `(player, action)`.
- Every other extended ID returns zero.

## Remaining compiler delta

The call targets, constants, conditions, and ID families agree with the live
Binary Ninja evidence. The residual is VC6.5 register allocation and block
layout: the target keeps the key in `edi`, the provider group base in `esi`,
and the player in `ebx`, while this natural source assigns those lifetimes
differently. The target also tail-merges the six identical axis thresholds at
the first branch rather than the last, and retains a separate mapped-ID
increment; the candidate is one instruction shorter. The single conflicting
masked reference is a block-alignment artifact pairing the candidate Rz load
with the target X load; all six exact axis destinations at
`grim_joystick_state + 0x0..0x14` are present in both functions.

Compiler/profile checks do not justify an override: `msvc6.5pp`, `msvc7.0`,
and `/O1` all score materially worse. No inline assembly, volatile shaping,
fake references, forced addresses, or source-level register tricks are used.
There is no unresolved behavior or missing referenced destination, so the
scratch is classified as semantic-complete with a compiler residual.
