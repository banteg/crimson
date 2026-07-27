# grim_is_key_active

Native target: `grim.dll` at `0x10006fe0..0x100071a8` (456 bytes).

This is an evidence-backed semantic-complete reconstruction, not an exact
match. Microsoft Visual C++ 6.5 with the stock `/O2 /GB /W3 /GR-` profile
currently reproduces 176 candidate instructions against 175 target
instructions: 79.20% normalized match, 95/175 prefix, and references `7/0/1`.

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
Binary Ninja evidence. A recorded provider-loop sweep found that naming the
exclusive end of each five-key group keeps the input key in native `edi`.
Spelling the same bounded traversal as a `for` over `[base, mapped_end)` then
raised the score from 73.93% to 79.20% and moved the exact prefix from 2 to 95
instructions. This is a semantic source improvement: it directly names the
native three groups of five and retains the recovered `(player, action)`
dispatch.

The residual is block layout and the final loop allocation. The target
tail-merges the six identical axis thresholds at the first branch, while VC6.5
places the candidate common tail after the last branch. The candidate also
keeps the `for` loop's provably nonempty entry check, making it one instruction
longer overall. The single conflicting masked reference is a block-alignment
artifact pairing the candidate Rz load with the target X load; all six exact
axis destinations at `grim_joystick_state + 0x0..0x14` are present in both
functions.

Compiler/profile checks do not justify an override: `msvc6.5pp`, `msvc7.0`,
and `/O1` all score materially worse. No inline assembly, volatile shaping,
fake references, forced addresses, or source-level register tricks are used.
There is no unresolved behavior or missing referenced destination, so the
scratch is classified as semantic-complete with a compiler residual.

## Recorded mutation evidence

The mutation record covers the natural action-count loop, mapped-end loops,
post-tested equivalents, declaration orders, and shared-axis formulations.
The retained `for-mapped-to-end` variant is the only candidate that both
improves fuzzy parity and preserves 95 exact leading instructions. Seven
post-tested refinements either lose that prefix or regress the fuzzy score.
Float `else if` axis selection compiles byte-identically; explicit
float/double/long-double shared-tail and declaration-order variants do not
improve the native layout. These negative results are retained in
`experiments.jsonl`.
