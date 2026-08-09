# `grim_is_key_active`

Native target: `grim.dll` at `0x10006fe0..0x100071a8` (456 bytes).

The canonical MSVC 6.5 `/O2 /GB /W3 /GR-` source is exact: 175/175
normalized instructions, prefix 175, and references `13/0/0`.

## Recovered router

- IDs at or below `0xff` forward to the raw keyboard-state query.
- `0x100..0x104` forward to mouse buttons `0..4`.
- A twelve-iteration loop maps `0x11f..0x12a` to joystick buttons `0..11`.
- `0x131..0x134` call the up, down, left, and right deadzone helpers.
- Six sparse axis IDs (`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and
  `0x155`) scale the corresponding `DIJOYSTATE2` value by `0.001f`, take its
  absolute value, and test it strictly above `0.5`.
- When the optional input provider exists, `0x16d..0x17b` are three players'
  five consecutive actions, dispatched as `(player, action)`.
- Every other extended ID returns zero.

## Exact closure

The provider tail is an indexed two-dimensional router, not a separately
maintained base/mapped cursor pair. Expressing its key as
`0x16d + player * 5 + action` lets VC6 strength-reduce the expression to the
native `esi` base and incremented `edx` key while keeping `ebx` as player and
`eax` as action. This moved the candidate from 176 to the native 175
instructions and raised the match from 79.20% to 87.43% without changing the
95-instruction prefix or reference audit.

The remaining native axis CFG keeps the X threshold as the shared x87 tail;
the later axis loads jump backward into it. Explicit semantic labels reproduce
that ownership. Ordering the first five active blocks back toward X makes X
the shared tail, while spelling the final Rz case as a positive branch keeps
its load adjacent to the provider fallthrough. Together those ordinary
control-flow choices close the function at 100% and resolve all 13 references.

## Negative evidence

Earlier bounded sweeps covered mapped-end, action-count, post-tested, scoped
lifetime, declaration-order, direct-switch, shared-scalar, and inline-helper
forms. The former mapped-end loop was the strongest partial because it kept a
95-instruction prefix, but its entry check added one instruction. Direct axis
switches improved aggregate similarity while losing that prefix, and explicit
shared scalar tails changed x87 lifetime. Those variants remain historical
evidence in `experiments.jsonl`; none is retained.

No inline assembly, volatile shaping, fake references, forced addresses,
register forcing, or dummy operations are used.
