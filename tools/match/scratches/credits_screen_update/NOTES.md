# `credits_screen_update`

Native target: `crimsonland.exe` at `0x0040d800` (1857 bytes).

Live Binary Ninja HLIL/disassembly and the shipped credits port recover the
screen's local-static Back/Secret buttons, 16-line scrolling/fade window,
lowercase-`o` click puzzle, and ten-line secret replacement block.

The source intentionally preserves native behavior that is easy to mistake for
decompiler noise: the scan is lowercase-only, non-matching clicks walk backward
to clear a prior flag, the first nine secret text pointers are replaced without
being freed, and only the final pointer is explicitly freed before replacement.

Verified semantic reconstruction: 98.90%, with the same 454 normalized
instructions as native and all 175 masked references audited. The only
remaining region is the initial panel-anchor construction: native and
candidate compute the same two floats, but VC6 coalesces the intermediate Y
value with a later two-float scratch slot in the binary while this natural
reconstruction reuses the panel Y slot. The related perk screen independently
supports the `operator+` then `operator+=` source idiom used here.

The rest of the function matches instruction-for-instruction, including both
local-static constructors, all scrolling/fade/click logic, the full table scan,
the ten flag writes, the ten text replacements, both buttons, and all three
exit actions. The resettable line index explains the native split between an
EAX flag cursor and an ESI text cursor without register steering.

No union, dead expression, fake reference, volatile state, or register/order
constraint is used to force the remaining stack-slot choice. The fakematch
validator passes.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**98.90%**, 454/454 instructions, prefix 48, and `175/0/0` references. Its
single region at native `0x0040d8d3..0x0040d932` is confined to the initial
panel-vector temporary slot and equivalent x87/add scheduling. The remainder
matches instruction-for-instruction, covering initialization, scrolling,
fades, click flags, all secret-line mutations, both buttons, and exit actions.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
