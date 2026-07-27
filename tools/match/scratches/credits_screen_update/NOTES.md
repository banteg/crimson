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

## Recorded panel-lifetime bounds

Two complete mutation sweeps now bound the remaining panel-anchor residual.
`panel-anchor-lifetime-mutations.json` tested eight named-anchor, component,
constructor, and chained-add spellings (spec
`e5229aab47a79f2058c1f402d6c1f6500bfdbbf2248ea3faa950011802571bb2`).
`panel-chain-storage-mutations.json` tested eight predeclared-storage and
chained-assignment spellings (spec
`5e70f061b2cb8a72a1d068687f9cbf2a408dc580391f903fd8eebab79c3a029b`).
Neither sweep improved the baseline: the closest alternatives lose 8.18 or
12.27 weighted bytes while retaining the same first mismatch. The complete
results are recorded in `experiments.jsonl`.

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

## Exact-tail audit (2026-07-27)

Live Binary Ninja reconfirmed that the only residual is the initial panel
anchor's temporary slot and equivalent x87 schedule. MSVC 6.5 and 6.6 tie at
the baseline; MSVC 6.0 falls to 88.84%, Processor Pack to 77.75%, and VC7 to
66.15% with reference debt. No tested flag profile is exact.

`hit-position-lifetime-mutations.json` evaluates three early/phase-local
declaration combinations: both complete forms are byte-neutral and the
declaration-removal-only form correctly fails compilation.
`panel-declaration-order-mutations.json` evaluates four predeclaration orders:
predeclaring only the real position is byte-neutral; the three panel-first
forms fall to 88.84% and introduce one reference mismatch. The recorded
`predeclared-panel-position-confirmation` probe is neutral. No source change
was retained; baseline and final remain **98.90%**, 454/454, prefix 48,
`175/0/0`.

`copy-constructor-interactions.json` records 14 explicit-copy and position
initialization combinations (spec
`27033728b3916334b2c876ed3088221a26c95f161e3c82133bb31297d3ba8e79`).
Direct initialization and default-plus-aggregate assignment are byte-neutral.
An explicit user copy constructor or component-wise position construction
removes six instructions, moves the first mismatch to the prologue, and falls
to 73.61%. The implicit copy source therefore remains the best evidenced
shape.

`vector-operator-shape-mutations.json` adds six return, parameter, constness,
and `operator+=` variants. Non-const `operator+`, a void `operator+=`, and a
by-value `operator+=` are byte-identical at 98.90%. Naming the returned vector
adds six instructions and loses 186.78 weighted bytes; taking the operand by
value adds four instructions and loses 187.24. None induces the native panel-Y
temporary slot, so the canonical operators remain unchanged.
