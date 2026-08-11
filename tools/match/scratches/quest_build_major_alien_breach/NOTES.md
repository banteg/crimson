# `quest_build_major_alien_breach`

Native target: `crimsonland.exe` at `0x00437af0` (167 bytes).

Live Binary Ninja evidence shows a paired-spawn quest builder. Each iteration
adds two template `0x20` aliens at `(1088, 512)` and `(512, -64)`, two creatures
per entry. Trigger time starts at 4000 ms, advances by `2000 - acceleration`,
and is clamped to 1000 ms while acceleration rises from 0 to 1485 in steps of
15. The loop emits 200 entries in total.

The recovered source uses an inlined cursor/count builder. Incrementing the
builder count at the start of `add` explains the native's two adjacent count
increments before the second entry is materialized. Flattening the builder's
nested entry setter into the same four direct field assignments is a
source-equivalent simplification and raises the VC6 candidate from 95.83% to
97.92% (163.52/167 fuzzy-weighted bytes). It retains the exact 48-instruction
body while eliminating the template-store/trigger-step scheduling swap.

The only remaining residual is placement of the loop-counter zeroing relative
to the two hoisted second-position constants. It is left visible rather than
forced with an artificial dependency.

`position-lifetime-mutations.json` evaluated three paired-position lifetime
shapes. All three regress, the least by 10.44 fuzzy-weighted bytes, so the
current aggregate form remains the strongest evidenced source.

`loop-schedule-mutations.json` adds a complete 14-variant sweep over explicit
counter lifetimes, staged `2000 - acceleration` calculations, and every pair
interaction. Stock VC6 canonicalizes all 14 to the same 48 instructions and
97.92% result after the retained flattening. The remaining initialization swap
is therefore a compiler residual, not an unexplored loop-source alternative.

`helper-boundary-mutations.json` evaluates 34 entry-setter/builder-helper
single and pair combinations. Only `direct-entry-stores` improves, by
3.479167 fuzzy-weighted bytes, and is retained; its plan SHA-256 is
`442df867dcd3702c1a6965033a6094f27ceb4089b29d07c79290dd96ed2dfc0d`.
The improved source was then replayed through the three position-lifetime
variants and all 14 loop-schedule variants, with no further gain.
`vector-helper-mutations.json` adds six constructor/assignment shapes; the
three constructor spellings are byte-neutral and explicit assignment operators
regress sharply.

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tie at the retained score; MSVC 7.0
regresses. `/G5`, `/G7`, `/Ox`, and `/Ob1` are byte-neutral against `/GB`,
while `/G6` regresses.

`loop-form-mutations.json` tests equivalent `while` and `do while` spellings
for the 100-iteration paired-spawn loop. Both are byte-neutral at 97.92%,
48/48 instructions, confirming that loop syntax does not move the remaining
counter/constant scheduling swap. The spec SHA-256 is
`1baa6632ca8e7c6e5f29c31a486b0023cd213f2cf6044d9508a65ad99dda9947`.

`one-sided-position-lifetime-mutations.json` isolates the one remaining gap
more narrowly than the earlier paired-position sweep. Hoisting only the first
position falls to 89.58%; hoisting only the second adds an instruction and
falls to 61.86%, regardless of whether the local appears before or after the
trigger variable. None moves just the native loop-counter zeroing. The
complete four-variant result is recorded under spec SHA-256
`50b067d9e5706a3988ff8b5517bda1419273f0c401b37097e4a219a3f350de32`.

## Exact wave counter model

The residual was not a free-standing acceleration lifetime. Expressing the
loop in its quest-domain unit—100 paired waves—and deriving acceleration as
`wave * 15` preserves the same 0 through 1485 sequence. VC6 strength-reduces
that expression back to the native `ESI += 15` induction while scheduling its
zeroing after both hoisted position constants.

Both `wave * 15` and `15 * wave` match all **167/167 bytes** and **48/48
instructions**; the explicit acceleration-counter form reproduces the former
swap. `wave-counter-model-mutations.json` records the comparison. No recovery
or residual override remains.
