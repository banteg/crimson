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
