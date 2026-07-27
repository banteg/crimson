# `quest_build_major_alien_breach`

Native target: `crimsonland.exe` at `0x00437af0` (167 bytes).

Live Binary Ninja evidence shows a paired-spawn quest builder. Each iteration
adds two template `0x20` aliens at `(1088, 512)` and `(512, -64)`, two creatures
per entry. Trigger time starts at 4000 ms, advances by `2000 - acceleration`,
and is clamped to 1000 ms while acceleration rises from 0 to 1485 in steps of
15. The loop emits 200 entries in total.

The recovered source uses an inlined cursor/count builder. Incrementing the
builder count at the start of `add` explains the native's two adjacent count
increments before the second entry is materialized. The VC6 candidate has the
same 48 instructions and scores 95.83%. Its only residuals are the placement of
the loop-counter zeroing relative to two hoisted position constants and the
commutative scheduling of one template store against the trigger-step
subtraction. Both are left visible rather than forced with artificial
dependencies.

`position-lifetime-mutations.json` evaluated three paired-position lifetime
shapes. All three regress, the least by 10.44 fuzzy-weighted bytes, so the
current aggregate form remains the strongest evidenced source.
