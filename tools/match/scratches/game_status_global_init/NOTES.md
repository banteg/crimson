# `game_status_global_init`

Native target: `crimsonland.exe` at `0x004122a0` (171 bytes).

This CRT global initializer zeros the four mode counters and sequence id,
clears status-counter regions, resets both quest unlock words, and fills the
four 32-bit reserved tail words from `crt_rand() % 345354345`.

Live Binary Ninja xrefs prove that the two 50-byte clears begin at
`quest_play_counts[11]` and `[51]`. The 256-byte clear begins at the 53-slot
weapon counter table and consequently overlaps quest slots `[0..10]`. These
odd byte counts are preserved as literal native source behavior: the routine
runs once over zero-initialized storage, so the untouched bytes start clear as
well. No wider reset or inferred safety correction is substituted.

No dummy references, inline assembly, volatile ordering constraints, or dead
expressions are used.
