# `quest_build_lizard_zombie_pact`

Native target: `crimsonland.exe` at `0x00438700` (311 bytes).

Live Binary Ninja evidence recovers sixteen paired template `0x41` zombie
waves from the right and left edge midpoints. Triggers begin at 1500 ms,
advance by 7000 ms, and stop before 113500 ms; each edge entry has count six.
On waves 0, 5, 10, and 15, the quest also adds two template `0x0c` alien
spawners at x 356. Their y coordinates are `wave / 5 * 180 + 256` and
`wave / 5 * 180 + 384`, with counts `wave / 5 + 1` and `wave / 5 + 2`.
The final count is 40.

The candidate preserves the native pointer-plus-count builder, signed width
halving, x87 integer-to-float conversions, 24-byte entry stride, signed
division for the five-wave predicate, separately lowered quotient for the
spawner group, loop arithmetic, and output count. It compiles to the same 95
instructions and resolves all three constant references.

The residual is a VC6 register-allocation cycle: native keeps the entry base in
EBP, wave in EDI, and trigger in EBX, while the candidate assigns those values
to EBX, EBP, and EDI. Independent metadata stores are consequently scheduled
around the x87 conversions differently. Pointer aliases, declaration and loop
forms, explicit quotient/remainder locals, direct y expressions, vector
setters, reversed builder fields, raw pointer/count storage, `msvc6.5pp`,
`msvc6.6`, `msvc7.0`, and `/G6` were checked. The exact-length default-profile
candidate remains an honest WIP without volatile state, dummy dependencies, or
forced-register constructs.
