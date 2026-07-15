# `quest_build_two_fronts`

Native target: `crimsonland.exe` at `0x00436ee0` (383 bytes).

Live Binary Ninja evidence recovers forty waves of paired edge spawns. Each
wave emits template `0x1a` from `(width + 64, width / 2)` at
`wave * 2000 + 1000` ms and template `0x1b` from `(-64, width / 2)` at
`(wave * 5 + 5) * 400` ms. Waves ten and twenty add template `0x0a` at
`(256, 256)` and template `0x07` at `(768, 768)`, both at
`wave * 2000 + 2500` ms. Wave thirty adds the same templates at `(768, 256)`
and `(256, 768)` at 62500 ms. Every entry has count one, and the final table
contains 86 entries.

The exact source shape uses a cursor/count builder, scalar writes for the two
dynamic edge positions, whole-vector construction for the four fixed special
entries, and a two-field metadata setter followed by an explicit entry count.
For the wave-ten/twenty pair, the first cursor advances before its builder
count; that count advances after the second vector is formed and before its
metadata is written. This reproduces the native temporary layout and store
schedule without an artificial dependency.

The default VC6 profile matches all 112 instructions, the full 112-instruction
prefix, all three references, and the 383-byte function exactly.
