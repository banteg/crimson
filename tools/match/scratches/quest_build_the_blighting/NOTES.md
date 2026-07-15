# `quest_build_the_blighting`

Native target: `crimsonland.exe` at `0x00438050` (624 bytes).

Live Binary Ninja evidence recovers a six-entry prefix. Two template-`0x2b`
red aliens arrive at trigger 1500/count two: the first at
`(terrain_texture_width + 128, terrain_texture_width / 2)`, the second at
`(-128, terrain_texture_width / 2)`. Four template-`0x07` spawners then occupy
the fixed corners `(896, 128)`, `(128, 128)`, `(128, 896)`, and `(896, 896)`,
all at trigger 2000/count one.

The eight-wave loop starts with six emitted entries and trigger 4000. Waves two
and four add a template-`0x2b` count-four entry at the wide left edge. Waves
three and five add the corresponding right entry at the native hardcoded x
coordinate 1152; only its y midpoint is terrain-derived. These constants
revealed and fixed a Zig corner bug and a Python/Zig optional-right bug in a
separate parity commit.

Signed `wave % 2` alternates the main template between `0x1a` and `0x1c`.
Signed `wave % 5` selects right, left, bottom, or top for remainders zero
through three; remainder four emits no main entry. Each recognized layout adds
15000 to the trigger, followed by a universal 1000 increment. The builder emits
seventeen entries total.

The indexed fixed prefix followed by a cursor/count builder reproduces the
native register roles and exact loop. Assigning fixed-corner y before x is a
decisive source clue: it recovers the target's 128-before-896 constant loads and
raises the score from 90%. Moving loop declarations permits VC6 to hoist the
cursor adjustment across the fixed table and is therefore ruled out.

The candidate has the exact 190-instruction length, all 11 audited references,
and scores 94.74%. The complete optional-wave, parity, layout, timing, count,
and backedge body matches. Its ten residual mismatches are independent VC6
schedules within the fixed prefix and loop initialization; no artificial
dependencies or register forcing are used.
