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

The fixed prefix and loop now publish every entry through one continuous append
count. Assigning fixed-corner y before x remains a decisive source clue: it
recovers the target's 128-before-896 constant loads. Keeping the count-one value
live across the four corner entries and exposing the third and sixth metadata
stores directly recovers the native fixed-prefix schedule.

Removing the synthetic cursor/count builder exposes the original-style indexed
append path throughout the loop. Declaring the trigger before the wave counter
then reproduces the native initialization order (`count`, trigger, spilled wave,
cursor advance). The candidate is exact: 190/190 instructions, 624/624 bytes,
and all 11 audited references resolved. No artificial dependency or register
forcing is used.

## Recorded prefix-lifetime search

`prefix-lifetime-mutations.json` exhaustively evaluated 53 single and pair
combinations over the two terrain-derived prefix entries, template lifetime,
direct metadata stores, and loop initialization order. Several natural forms
are byte-neutral, including direct first-entry metadata and a split trigger
assignment. The complete matrix is recorded in `experiments.jsonl` (spec
`a24eba9ef1efe6187cd7f486b0bc0dbcb48db7354fd80776e7bf5fb5bb3c32eb`).

## 2026-08-08 append-count recovery

Publishing the six fixed entries through an append count, preserving the
count-one lifetime, and ordering the loop declarations as wave, trigger, then
builder improves the match from 94.74% to 99.47% and the exact prefix from 17
to 62 instructions. Reusing that same count directly in the loop removes the
builder boundary; ordering the remaining declarations as trigger then wave
matches all 624 bytes exactly.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native, all masked references resolved, and all
bytes equal. Classification: `RECOVERY=semantic-complete`.
