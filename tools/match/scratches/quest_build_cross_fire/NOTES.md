# `quest_build_cross_fire`

Native target: `crimsonland.exe` at `0x00435480` (390 bytes).

Live Binary Ninja evidence recovers seven fixed entries. Template `0x40`
spiders appear at `(1074, height * 0.5)` at 100 ms and at `(512, 1152)` and
`(512, -128)` at 26000 ms, all count six. Template `0x3c` spiders appear at
`(-40, 512)` at 5500/count four and 15500/count six, then at `(-100, 512)`
at 25500/count eight. A template `0x01` splitter occupies `(512, 512)` at
18500 ms/count two. The lower `(512, 1152)` coordinate is a hard-coded native
constant, not a map-size-derived bottom edge.

Whole-vector construction reproduces the native reusable eight-byte temporary,
the height-to-x87 conversion, shared registers for 512, template `0x3c`,
template `0x40`, trigger 26000, and count six, plus the exact entry offsets and
epilogue. One continuous append count owns all seven entries. Constructing the
following position between the current template and trigger/count publication
reproduces the native overlap at the three relevant boundaries.

The candidate is exact: 76/76 instructions, 390/390 bytes, and both references
resolved. No artificial dependencies or register forcing are used.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all bytes match. Classification:
`RECOVERY=semantic-complete`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed all seven fixed entries, the height-derived
first y coordinate, and the hardcoded 1152/-128 vertical extremes. MSVC 6.0,
6.5, 6.5 Processor Pack, and 6.6 tie at 81.57894736842105%; 7.0 falls to
57.89473684210527% and loses one matched reference. `/GB`, `/G5`, `/G7`,
`/Ox`, and `/Ob1` tie, while `/G6` reproduces that regression.

`fixed-entry-sibling-shape-mutations.json` (SHA-256
`5f8ced5e63fb8317a96c1ec0bfab21ac9d857bf2171acf887640fe364b17ed87`)
recorded thirteen variants. Entry-zero direct metadata is byte-neutral;
every helper-order, other metadata, or direct-position variant regresses by
4.06 to 49.37 weighted bytes, often shortening the prefix or removing the
native vector temporary. No source change is retained. Validation remains
318.1578947368421/390 weighted bytes, a 71.84210526315792 gap, 76/76
instructions, prefix ten, and references 2/0/0.

## 2026-08-08 first-entry publication pass

Publishing the first entry through a trigger-field cursor preserves the exact
seven-entry table while changing the lifetime of its initial metadata owner.
That single source-level boundary moves the first mismatch from instruction 10
to instruction 24 and raises the score from 81.58% to 93.42%, with the native
76/76 instruction count and 2/0/0 references unchanged. The residual is now
three localized independent-store schedules: entry-one metadata against the
next vector temporary, then two template stores against the following x
coordinate construction.

## 2026-08-08 append and publication-boundary recovery

Replacing the fixed indices and output literal with one continuous append
count raises the retained candidate from 93.42% to 94.74%. The remaining three
regions all have the same source shape: native publishes the current template,
constructs the following position, then publishes the current trigger and
count.

Naming those three following positions at that boundary recovers each overlap
in turn, first reaching 97.37% and then matching all 390 bytes exactly. The
final source retains the aggregate temporaries and semantic table order while
making the original publication boundaries explicit.
