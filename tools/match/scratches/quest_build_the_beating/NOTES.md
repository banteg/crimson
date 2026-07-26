# `quest_build_the_beating`

Native target: `crimsonland.exe` at `0x00435610` (649 bytes).

Live Binary Ninja evidence recovers 31 entries in seven phases:

- one template `0x27` bonus at (256, 256), trigger 500 ms, count 1;
- one template `0x29` AlienBigGray at `(width + 32, height / 2)`, trigger 8000 ms,
  count 3;
- eight template `0x25` waves at `(width + x, height / 2)`, where `x` starts
  at 64 and advances by 32, triggers start at 10000 ms and advance by 100 ms,
  and every count is 8;
- one template `0x29` AlienBigGray at `(-32, height / 2)`, trigger 18000 ms, count 3;
- eight template `0x25` waves at `(x, height / 2)`, where `x` runs from -64
  through -288 by -32, triggers start at 20000 ms and advance by 100 ms, and
  every count is 8;
- six template `0x0f` waves at `(width / 2, y)`, where `y` runs from -64
  through -274 by -42, triggers start at 40000 ms and advance by 100 ms, and
  every count is 4;
- six template `0x12` rings at `(width / 2, width + 44 + y_offset)`, where
  `y_offset` starts at 0 and advances by 32, triggers run from 40000 through
  40500 ms, and every count is 2.

The final phase deliberately derives both coordinates from terrain width. This
native detail also corrected the Zig quest port, whose prior y coordinate used
height and only happened to agree on square maps. Heading remains untouched.

The candidate represents all 166 native instructions and resolves all seven
audited global references. The residual is VC6 scheduling and register
allocation: native keeps the entry base in ESI, trigger time in EBX, and the
coordinate offset in EDI; advances a cursor before storing through negative
offsets; and waits to write metadata until both coordinates are converted.
No artificial dependencies, volatile state, or register-forcing constructs
are used.

The opening eight-entry walk now advances its X offset immediately after
constructing the current position and before storing spawn metadata. Live
Binary Ninja shows the same update between the coordinate calculation and the
template/trigger/count stores. This source order preserves offsets 64 through
288 and triggers 10000 through 10700 while improving the exact prefix from 22
to 37 instructions and the match from 53.61% to 54.82%.

All four repeated walks now also advance the entry cursor before writing the
current entry's metadata, then address that just-completed entry as
`spawn[-1]`. This is the native dataflow: the first walk advances ECX at
`0x004356b3` before coordinate stores at `0x004356de..0x004356e9` and metadata
stores at `0x004356ec..0x004356f6`; the later walks repeat that shape at
`0x0043577a`, `0x004357dd`, and `0x00435838`. Using direct fields after the
cursor advance improves the match from 54.82% to 68.07%, raises weighted
matched bytes from 356 to 442, and reduces the weighted gap from 293.2229 to
207.2108 bytes while preserving the 37-instruction prefix, exact 166/166
instruction count, and `7/0/0` references.

The combined cursor/dataflow recovery is material: applying it only to the
first walk reached 56.02% but temporarily aligned only six references.
Retaining the helper call after advancing the cursor regressed to 26.19% with
170 instructions, a one-instruction prefix, and `2/0/1` references. Introducing
a separate current-entry pointer or reference also emitted 170 instructions
and regressed to 43.45%, so those variants were rejected.

Recovery is classified `semantic-complete` with a `compiler` residual.
