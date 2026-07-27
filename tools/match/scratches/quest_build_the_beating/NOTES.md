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

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at the
68.07228915662651% baseline; MSVC 7.0 regressed to 44.64% with references
5/1/0. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tied, while `/G6` regressed.

`fixed-position-store-mutations.json` (SHA-256
`fbea9d4516b925edd0ff05344e55e6f42503a675c57c78322adc714460542854`)
recorded seven variants. The retained `left-big-alien-position/direct-fields`
variant spells the fixed entry-ten position as direct x/y stores, matching
the native scalar-store shape without changing the quest entry. The analogous
right-side change improved less but shortened the prefix, and combining both
regressed below baseline; neither was retained.

Fresh scratch recomputation improved 441.78915662650604/649 to
478.8353658536585/649 weighted bytes: 68.07228915662651% to
73.78048780487805%, with the gap falling from 207.21084337349396 to
170.16463414634148. The validated result has 162/166 instructions, preserves
the 37-instruction prefix, and preserves references 7/0/0.

## First-line cursor/offset ordering audit

Live native disassembly advances both the entry cursor and x offset inside the
first coordinate-conversion window. `first-line-advance-order-mutations.json`
(SHA-256 `df2bdeabb596459e7475753725fff7e720e9d199df7c6aac99f89d207fbf09c8`)
tested the remaining cursor-before-offset source order. VC6 emitted identical
bytes, so the canonical smaller ordering and 73.7805% score remain unchanged.
