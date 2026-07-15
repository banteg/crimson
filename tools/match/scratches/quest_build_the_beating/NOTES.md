# `quest_build_the_beating`

Native target: `crimsonland.exe` at `0x00435610` (649 bytes).

Live Binary Ninja evidence recovers 31 entries in seven phases:

- one template `0x27` bonus at (256, 256), trigger 500 ms, count 1;
- one template `0x29` brute at `(width + 32, height / 2)`, trigger 8000 ms,
  count 3;
- eight template `0x25` waves at `(width + x, height / 2)`, where `x` starts
  at 64 and advances by 32, triggers start at 10000 ms and advance by 100 ms,
  and every count is 8;
- one template `0x29` brute at `(-32, height / 2)`, trigger 18000 ms, count 3;
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
audited global references, scoring 53.61% with a 22-instruction exact prefix.
The residual is VC6 scheduling and register allocation: native keeps the entry
base in ESI, trigger time in EBX, and the coordinate offset in EDI; advances a
cursor before storing through negative offsets; and waits to write metadata
until both coordinates are converted. The candidate assigns trigger time to
EDI and the offset to EBX, hoists metadata into conversion gaps, and uses the
direct cursor address.

Direct metadata fields, a combined position-and-metadata setter, a preincrement
cursor, and reversed local declaration order were all tested and scored worse
or failed to improve this shape. No artificial dependencies, volatile state,
or register-forcing constructs are used.
