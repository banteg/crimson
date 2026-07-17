# quest_build_zombie_time WIP

Native target: `crimsonland.exe` at `0x00437d70` (152 bytes).

The builder emits paired zombie waves just outside the right and left arena
edges every eight seconds, from 1.5 through 89.5 seconds. Each wave contains
eight random zombies; the native intentionally leaves heading untouched.

The native keeps the output base in `EBX` and the logical entry count in `ESI`,
recomputing each 24-byte record address instead of strength-reducing the loop
to a moving pointer. Modeling the same `{spawns, count}` builder abstraction
used by neighboring quest constructors recovers that allocation, raises the
prefix from 1 to 16 instructions, resolves another aligned reference, and
improves the score from 60.00% to 82.00%. The candidate still has the exact
50-instruction length, now with references `3/0/0`.

The remaining nine ordering differences are VC6 scheduling of independent
template/time/count stores around the two integer-to-float y conversions and
the loop increment. The natural inlined entry setter produces the same
schedule, so no artificial dependencies or volatile fields are used to move
those stores.
