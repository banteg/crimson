# quest_build_spider_wave_syndrome

Native target: `crimsonland.exe` at `0x00436440` (96 bytes).

Recovered Tier 1 Quest 7's loop policy: 18 left-edge spider waves from 1500
through 95000 ms in 5500 ms steps, at `(-64, terrain_width / 2)`, using spawn
template `0x40` and `player_count * 2 + 6` creatures per wave.

The count-bearing local builder is the simplest source-shaped model found that
preserves the native independent base, entry-index, and trigger-time induction
variables. Native writes the fixed template and trigger before loading the
dynamic configured-player count. A two-argument metadata setter followed by a
separate count assignment recovers that distinction, matching the source shape
also evidenced in `quest_build_nesting_grounds`.

The candidate produces the same 31 instructions, resolves both audited global
references, and raises the match from 80.65% to 83.87%. The residual is
independent scheduling around the signed terrain-width conversion and loop
increments; the recovered loop, constants, arithmetic, record stride, and
output count agree. It remains a WIP, with no volatile state, dummy dependency,
or forced register/address construct.
