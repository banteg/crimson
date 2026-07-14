# quest_build_spider_wave_syndrome

Native target: `crimsonland.exe` at `0x00436440` (96 bytes).

Recovered Tier 1 Quest 7's loop policy: 18 left-edge spider waves from 1500
through 95000 ms in 5500 ms steps, at `(-64, terrain_width / 2)`, using spawn
template `0x40` and `player_count * 2 + 6` creatures per wave.

The count-bearing local builder is the simplest source-shaped model found that
preserves the native independent base, entry-index, and trigger-time induction
variables. It produces the same 31 instructions, a 17-instruction exact prefix,
references `1/0/0`, and scores 80.65%. The residual is instruction scheduling
inside the inlined entry setter; the recovered loop, constants, arithmetic,
record stride, and output count agree. It remains a WIP, with no volatile state,
dummy dependency, or forced register/address construct.
