# effect_spawn_ion_hit_sparks

Native target: `crimsonland.exe` at `0x0042f540` (378 bytes).

This emitter scales the impact input by 0.8, seeds a translucent blue shared
template, clamps lifetime to 1.1 seconds, and emits roughly five sparks per
scaled unit. Low detail halves the count. Each spark receives a random full
turn, velocity in a scale-adjusted square, and positive scale growth.

All 86 native instructions and all 31 static references match. Two source-shape
details are visible. The unclamped lifetime remains a local x87 value for the
`> 1.1` test instead of being read back from the shared template. The small
inline detail-count helper adjusts the integer while it is still in EAX; an
early return then delays reserving ESI/EDI until at least one spark will run.

The original `PART_SpawnIonBurst(vec2_t pos, float size)` declaration confirms
the aggregate input. Its lowered source and Binary Ninja boundary now use
`const vec2f_t *`, preserving all 86 instructions and 31 references.
