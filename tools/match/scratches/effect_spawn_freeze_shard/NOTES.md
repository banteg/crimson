# effect_spawn_freeze_shard

Native target: `crimsonland.exe` at `0x0042ec80` (376 bytes).

This helper configures one fast receding ice shard in the shared effect
template. It turns the supplied direction by pi, randomizes lifetime, size,
sprite id, visual rotation, angular velocity, and shrink rate, then launches
the shard at speed 114 along the turned direction.

The ordinary source matches all 81 native instructions and all 33 static
references. Statement order is observable: assigning randomized lifetime
before clearing age lets VC6 schedule the age and 8-pixel extent stores around
the integer-to-float conversion exactly as native.

The original `PART_SpawnIceBurst(vec2_t pos, float angle)` declaration confirms
the aggregate input. Its lowered shared declaration, source, and Binary Ninja
prototype now use `const vec2f_t *`, preserving the exact match.
