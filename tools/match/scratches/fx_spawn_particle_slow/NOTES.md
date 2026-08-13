# fx_spawn_particle_slow

The fixed-pool scan, random replacement on exhaustion, inline four-float
scale copy, x87 trigonometry, particle initialization, and both RNG uses match
the shipped function exactly. All 19 masked references resolve to the intended
pool fields, constants, and `crt_rand` call.

Recovering the native arithmetic also exposed a port mismatch: the Python and
Zig implementations rounded `cos` and `sin` before multiplying by particle
speed. Native keeps each trigonometric result wide through the PC=24 multiply
and rounds only on the particle velocity store. The corresponding port fix
also canonicalizes the Python spawn inputs and spin multiplication as f32.

The spawn position is recovered as a read-only `vec2f_t` in both source and
Binary Ninja, replacing `pos[0]`/`pos[1]` without changing the exact match.
The destination uses the canonical `particle_t::position` aggregate directly;
that assignment is also byte-for-byte exact.
The recovered byte-sized `particle_t::style_id` is also assigned directly,
removing the stale byte-pointer cast with unchanged codegen.

The destination velocity stores now use the canonical `particle_t::velocity`
components as well. The constructor remains exact at 67/67 instructions and
19/0/0 references.

The native call contract includes a third `const vec2f_t *unused` parameter.
Its sole call at `player_update+0x34b8` (`0x00417458`) first pushes
`&player->movement` and cleans 12 bytes after the call. The callee reads only
the position and angle, so naming the recovered trailing parameter `unused`
preserves the exact behavior. The name map and both scratches now agree on
this three-argument signature; the callee remains exact at 67/67 instructions
and 19/0/0 references.
