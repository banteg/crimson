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
