# fx_spawn_particle

The fast particle constructor matches the shipped function exactly: 67/67
instructions and all 18 masked references. It confirms the same fixed-pool
scan, random replacement, inline four-float scale copy, wide x87 trig, and
spin initialization recovered independently for the slow constructor.

The third argument is accepted but unused. The final argument is copied
directly into particle intensity, while the slow constructor uses a constant
intensity and initializes Bubblegun-only style and target fields.

The spawn position is recovered as a read-only `vec2f_t` in both source and
Binary Ninja, replacing `pos[0]`/`pos[1]` without changing the exact match.
The destination uses the canonical `particle_t::position` aggregate directly;
that assignment is also byte-for-byte exact.
The recovered byte-sized `particle_t::style_id` is also assigned directly,
removing the stale byte-pointer cast with unchanged codegen.

Callsite evidence also identifies the otherwise-unused third argument as a
read-only movement vector: player fire-cough passes the embedded move delta,
while Pyrokinetic passes a temporary zero vector. Source and the saved Binary
Ninja prototype now preserve that type without changing code generation.
