# `fx_queue_add_rotated`

Exact 210-byte, 55-instruction match with MSVC 6.5 `/O2 /GB`; all 18
candidate references resolve to the native data objects without a mismatch.

The helper returns a byte boolean. A queue count of 63 is the full sentinel and
returns false. Otherwise it copies a `vec2f_t` position and an
`effect_color_t` aggregate into parallel 64-entry arrays, stores rotation,
scale, and effect id, then increments the count. The defensive post-increment
clamp also writes 63 if the count reaches 64.

The alpha adjustment is `alpha *= 0.8f` when
`cv_terrainBodiesTransparency` is zero and `alpha *= 1.0f / value` otherwise.
When `terrain_texture_failed` is set, native skips the queue entirely but still
returns true; the Python port now preserves that successful no-op behavior.

Directly indexing the arrays with the global `fx_queue_rotated` count is
material source-shape evidence. A semantically cleaner local copy produces the
same 55 instructions but swaps `ECX` and `EDX` throughout; the direct-global
form matches every byte and reflects the native count load/store sequence.
