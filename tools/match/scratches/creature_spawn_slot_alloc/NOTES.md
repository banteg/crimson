# `creature_spawn_slot_alloc`

Exact 30-byte, 10-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align to the spawn-slot table bounds.

Live Binary Ninja shows ten callsites in `creature_spawn_template`. The helper
walks all 32 24-byte spawn slots, returns the first whose owner pointer is null,
and falls back to index 31 when the table is full. The sentinel therefore
aliases the last valid slot, matching the native's intentionally ambiguous
pool policy.
