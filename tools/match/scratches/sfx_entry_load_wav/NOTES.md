# sfx_entry_load_wav

Reads a packed or standalone WAV resource into temporary storage, parses it into
the entry, frees the temporary bytes on both parse outcomes, then creates the 16
resident DirectSound voices. The return value is normalized to boolean.

Exact 44/44-instruction match with all five native references aligned.

## 1.9.8 (C2 9044)

Exact through translation-unit context: 9044 reuses what it learned compiling
earlier functions of the unit, so the resource reader that precedes this
function in 1.9.8 (`resource_open_read`, or `resource_read_alloc` for the WAV
loader) lets the size or entry stay in a callee-saved register across the
calls. The guarded copy of that body is the same mechanism as
`projectile_update`'s; 1.9.93 (8966) is unaffected.
