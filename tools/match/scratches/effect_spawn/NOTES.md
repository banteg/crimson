# `effect_spawn`

Native target: `crimsonland.exe` at `0x0042e120` (1507 bytes).

Live Binary Ninja evidence recovers the low-detail throttle, free-list
allocation policy, effect-template copy, and all four atlas-size quad builders.
The throttle increments `effect_spawn_detail_skip_counter` and rejects every
other spawn at detail presets 0-2. Exhausting the free list selects the same
zero-initialized `effect_discard_entry` at `0x004ab270`.

The four atlas paths use 16x16, 8x8, 4x4, and 2x2 UV tables. Their repeated
instruction shape is explained by `table[frame] + vec2(offset_x, offset_y)`;
the `(step, step)` case also accounts for the target's third stack temporary.

Verified with MSVC 6.5 `/O2 /GB`: 350/350 instructions, 1507 bytes, and all
90 masked references audited.

The recovered original `Crimson.h` names this lineage as
`PART_Spawn(int ptype, vec2_t pos)`, proving that the two input floats form one
position vector. The exact scratch and saved Binary Ninja prototype now expose
that lowered argument as a read-only vector pointer and render `pos->x` and
`pos->y`, while remaining exact. Compiling the available reconstructed vector
class directly by value changes VC6 alias analysis, loses one instruction, and
falls to 61.23%; that probe is rejected rather than presented as the original
class semantics.
