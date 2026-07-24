# bonus_spawn_at

The native constructor clamps its caller-owned position into the terrain bounds,
returns the sentinel in Rush mode, initializes a caller-selected bonus entry,
and uses the metadata default when the duration override is `-1`.

It then emits the same 16-particle blue pickup burst recovered in
`bonus_try_spawn_on_kill`. The local `effect_color_t` aggregate explains the
four stack constants and the interleaved global stores in the native code.

The recovered source is an exact 128/128-instruction match with all 28 native
references aligned. Keeping the color aggregate in a nested block after entry
initialization reproduces MSVC's native constant-materialization schedule.

The original `Crimson.h` declaration takes `vec2_t &spot`; the lowered matching
boundary therefore uses a mutable `vec2f_t *` and names both components as
`x`/`y`. This is semantically important because the four bounds checks mutate
the caller-owned position. The aggregate recovery leaves the exact score and
all references unchanged. The same prototype is saved in Binary Ninja, whose
HLIL now renders every clamp and initialization through `pos->x`/`pos->y`.

The live xref set contains only `creature_handle_death` at `0x0041e93e`, which
passes the address of the creature's embedded position. Disassembly confirms
that all four bounds clamps at `0x0041f5b8..0x0041f625` precede the Rush-mode
return, so even a suppressed Rush drop moves the corpse. This constructor does
not run the 32-unit spacing scan from `bonus_spawn_at_pos`; it writes the normal
or sentinel allocation directly and still emits the pickup burst when the real
pool is full. The burst's four `crt_rand` callsites are `0x0041f6ed`,
`0x0041f709`, `0x0041f72b`, and `0x0041f74d`.

Both ports now tag those 64 draws explicitly. Zig also restores the native
clamp, no-spacing allocation, `duration_override == -1` test, corpse mutation,
and forced 16-particle burst. Focused regressions cover an out-of-bounds death,
the exact first-particle caller sequence, and the clamp-before-Rush behavior.
