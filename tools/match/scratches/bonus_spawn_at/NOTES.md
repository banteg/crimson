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
