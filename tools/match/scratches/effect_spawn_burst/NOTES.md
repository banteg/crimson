# effect_spawn_burst

Native target: `crimsonland.exe` at `0x0042ef60` (282 bytes).

This generic burst seeds the shared effect template with flags `0x1d`, a
half-second lifetime, 32-pixel half extents, and translucent blue color
`{0.4, 0.5, 1.0, 0.5}`. For each requested particle it chooses rotation from
128 evenly spaced circle steps, independent masked velocity components in
`[-64, 63]`, and a scale step from `0.10` through `1.09`, then spawns effect
ID zero at the supplied position. Nonpositive counts do not spawn.

The source, shared gameplay declaration, and saved Binary Ninja prototype now
carry that position as `const vec2f_t *`. All native callers pass embedded
two-float positions through the same aggregate boundary; the exact 61/61 code
and 21 references are unchanged.

The particle loop now writes the shared template through its canonical
`velocity` and `half_extent` aggregates. The exact 61/61 instructions and
21/0/0 references are unchanged.
