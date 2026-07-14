# effect_spawn_burst

Native target: `crimsonland.exe` at `0x0042ef60` (282 bytes).

This generic burst seeds the shared effect template with flags `0x1d`, a
half-second lifetime, 32-pixel half extents, and translucent blue color
`{0.4, 0.5, 1.0, 0.5}`. For each requested particle it chooses rotation from
128 evenly spaced circle steps, independent masked velocity components in
`[-64, 63]`, and a scale step from `0.10` through `1.09`, then spawns effect
ID zero at the supplied position. Nonpositive counts do not spawn.
