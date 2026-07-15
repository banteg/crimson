# `quest_build_frontline_assault`

Native target: `crimsonland.exe` at `0x00437e10` (285 bytes).

Live Binary Ninja evidence recovers waves 2 through 21. Every wave emits a
bottom-center alien at `(terrain_width / 2, 1088)`. Waves 2-4 use template
`0x26`, waves 5-9 use `0x1a`, and later waves return to `0x26`. Waves above
four add a template `0x26` alien at `(-64, -64)`; waves above ten also add one
at `(1088, -64)`. Wave ten uniquely adds two template `0x29` brutes at the
right and left edge midpoints. All counts are one.

Each wave trigger is `wave * step - 5000`. The step starts at 2500, decreases
by 50, and clamps to 1800. The special wave-ten trigger retains the native
spelling `(step * 5 - 2500) * 2`. The result contains 50 entries.

The candidate preserves the native cursor/count/step/wave registers, signed
terrain halving, conditional entry policy, trigger arithmetic, clamp, and
output count. It resolves the terrain-width reference and emits 81
instructions against the native 84, scoring 75.15%.

The residual is legitimate VC6 simplification and scheduling. The candidate
merges the pale/blue/pale template ladder into one range test, folds the two
wave-ten count increments into `+= 2`, and schedules the constant bottom y
store before the x87 conversion. `pos.set(x, y)` and `msvc6.5pp` do not improve
the result. Dummy dependencies or semantically distinct fake template values
are not used to preserve the native control-flow spelling.
