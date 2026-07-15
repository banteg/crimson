# effect_spawn_shrinkifier_hit

Native target: `crimsonland.exe` at `0x0042f080` (482 bytes).

The impact emits one contracting 36-pixel blue-green core pulse, then four
translucent blue debris particles (two below detail preset 3). Debris uses a
random full-turn rotation, independent velocity components in [-89.6, 88.2],
and positive scale growth from 0.10 through 1.09.

All 92 native instructions and all 38 static references match. The same inline
detail-count helper recovered in `effect_spawn_ion_hit_sparks` is decisive
here: starting from four, it halves the count below preset 3 and preserves the
native positive-count guard before entering the debris loop.
