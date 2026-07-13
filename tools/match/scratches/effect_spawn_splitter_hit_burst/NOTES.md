# effect_spawn_splitter_hit_burst

Work in progress. The current source recovers the native behavior without
pretending that compiler shape is exact:

- configure effect id 0 with flags `0x19`, yellow tint
  `(1.0, 0.9, 0.1, 1.0)`, four-pixel half extents, zero velocity/rotation,
  and scale step `55.0`;
- return immediately when `count <= 0`;
- truncate `radius` to an integer once;
- consume three `rand()` calls per particle for angle, distance, and negative
  starting age;
- choose angle from 512 steps across one turn, choose distance with integer
  remainder, set `lifetime = 0.1 - age`, and spawn effect id 0.

The remaining delta is compiler/source shape: register allocation, the x87
distance value kept across `fcos`/`fsin`, and the native two-multiply angle
expression. The native constants are separately loaded `1/512` and float tau;
the current build folds them into one constant. Those differences remain
visible in the dashboard and must not be hidden with fake externs or volatile
padding.
