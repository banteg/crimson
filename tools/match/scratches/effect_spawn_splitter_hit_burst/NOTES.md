# effect_spawn_splitter_hit_burst

Matches all 75 native instructions and all 23 masked references with the
default MSVC 6.5 `/O2 /GB /W3 /GR-` profile.

- configure effect id 0 with flags `0x19`, yellow tint
  `(1.0, 0.9, 0.1, 1.0)`, four-pixel half extents, zero velocity/rotation,
  and scale step `55.0`;
- return immediately when `count <= 0`;
- truncate `radius` to an integer once;
- consume three `rand()` calls per particle for angle, distance, and negative
  starting age;
- choose angle from 512 steps across one turn, choose distance with integer
  remainder, set `lifetime = 0.1 - age`, and spawn effect id 0.

Three source-shape details are decisive. A `remaining` copy of `count` recovers
the native EDI/EBX/ESI allocation. Scaling `angle` in two compound-assignment
statements preserves the separate `1/512` and float-tau multiplications.
Finally, `distance` is `double`: VC6 keeps that value live on the x87 stack
across both `fcos`/`fsin` projections, emits `fmul st(1)` twice, and pops the
preserved value only after the second coordinate.
