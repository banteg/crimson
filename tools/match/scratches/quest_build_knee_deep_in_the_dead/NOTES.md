# `quest_build_knee_deep_in_the_dead`

Native target: `crimsonland.exe` at `0x00434f00` (541 bytes).

Live Binary Ninja evidence recovers an opening template-`0x43` brute at
`(-50, terrain_texture_height * 0.5)`, trigger 100, count 1. The main loop
starts at trigger 500 and wave zero, advances both by 1500 and one
respectively, and continues while the trigger is below `0x178f4`. It produces
245 entries in total.

Every loop iteration adds a template-`0x41` random zombie at the vertical
center. Its count changes from one to two after wave `0x20`. Every eighth wave
first adds another template-`0x43` brute at trigger minus two. Four strictly
greater-than trigger thresholds add escalating flanking entries:

- above `0x30d4`, template `0x41` at center plus 158, trigger plus 500;
- above `0x5fb4`, template `0x41` at center minus 158, trigger plus 1000;
- above `0x8e94`, template `0x42` at center minus 258, trigger plus `0x514`;
- above `0xbd74`, template `0x42` at center plus 258, trigger plus 300.

The native function reloads the integer terrain height and performs the
multiply and optional offset on x87 for every emitted position; it does not
cache a rounded midpoint. Whole-vector construction reproduces each temporary,
and the inlined metadata setter reproduces the native cursor and count update
schedule. Signed `wave % 8` is required for the target's correction sequence,
even though the runtime wave never becomes negative. The opening count is also
the initial logical entry count, explaining the shared `edi` value.

The candidate has the exact 141-instruction length, all 17 audited references,
and scores 95.74%. The complete loop body and backedge match. Its six residual
mismatches are scheduling of independent opening vector work, callee-save
pushes, and the initial trigger load. `while` and `do/while` compile identically;
the simpler decompiler-aligned `while` is retained without artificial ordering
dependencies.
