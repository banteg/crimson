# `quest_build_alien_squads`

Native target: `crimsonland.exe` at `0x00435ea0` (507 bytes).

Live Binary Ninja evidence recovers eight fixed template-`0x12` entries, all
with count 1 and heading left untouched:

- `(-256, 256)` at trigger 1500;
- `(-256, 768)` at trigger 2500;
- `(768, -256)` at trigger 5500;
- `(768, 1280)` at trigger 8500;
- `(1280, 1280)` at trigger 14500;
- `(1280, 768)` at trigger 18500;
- `(-256, 256)` at trigger 25000;
- `(-256, 768)` at trigger 30000.

The remaining 52 entries are 26 paired waves. Starting at trigger 36200 and
advancing by 1800 while the trigger is below 83000, each pair adds a
template-`0x26` spawn at `(-64, -64)` with trigger minus 400, followed by one
at the native fixed corner `(1088, 1088)` with the unadjusted trigger. This is
not derived from the terrain dimensions; recovering the hardcoded corner also
revealed and fixed a port-parity bug separately.

The fixed entries require whole-vector construction plus the shared inlined
metadata setter. Replacing their setters with direct fields makes VC6 batch all
24 metadata stores and drops the score sharply. The loop has the opposite
shape: native emits immediate coordinate stores, and direct metadata fields
preserve template-before-trigger ordering. Using vector constructors there
hoists four constants, saves an extra register, and adds 11 instructions.

The append-count candidate has the exact 108-instruction length and scores
94.44%. The entire repeated loop body matches. Publishing the eight fixed
entries through the same count used by the loop removes nearly half of the
former fixed-prefix gap while preserving the indexed source and native count
register. The remaining differences are independent fixed-entry vector and
metadata scheduling plus the loop cursor adjustment and trigger load.

Binary Ninja now types the repeated-wave cursor as a layout-equivalent
`quest_spawn_pair_binja_t *` presentation view. The loop consequently renders
both entries as `entries[0]` and `entries[1]`, including position, template,
trigger, and count, instead of leaving the second wave behind raw offsets.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices retain VC6 `/O2 /GB`; VC7,
`msvc6.5pp`, and `/G6` regress. A recorded 145-variant fixed-entry sweep
exhausts every single and pairwise choice between setter-before-position and
direct-metadata spellings, plus loop-local order. A five-variant helper-store
sweep covers the remaining setter permutations. None improves the
`455.3611111111111/507` weighted bytes, exact 108 instructions,
ten-instruction prefix, or `0/0/0` references, so the fixed-entry source and
the already exact repeated loop remain unchanged.

## 2026-08-08 append-count improvement

Replacing the eight fixed indices and preseeded loop count with continuous
publication improves the candidate from 89.81% to 94.44% while preserving
108/108 instructions, a ten-instruction prefix, and the exact repeated loop.
The retained source SHA-256 is
`5fec8611109e15b3a8cb11a84792b3e7ac1c71d4e839b907d1fc1c6e0d5aabbd`.
