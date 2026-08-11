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

The fixed entries require whole-vector construction. After the append-count
recovery, alternating metadata boundaries reproduce the native schedule:
entries zero, two, four, and six use direct fields, while the intervening
entries retain the shared inlined setter. Replacing all setters at once makes
VC6 batch the metadata stores and drops the score sharply. The loop has the
opposite shape: immediate coordinate and metadata fields preserve its exact
template-before-trigger ordering.

The candidate has the exact 108-instruction length and scores 99.07% with an
83-instruction exact prefix. The fixed table and loop setup now match. The
sole residual is one independent body swap: native stores the first wave's two
coordinates before computing trigger minus 400, while VC6 emits the `lea`
first.

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

## 2026-08-08 alternating-metadata improvement

Replaying fixed-entry metadata shapes after the append-count change exposes a
new interaction. Direct metadata on alternating entries zero, two, four, and
six improves the score from 94.44% to 99.07% and extends the exact prefix from
10 to 80 instructions while preserving the exact 108-instruction body. The
retained source SHA-256 is
`b404a7f4e5698f1d956b6c19d8278f655068ad23be5653838531e73d5e8dcea6`.

## 2026-08-09 synchronized-cursor improvement

Keeping a cursor for the first entry of each repeated pair while retaining the
publication count for the second entry reproduces the native setup order:
count 8, cursor advance, then trigger 36200. This preserves 99.07%, 108/108
instructions, and `0/0/0` references while extending the exact prefix from 80
to 83 instructions. Direct cursor increments and fully cursor-owned pairs
regress register allocation or let VC6 fold the final count to 60, so only the
synchronized first-entry cursor is retained. Scoped references, named scalar
coordinates, fluent setters, and `for`-header lifetimes are byte-neutral;
splitting position and metadata ownership or rebasing indexed publication
regresses. The retained source SHA-256 is
`7c29de20218b87fc3d6a2a6fbb55347c66b9f704264800711438fa7ad1e38052`.

## 2026-08-11 repeated-pair position ownership bound

Live native disassembly confirms the sole residual begins where the first
repeated pair publishes `(-64, -64)` before computing `trigger - 400`; the
candidate schedules that independent `lea` first. The complete 7/7 single and
pair sweep in `loop-position-ownership-mutations.json` tests whole-vector
assignment for either pair member and both ordinary chained scalar assignment
orders for the first member.

The `y`-through-`x` chain is byte-neutral at 99.07%, while the opposite chain
falls to 98.15%. Whole-vector assignment falls to 61.88% for the first member,
60.99% for the second, and 57.27% when combined. No variant improves the
108/108-instruction baseline or changes its `0/0/0` reference audit, so the
natural direct coordinate stores remain canonical. The spec SHA-256 is
`8c98855d0c865817eb742f42236b8aca4775d5e5573280e791e2fe259e6296c2`.
