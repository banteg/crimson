# `quest_build_survival_of_the_fastest`

Native target: `crimsonland.exe` at `0x00437060` (861 bytes).

Live Binary Ninja disassembly recovers a 26-entry route. Heading is left
untouched throughout and every entry has count one:

- entries 0-5 move east from (256,256) to (616,256) in 72-unit steps,
  using template `0x10` at triggers 500 through 5000 ms in 900 ms steps;
- entries 6-11 move south from (688,256) to (688,616), continuing triggers
  5900 through 10400 ms;
- entries 12-15 move west across y=688 from x=688 to x=472, at triggers
  11300 through 14000 ms;
- entries 16-19 move north along x=400 from y=688 to y=472, at triggers
  14900 through 17600 ms;
- entries 20-21 move east from (400,400) to (472,400), at triggers 18500
  and 19400 ms;
- entries 22-25 are fixed corners: template `0x10` at (128,128), template
  `0x07` at (896,128), template `0x07` at (128,896), and template `0x10` at
  (896,896). The top pair triggers at 22300 ms and the bottom pair at
  24300 ms.

The fixed final coordinates corrected the Zig port, which had scaled the four
corners by runtime terrain dimensions. The native builder has no terrain-size
references.

The current candidate scores 66.07% with a five-instruction exact prefix, 217
candidate instructions against 228 native instructions, and no static-reference
debt. A small builder object plus pointer-based first phases preserves the
native generalized threshold loops at 16, 20, and 22 entries. Those middle
regions individually score between 75% and 91%, including the recovered
coordinate and trigger-time formulas.

The remaining mismatch is optimizer shape, not unresolved behavior. VC6
eliminates the first two phase counters and starts the shared entry/path
registers at twelve, while the candidate retains induction through the builder
count. The candidate also schedules independent template/count stores before
some x87 coordinate conversions, and folds more corner float literals directly
into stores. Fixed-count, combined-setter, and corner-vector-constructor
spellings all regressed materially; the latter changed the frame from 12 to 20
bytes. No volatile state, dummy dependencies, or register-forcing constructs
are used.

## Cursor type recovery

The native loops intentionally advance pointers rooted at each entry's
`trigger_time_ms` field, so their negative indices are genuine interior-cursor
accesses rather than missing `quest_spawn_entry_t` base types. The five
phase cursors are now saved as named `int32_t *` locals in Binary Ninja.

The final four fixed-corner pointers are different: each points to a complete
entry, but Binary Ninja had degraded all four to `int32_t *`. Address-keyed
local annotations recover them as `quest_spawn_entry_t *`, and live readback
now renders `pos_x`, `pos_y`, `template_id`, `trigger_time_ms`, and `count`
for every corner. This is presentation-only and leaves the 62.02% candidate
and its reference audit unchanged.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live decompilation confirms all five routed phases plus the four fixed
corners, including their template IDs and paired trigger times. The candidate
remains 217/228 instructions with no static-reference debt; direct corner
trigger expressions improve its final two regions as documented below.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 produced the same 62.02247191011236%
baseline; MSVC 7.0 regressed to 12.84%. `/GB`, `/G5`, `/G7`, `/Ox`, and
`/Ob1` tied, while `/G6` regressed.

`opening-phase-reservation-mutations.json` (SHA-256
`82c4900a8f8975dd4341ca277530c9875e5b5eb711ec0c7fd125e6f66eaa7eae`)
recorded all 15 requested single and pair variants. The retained
`south-phase-count/preadvance-direct` spelling advances the south-phase entry
cursor before direct stores through `spawn[-1]`, matching the native
trigger-field cursor's preadvance/negative-offset dataflow without changing
the entries produced. Adding the analogous east-phase spelling was
byte-neutral relative to this winner, so only the smaller south-phase change
was retained; reservation forms regressed materially.

Fresh scratch recomputation improved 534.0134831460674/861 to
548.2600896860986/861 weighted bytes: 62.02247191011236% to
63.67713004484304%, with the gap falling from 326.9865168539326 to
312.7399103139014. The validated result has 218/228 instructions, prefix
five, and references 0/0/0.

## Opening local-order interaction audit

Live native disassembly keeps the entry base in EBX, the first x coordinate in
ECX, and its trigger time in EDX. `opening-local-order-interactions.json`
(SHA-256 `873cc60673a179ddf330c0402abb816df9c18a53dfa48786a59ec2ecc928a6c0`)
tested all five remaining semantic declaration orders, both natural first-phase
metadata spellings, and every pair interaction. All 17 variants were
byte-identical to the retained source. This closes the declaration-order and
east/south cursor-shape interaction hypothesis without changing the 63.6771%
scratch.

## Fixed-reservation scheduling audit

Fresh live disassembly shows a sharper opening invariant than the earlier
reservation sweep captured. Neither of the first two six-entry loops updates
the later entry/path registers. Immediately before the south loop, native
materializes entry index 12 in EAX and copies it to path index ECX; the south
loop leaves both registers untouched. Its entry cursor is rooted directly at
entry six.

`opening-fixed-reservation-mutations.json` (SHA-256
`8a59bc5a91e699ad0825d6bc5dc59a5d0e21341a200fc725059fd3503aafc037`)
tested fixed, builder-backed, shared-index, and six-plus-six spellings for
that invariant. All four exposed the constant early enough for VC6 to
specialize the later route phases, producing only 173 instructions and
regressing from 63.6771% to 11.9701%.

Native schedules the two index loads before the south loop even though that
loop does not use them, so `opening-post-loop-indices-mutations.json`
(SHA-256 `02baf7a6073f836147153bc0d38335964f7acd3e5b647bca9ac178adf087c787`)
also tested declarations and assignments after the loop, plus a dead builder
induction intended to inhibit early propagation. The three direct forms
compiled to the same 173-instruction cliff; retaining the dead induction
produced 174 instructions and 13.2982%, still a large regression.

The semantic invariant is therefore confirmed but not safely expressible as
a visible fixed reservation in the current reconstructed builder shape.
The pre-transfer 218-instruction scratch remained the honest best result. The next
useful revisit needs a recovered original helper or object boundary that
explains why VC6 emits the immediate 12 without specializing the later loops;
more scalar reservation or declaration-order variants are exhausted.

## Corner trigger-expression ownership transfer (2026-08-09)

The exact Frontline/Everred expression-ownership shape also improves both
fixed-corner pairs here. Exactly three forms were tested against the retained
548.2601/861 (63.6771%) baseline: repeating only
`path_index * 900 + 2500` reached 555.9821/861 (64.5740%); repeating only
`path_index * 900 + 4500` reached 561.1011/861 (65.1685%); repeating both
reached 568.8404/861 (66.0674%) and was retained.

The combined form has 217/228 candidate/native instructions versus 218/228 at
baseline, while prefix five and references 0/0/0 are unchanged. A regional
comparison showed the first six mismatch regions unchanged and improvements
confined to the final two corner regions, including fewer changed candidate
instructions in both. This is a tradeoff-free local alignment improvement,
not a builder-opacity or reservation change. The retained `scratch.cpp` has
SHA-256 `e3abffd6f2a778065673095932304b75fce58473fa371a9ba054033cea58bd6b`.
