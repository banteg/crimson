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

The current candidate scores 76.32% with a five-instruction exact prefix, the
exact 228 native instructions, and no static-reference debt. A small builder
object plus pointer-based first phases preserves the native generalized
threshold loops at 16, 20, and 22 entries. Those middle regions individually
score between 75% and 91%, including the recovered coordinate and trigger-time
formulas. Whole-vector construction for the first three fixed corners restores
the native stack-temporary publication shape and the former 11-instruction
deficit; the fourth corner deliberately remains scalar because its constructor
form changes the whole function's frame and prologue.

The remaining mismatch is optimizer shape, not unresolved behavior. VC6
eliminates the first two phase counters and starts the shared entry/path
registers at twelve, while the candidate retains induction through the builder
count. The candidate also schedules independent template/count stores before
some x87 coordinate conversions. Fixed-count, combined-setter, and
all-four-corner constructor spellings regress materially; the latter changes
the frame from 12 to 20 bytes. The retained three-corner interaction keeps the
native 12-byte frame. No volatile state, dummy dependencies, or
register-forcing constructs are used.

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

## Three-corner constructor interaction (2026-08-09)

Replaying fixed-corner position publication after the direct trigger-expression
recovery overturns the older all-or-nothing constructor result.
`corner-position-constructor-mutations.json` evaluates the complete 15-variant
matrix of scalar versus whole-vector publication for the four corners. The
tradeoff-free winner uses constructor temporaries for the top-left, top-right,
and bottom-left entries while retaining scalar fields for the bottom-right.

That ordinary source change improves the candidate from
568.8404494382022/861 weighted bytes (66.067363%) to
657.078947368421/861 (76.315789%), a gain of 88.23849793021884 weighted
bytes. It restores the exact 228/228 instruction extent from 217/228 while
preserving prefix five and references `0/0/0`. Using constructors for all four
corners instead emits 230 instructions, changes the prologue immediately, and
regresses to 51.53%; the asymmetric retained result is therefore measured, not
stylistic.

The complete sweep is recorded in `experiments.jsonl`. The mutation spec has
SHA-256 `4ca6313f5f77b6feec937b3f4b5cd38d7e1cffbe9e66483a13bd9242d7c2ba2c`;
the retained source has SHA-256
`248f702d2a451704e7eece73b912d2355ccb8c5240d80755fed1a2e86d012dec`.

## Current-baseline opening and publication replay (2026-08-11)

The retained three-corner constructor changes the whole-function allocation
graph, so the older opening exclusions were replayed rather than assumed. The
four variants in `opening-fixed-reservation-mutations.json` remain negative on
the 76.3158% source: every literal or builder-backed fixed-12 form collapses to
12.11% and 173 candidate instructions. The historical conclusion survives the
new baseline.

Four fresh complete matrices then test the source explanations not covered by
that historical sweep:

- `current-opening-derived-count-mutations.json` (SHA-256
  `e9ecc439ff8c9e10799d1c06c5b8d33c8178c74c8450b9b8c354e5905c906271`)
  evaluates all 4/4 pointer-, X-, and trigger-induction derivations of the
  native value 12. The X form advances the exact prefix from five to nine but
  emits a runtime division, grows to 230 instructions, and falls to 63.32%;
  the other forms fall farther.
- `current-fixed-count-loop-interactions.json` (SHA-256
  `0339eb0ba9c173b9a9a65faeac76819aa12e47e49ce548ac40bc79dc1f80c11e`)
  evaluates all 14/14 fixed-count, `for`, guarded `do`, countdown, and pair
  interactions. The two ordinary `for` spellings are byte-neutral alone; no
  loop form prevents the fixed-count specialization cliff.
- `current-route-position-publication-mutations.json` (SHA-256
  `ea72fa26ea1cf47b4fe79560cab8ad7043971a86ee20da9c3c1879a6caa5377b`)
  evaluates all 26/26 scalar X/Y orders and interactions across the three
  middle route phases. Every variant loses score, from 3.75 to 11 percentage
  points, confirming the retained vector publication at each phase.
- `current-fourth-corner-lifetime-mutations.json` (SHA-256
  `af273554eda48383d2d722789202ad7e32f7f23d78ba73dab5b060837b23c131`)
  evaluates all 8/8 scalar, array, and scoped-vector lifetimes around the final
  `(896, 896)` corner. Six compile byte-identically; both whole-vector copies
  reproduce the known 51.53% frame/prologue regression.

Across 56 current-baseline evaluations, no variant improves the 76.32%,
228/228-instruction, prefix-five, `0/0/0` baseline and no tradeoff appears.
The scratch source is unchanged. The complete 10-line experiment log now has
SHA-256
`4ac494a819db93fbd4157354a1945f9ab1e6a233fe437b47641f58cc50d96542`.

## Indexed late-edge ownership (2026-09-05)

The three late path loops publish position and metadata directly through
`builder.spawns[entry_count]` instead of a cached record pointer and member
setter. Each individual edge improves native alignment without an instruction,
prefix, or reference tradeoff; all seven nonempty combinations are additive.
The first two edges contribute 7.552632 weighted bytes apiece and the third
11.328947, for a combined gain of 26.434211 weighted bytes. The retained result
is 79.385965% (683.513158/861), 228/228 instructions, prefix 5, and 0/0/0
references. Field values, publication order, and path/count increments are
unchanged. The native loop bodies provide the instruction-level control.

The nine complete controls in `indexed-late-edge-ownership-mutations.json`
also test folding the final count increments into the stores (byte-neutral)
and extending indexed ownership to the first edge (regresses to 71.93%).
Only the three supported late edges are retained. A separate named late range
and second-edge pointer publication probe regress; neither justifies changing
the early dynamic-counter reconstruction. This is a source-ownership gain,
not evidence that the remaining loop and corner schedules are exhausted.
