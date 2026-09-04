# `quest_build_the_unblitzkrieg`

Native target: `crimsonland.exe` at `0x00438a40` (975 bytes).

Live Binary Ninja disassembly recovers 81 entries: eight ten-entry perimeter
sweeps with one center entry between the second and third sweeps. Heading is
left untouched and every entry has count one. Each sweep advances an integer
offset from 0 by `0x270` while it is below `0x1860`; dividing that offset by
ten produces the axis coordinate. Templates alternate `0x07`, `0x0d`, starting
with `0x07` in every sweep.

- x=824, y=`200 + offset/10`, triggers 500 through 16700 by 1800;
- y=824, x=`824 - offset/10`, triggers 18500 through 32000 by 1500;
- center (512,512), template `0x07`, trigger 33500;
- x=200, y=`824 - offset/10`, triggers 33500 through 44300 by 1200;
- y=200, x=`200 + offset/10`, triggers 45500 through 52700 by 800;
- x=824, y=`200 + offset/10`, triggers 53500 through 60700 by 800;
- y=824, x=`824 - offset/10`, triggers 61500 through 67800 by 700;
- x=200, y=`824 - offset/10`, triggers 68500 through 74800 by 700;
- y=200, x=`200 + offset/10`, triggers 75500 through 82700 by 800.

The retained candidate scores 86.59% with a forty-instruction exact prefix,
298 candidate instructions versus 291 native instructions, and no
static-reference debt. It reproduces the signed division-by-ten lowering,
parity-to-template arithmetic, 24-byte stride, loop limits, count reservation,
trigger increments, register frame, and final count. In particular, the first
sweep advances the live count per entry while each later sweep reserves ten
entries before looping, matching the native `add edi, 0xa` boundaries. The
first sweep is exact; each later fixed batch currently carries one extra
member-address adjustment.

In the earlier carried-pointer candidate, advancing the independent integer
offset immediately after the coordinate
expressions is semantics-neutral and recovers the native `add ebp, 0x270`
schedule in most sweeps, improving the fuzzy gap from 291.49 to 241.24 bytes.
The repeated residual is legal independent-store scheduling. Native VC6 uses
the `template_id` field as its cursor base, advances that cursor before storing
template/time/count through negative offsets, and leaves those metadata stores
until after the x87 coordinate conversion. Moving the constant count assignment
out of the metadata helper recovers four exact prefix instructions and 6.70
fuzzy-weighted bytes; the candidate still hoists some trigger stores around
that conversion. Other metadata helper bodies and direct field stores tested
against the earlier three-argument form compile identically. A post-incremented
spawn cursor regresses to 52.97%, and encoding a negative-field cursor would
describe the optimizer rather than plausible game source. No volatile state,
dummy dependencies, or register-forcing constructs are used.

## Semantic-completion audit

Fresh live Binary Ninja HLIL confirms all eight ten-entry sweeps, the inserted
center entry, every axis formula, alternating template expression, trigger
step, and the final count of 81. Address-matched IDA and Ghidra snapshots
independently agree on the signature and absence of callees. The retained
indexed form has 298 candidate instructions versus 291 native instructions and
no static-reference debt.

Replacing the direct position stores with a natural vector constructor
regressed from 75.26% to 61.24%, added 32 instructions, and removed the
12-instruction exact prefix. Moving each offset increment after the metadata
stores also regressed to 70.10% while preserving instruction count and prefix.
The retained source is the strongest natural spelling, and the repeated
independent-store schedule is a compiler residual. The scratch is classified
`semantic-complete` with a `compiler` residual.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at
75.25773195876289%; MSVC 7.0 regressed to 36.49%. `/GB`, `/G5`, `/G7`,
`/Ox`, and `/Ob1` were byte-identical, while `/G6` regressed.

`metadata-helper-shape-mutations.json` (SHA-256
`eff4f02fc31cd68015005e127d560fd282e016cfdddf01c662f15aae582e6c6f`)
recorded five complete variants. Explicit-inline, force-inline,
return-by-reference, and count-before-trigger spellings were byte-neutral.
Reversing metadata stores lost 23.4536 weighted bytes and three prefix
instructions, so no variant was retained. The validated source remains at
733.7628865979382/975 weighted bytes, a 241.23711340206182 gap, 291/291
instructions, prefix twelve, and references 0/0/0.

## Two-argument metadata helper provenance

The exact neighboring `quest_build_two_fronts` reconstruction uses a
two-argument `set_spawn(template_id, trigger_time_ms)` helper and assigns the
constant entry count separately. Replaying that same recovered class boundary
here is the first improvement after the 2026-07-27 stopping audit. The recorded
`two-argument-helper-count-after` probe raises the score from 75.26% to
**75.95%**, adds **6.70 fuzzy-weighted bytes**, and extends the exact prefix
from **12 to 16 instructions** while preserving **291/291 instructions** and
`0/0/0` references. The two-argument helper plus direct `count = 1` assignment
is retained because it is both cross-function source evidence and a strictly
better tradeoff-free build.

The new first mismatch is the independent trigger store and offset increment
still moving ahead of the signed coordinate conversion. Count now remains at
the native metadata tail. This narrows the remaining search to trigger/offset
lifetime scheduling rather than the already-recovered entry layout or helper
ABI.

The exact `quest_build_syntax_terror` neighbor also motivated replaying its
`pos.set(x, y)` member boundary across all eight sweeps and the center entry.
The recorded `position-setter-all-sweeps` probe preserves 291/291 instructions
and the 16-instruction prefix but loses 60.31 fuzzy-weighted bytes, falling to
69.76%. That shared API is rejected here; the direct component stores remain
the stronger recovered source.

## First-sweep position-materialization audit

Native writes the fixed x coordinate before completing the signed
divide-by-ten y conversion. `first-sweep-position-shape-mutations.json`
(SHA-256 `74f6c26317c034087411cfe26fbd568be2c637c649b87f52bef2ee5df340958d`)
tested reversed field order, integer and float axis temporaries, and advancing
the offset between calculation and stores. The three integer forms were
byte-neutral; the float temporary lost 3.351 weighted bytes. This rules out a
missing position-materialization idiom at the first mismatch.

## Exact-neighbor builder and later-axis audit

`builder-lifetime-interactions.json` imports the cursor/count builder recovered
exactly in neighboring `quest_build_two_fronts`, tests both field orders, and
backs the existing `spawn` and `entry_count` lifetimes with its fields through
ordinary references. The builder type alone is eliminated; the exact-neighbor
field order loses 60.31 weighted bytes when used, while the reverse order loses
75.92 bytes and one instruction. No builder-backed form improves the retained
direct lifetimes.

`second-sweep-axis-materialization.json` independently tests integer, float,
quotient, and pre-advance temporaries around the first computed-X perimeter
sweep. All four variants compile byte-identically. Together these sweeps add
12 bounded variants without a gain or tradeoff, bringing the ledger to 21
variants and four consecutive non-improving sweeps. The scratch is now
formally stalled: its residual is independent-store scheduling, not the shared
builder ABI or a missing coordinate lifetime.

## 2026-08-09 single-field helper recovery

The surviving SDK's small inline-member style exposes a narrower metadata
boundary than the earlier two-field helper. Each perimeter entry now publishes
its alternating template through `set_template`, then writes trigger and count
explicitly before advancing the offset and trigger state. The center entry
likewise finishes its trigger before the template helper. For the opening
sweep, staging the chosen template and advancing the append count before the
record stores reproduces the native instruction order exactly.

The retained source improves the match from 75.95% to 79.73%, extends the exact
prefix from 16 to 41 instructions, and preserves the exact 291/291 instruction
count with no static-reference debt. The first ten-entry perimeter sweep is now
exact. Replaying explicit template-field cursors and post-incremented record
cursors regressed sharply, while named coordinate and template temporaries
were byte-neutral, so the ordinary record pointer and the smaller helper
boundary are retained. The retained source SHA-256 is
`c8e38ad16a82435cf18b52baa00da28d1b5826d48735df81dcac6725e6ea5016`.

## 2026-08-09 indexed fixed-batch recovery

The neighboring exact Nagolipoli builder establishes the original house style
for fixed-size quest batches: reserve the batch in the live count, then publish
records through `base[index]` rather than carrying and incrementing a record
pointer. Replaying that style across the seven later Unblitzkrieg perimeter
batches raises the score from 79.73% to 85.23%. The compiler materializes each
`template_id` member address as `lea base` followed by `add 0xc`, whereas the
native function folds the displacement into the `lea`; those seven uniform
adjustments explain the 298/291 instruction count.

The fixed batches also alternate between two natural inline publication
boundaries already recovered in neighboring builders: `set_template(template)`
plus a direct trigger store, and `set_spawn(template, trigger)`. The complete
127-combination sweep in `indexed-batch-publication-mutations.json` (SHA-256
`2ffa2ea756f5984b4cad83c77c39f9b015f54731c3b2e20fccf2d1ca0ffeaa73`)
selects the two-field boundary for batches 2, 4, 6, and 8 and the single-field
boundary for batches 3, 5, and 7. That alternating form is strictly better than
all other combinations: 844.2275/975 weighted bytes, **86.59%**, prefix 40,
298/291 instructions, and references 0/0/0. The retained source SHA-256 is
`d97cfdf0a07cb9c8ea887ae1a9f06183c9e6ed57db0cf910e14b61660dff5add`.

## Current indexed direct-publication replay (2026-08-11)

The earlier direct-field probes predate the retained indexed fixed batches, so
they do not exclude the current seven repeated `lea` plus `add 0xc` address
adjustments. `current-indexed-direct-publication-mutations.json` (SHA-256
`eba1ce4a28a5e91bd1bc1facfa692e40cac37316b45d2db422e65d99be2d94f0`)
therefore replaces each current helper independently with direct template and
trigger stores and evaluates the complete 127/127 interaction matrix.

Direct stores are byte-neutral in batches 3, 5, and 7, where they replace the
single-field helper. The seven non-empty combinations of only those batches
are identical to the baseline. Every variant touching batches 2, 4, 6, or 8
regresses because it removes the retained two-field publication boundary; no
variant folds away the address adjustment. The canonical source remains
86.59%, 298/291 instructions, prefix 40, and `0/0/0`. The complete eight-line
experiment log now has SHA-256
`2c08bbf01ac2fd8606fcd43c7257a9b35b4ca9da943092aa5ae09619a22ec9d3`.

## Fixed-batch owner replay (2026-08-12)

The seven extra candidate instructions are uniform `lea record_base` followed
by `add 0xc` pairs; native folds the `template_id` displacement into each LEA.
The publication-helper sweep does not test whether the fixed batch itself has a
different owner, so the first later batch was replayed through nine additional
bounded shapes.

`second-batch-owner-mutations.json` tests reserve-then-previous-base, pointer
arithmetic, direct global indexing, and per-entry pointer/reference forms.
Neither delayed base spelling folds the displacement; both lose 6.65 weighted
bytes and three prefix instructions. Direct and per-entry ownership regress by
89 to 103 weighted bytes and collapse the prefix to one instruction.

`second-batch-array-owner-mutations.json` models the ten reserved entries as a
fixed-size array pointer and array reference. Both are byte-identical to the
retained source, proving that a clean batch aggregate does not alter member
address selection.

A separately marked diagnostic,
`second-batch-interior-cursor-diagnostic.json`, checks the native optimizer's
`template_id`-biased induction directly. A parallel metadata cursor falls to
57.29%; using that cursor for negative position fields falls to 44.48%.
Neither low-level form is a retainable source shape, and the decisive
regressions show that the native cursor cannot be recovered by spelling the
optimizer's address bias back into C++.

The current source remains `844.2275/975` weighted bytes (`86.59%`), 298/291
instructions, prefix 40, and `0/0/0` references. Batch ownership, aggregate
shape, direct publication, and interior-cursor hypotheses are now current and
bounded; the repeated folded-displacement choice remains compiler residual.

## Exact per-record wave publication (2026-09-05)

Current result: **100%**, 291/291 instructions, full prefix, and no unresolved
or mismatched references. This function has no masked external references.
The previous 86.59% compiler-residual result is superseded by
`per-record-count-and-metadata-mutations.json`.

The seven later perimeter loops now index the current `entry_count` directly
and advance it when each entry's count field is published. VC6 folds the known
ten-entry advances into the loop setup itself. Replacing the earlier manually
reserved count and separate indexed base removes all seven extra pointer-offset
instructions. Moving the count advance to the completed record improves the
result further to 92.44%.

Publishing template and trigger fields directly in the four two-field-helper
loops restores the native metadata order and completes the match. The unused
helper and seven obsolete cursor assignments are removed; the cleanup is also
exact. The eight recorded controls isolate those steps. All eight ten-entry
perimeters, alternating templates, signed coordinate division, trigger cadence,
central entry, and final count of 81 are preserved.
