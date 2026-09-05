# `quest_build_spiders_inc`

Native target: `crimsonland.exe` at `0x004390d0` (346 bytes).

Live Binary Ninja evidence recovers three opening spider entries at 500 ms.
Two template `0x38` timer spiders spawn along the bottom edge at the horizontal
midpoint and midpoint plus 64, both with count one; one template `0x40` blue
spider spawns at the top midpoint with count four. Fifteen paired template
`0x38` waves then arrive from the bottom and top midpoints. Their triggers begin
at 17000 ms, advance by 6000 ms, and stop before 107000 ms. The paired count is
`step / 2 + 3`, using signed division, so the final output count is 33. The
Python and Zig ports agree with every recovered entry.

The candidate preserves the native fixed three-entry prefix, base-plus-count
builder, signed width halving, x87 integer-to-float conversions, 24-byte entry
stride, paired loop, trigger and count recurrences, and all eight references.
Each fixed record is completed through the indexed builder before its count is
advanced. The first and third fixed records publish metadata directly, while
the second retains the shared setter boundary. In the loop, a record pointer
owns the coordinate stores while metadata is published through the current
indexed builder entry. It compiles to 106 instructions versus the native 105,
preserves a 17-instruction prefix, and scores 89.10%.

The residual is VC6 allocation and independent-store scheduling. Native reuses
EBX for the loop trigger, keeps the wave count in EBP and the entry pointer in
EDI, and completes each x87 conversion before metadata stores. The candidate
keeps the trigger in EBP and the wave count in EBX, with one extra instruction
and a different prologue schedule. Direct metadata fields, a metadata setter, a
vector setter, post-incremented and explicit builder-count forms, a raw
pointer/count view, `msvc6.5pp`, `msvc7.0`, and `/G6` were checked. The default
VC6 profile remains the strongest evidence-backed shape without volatile state,
dummy dependencies, or forced-register constructs.

## Recovery classification audit

The live Binary Ninja body accounts for the three fixed entries, all fifteen
paired waves, signed count formula, trigger recurrence, coordinate conversions,
and final count. The candidate emits 106 instructions against 105 native
instructions with `8/0/0` references. Its localized residual is entirely the
documented register allocation and independent-store/x87 schedule, so recovery
is `semantic-complete` with a `compiler` residual.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed the three opening entries, all fifteen paired
waves, signed half-step count, and final count 33. MSVC 6.0, 6.5, 6.5
Processor Pack, and 6.6 tie at 69.19431279620854%; 7.0 regresses to
64.15094339622641%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while
`/G6` falls to 65.40284360189573%.

`opening-and-wave-shape-mutations.json` (SHA-256
`345a28651f7c5d9bba264cd11b1d7e7b944fd666e7087533d9507fde37dd338b`)
recorded all 24 bounded single and pair variants. Opening/builder lifetime
orders, explicit loop-local lifetimes, and direct metadata for either wave are
all byte-identical, alone and in the evaluated interactions. No source change
is justified. Validation remains 239.41232227488152/346 weighted bytes, a
106.58767772511848 gap, 106/105 instructions, prefix nine, and references
8/0/0.

## Fixed-opening builder-boundary audit

Native disassembly does not materialize the count until after the three fixed
entries. `first-entry-lifetime-mutations.json` (SHA-256
`3d537e07ddda3d4c0d544b3a59d61d0aeb264d02d5d234e414f608582fa02464`)
tested four first-entry declaration boundaries; all were byte-neutral.
`delayed-builder-construction-mutations.json` (SHA-256
`b6c31d301e0aafdffbb80f1d3ff6c1a94d927e39c5cd17e7919ee394cfdc3655`)
then tested the complete interaction that builds the count wrapper only after
the fixed entries. The full four-site form was also byte-identical; incomplete
site subsets correctly failed because they intentionally lacked one side of
the coordinated rename. No source change is retained.

## 2026-08-08 complete-record publication pass

Applying the recovered quest-builder house style improves the retained source
from 69.19% to 84.36% while preserving the 106/105 instruction counts, the
nine-instruction prefix, and all `8/0/0` references. The three opening records
now publish coordinates and metadata through `builder.spawns[builder.count]`,
then advance the count only after each record is complete. Each loop record
keeps a local pointer for its position, republishes metadata through the
indexed current entry, and advances the count at the same completion boundary.

Pointer and reference spellings, and `for` versus explicit `while` induction,
are byte-identical. The retained pointer-and-`for` form is the clearest source
expression of the native construction pattern. The remaining diff is the
localized EBX/EBP trigger and wave-count allocation swap, one extra candidate
instruction, and the associated prologue/store scheduling. The retained source
SHA-256 is
`6f7d78a2bc1afdfaf4ad8bbdb084327161bd6f29e95ff6ab6a0883749270d19e`.

## Staged-publication follow-up (2026-08-08)

Replaying individual publication boundaries against the stronger complete-
record source raises the score from 84.36% to 89.10%. Direct metadata for the
first fixed record moves the shared template load ahead of the final callee-
save push and extends the exact prefix from nine to 17 instructions. Direct
metadata for the third fixed record restores its native template/trigger/count
order. Finally, advancing the loop step before its trigger in source improves
the loop-bottom spill schedule; the compiler still emits the native trigger
advance first. The second fixed record remains on the shared setter because its
direct form is byte-neutral. The retained result remains 106/105 instructions
with `8/0/0` references; the residual is the bounded EBX/EBP trigger and wave-
count allocation swap plus its one extra half-step copy.

## Current-baseline loop allocation bound (2026-08-11)

Live Binary Ninja localizes the current residual more precisely. Native reuses
`EBX` for the 17000-ms trigger only after the fixed template-`0x38` lifetime,
computes the half-step in `EAX`, and forms `wave_count` in `EBP` with one
`lea`. The candidate hoists the trigger into `EBP` during the fixed prefix and
copies the half-step into `EBX`, accounting for its one extra instruction.
Both paired records and the loop tail otherwise perform the same operations.

Six current-source sweeps record 41 variants across the plausible ownership
boundaries that predated the retained staged-publication source:

- all ten trigger/step declaration, initialization, and update orders;
- six pointer-versus-wave-count local orders;
- eight signed, const, long, and staged wave-count spellings;
- five second-record pointer, reference, indexed, and reuse forms;
- four declaration-versus-assignment orderings; and
- every single and pair of the exact-neighbor count-advance/pointer-metadata
  boundary on both records.

Thirty forms are byte-neutral at 89.10%, 106/105 instructions, prefix 17, and
`8/0/0` references. The remaining eleven regress; computing the wave count
before pointer materialization loses one reference and falls to 75.83%, while
the exact-neighbor publication transfer falls as low as 86.26%. A fresh matrix
of all twelve installed VC6 builds is byte-identical to the baseline; VC7
regresses. No current-source form recovers the `EBX`/`EBP` allocation without
a metric or reference loss.

Recorded spec SHA-256 values:

- `current-loop-induction-mutations.json`:
  `fb0c39a327bbdb28074be58bb6dbb49580c8c989c124f9d3f174a3d66a3d50cc`;
- `current-wave-local-order-mutations.json`:
  `9af1b506000180fe48b53f33683d3d1a4be6d597a90ec17dfc17df7f4b13fb7c`;
- `current-wave-count-shape-mutations.json`:
  `5ab7c804ef7bcc95c668cd4c8e68a1d9913ca79107ceb34e78fb1d4a460e6f35`;
- `current-second-wave-pointer-mutations.json`:
  `c04cb19c801051ea40ddd7f34ed2e3e730622d86eb3896a8f918335d0ecb4e26`;
- `current-wave-declaration-assignment-mutations.json`:
  `f8d8487bfcbb3b7c7f09b4a70ab3a111a2e3653a5b5e81a4248a8383ab5f0d1e`;
  and
- `current-loop-publication-boundary-mutations.json`:
  `2d9ddb0e9b5cefdad063069265aa74a37fbcc366488faca35919fa5422568218`.

## Shared paired-wave count recovery (2026-09-05)

Publishing the first wave's count and caching that assigned value for its paired
wave recovers the native `EBX` trigger / `EBP` count allocation and removes the
extra half-step copy. Both records still receive `step_count / 2 + 3`; no
intervening calls can observe the order of field initialization. The result
improves from **89.0995% to 95.2381%**, 106 to **105/105 instructions**, and
prefix 17 to **54**, while retaining all **8/0/0** references.

The complete 20-variant `shared-wave-count-mutations.json` records the controls.
The retained `first-field-cached` form has no metric or reference tradeoff. The
96.1905% indexed-before-pointer form loses one aligned reference and is rejected.
The remaining native difference is confined to the first loop record: native
computes the count before constructing its pointer but publishes the count
after the coordinates and other metadata. Historical claims that the register
swap and extra instruction were unavoidable are superseded by this recovery.

## Focused follow-up (2026-09-05)

Eleven count declaration, integer-type, and stored-count reference variants
were tested against the 95.24% baseline. None improves it; the reference forms
add two instructions, and moving the computed local before its record pointer
changes allocation and loses a reference.

The complete bounded matrix is recorded in
`paired-count-lifetime-followup-mutations.json`. No source change is retained;
this result bounds these specific hypotheses only.
