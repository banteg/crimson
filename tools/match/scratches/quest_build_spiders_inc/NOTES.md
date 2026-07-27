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
Keeping the initial entries explicitly indexed and advancing the builder count
between coordinate assignment and metadata reproduces the native induction
shape. It compiles to 106 instructions versus the native 105, preserves a
nine-instruction prefix, and scores 69.19%.

The residual is VC6 allocation and independent-store scheduling. Native reuses
EBX for the loop trigger, keeps the wave count in EBP and the entry pointer in
EDI, and completes each x87 conversion before metadata stores. The candidate
assigns those values to EBP, EDI and EBX and fills conversion latency with the
independent stores. Direct metadata fields, a metadata setter, a vector setter,
post-incremented and explicit builder-count forms, a raw pointer/count view,
`msvc6.5pp`, `msvc7.0`, and `/G6` were checked. The default VC6 profile remains
the strongest evidence-backed shape without volatile state, dummy dependencies,
or forced-register constructs.

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
