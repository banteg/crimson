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
