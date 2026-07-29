# `quest_build_the_collaboration`

Native target: `crimsonland.exe` at `0x00437f30` (286 bytes).

Live Binary Ninja evidence recovers sixteen four-entry waves. Triggers begin
at 1500 ms and advance by 11000 ms while below 177500. Each wave count is
`int(wave * 0.8f + 7.0f)`, including the native x87-to-`__ftol` conversion.
The entries are a template `0x1a` alien at the right edge, template `0x1b`
spider at the bottom edge, template `0x1c` lizard at the left edge, and
template `0x41` zombie at `(512, -64)`. The final count is 64.

The candidate reproduces the native indexed builder, count and wave induction,
all integer-to-float coordinate conversions, count conversion, four templates,
loop bound, and trigger arithmetic. It has the same 86 instructions, resolves
all seven references, and preserves a 22-instruction prefix at 86.05%.

The residual is independent scheduling after the first x coordinate: VC6
interleaves metadata stores, later coordinate conversions, count increments,
wave bookkeeping, and the final fixed entry differently. A bounded sweep found
that spelling the independent update as `++wave` before the trigger increment,
then moving the bottom entry's builder-count increment between its x and y
assignments, reproduces more of the native latency-filling schedule. Reversing
other assignments, changing helper store order, and moving the other count
increments do not improve that result. The direct 86-instruction candidate
remains an honest WIP without dependencies added solely to fill conversion
latency.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Exact-tail follow-up (2026-07-27)

The five-compiler matrix leaves the VC6 family tied and VC7 worse. The six-flag
matrix leaves `/O2 /GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tied while `/G6`
regresses. Three recorded sweeps evaluate 70 variants: the 33-variant
source-order pass retains the wave-before-trigger update, the five helper-store
orders all regress, and the 32 count-placement variants retain the bottom
entry's increment-after-x spelling.

Together the two source changes raise weighted bytes from
`222.8139534883721` to `246.09302325581393`, reduce the gap from
`63.18604651162789` to `39.90697674418607`, and preserve the exact 86
instructions, 22-instruction prefix, and `7/0/0` references.

## Cross-sweep interaction bound (2026-07-29)

The retained bottom-entry count placement was introduced after the original
direct-metadata sweep, so a new 15-variant interaction pass re-evaluates every
single and combined direct-field spelling at the current baseline. All
fifteen are exactly byte-neutral. The spec SHA-256 is
`bd26d5d97af4b29a83375ee90967742ea64dc3d5674ed68a97db418eaf28d19e`.

The normalized native diff appears to materialize the bottom entry's
`terrain_texture_width + 64` Y coordinate before its X coordinate. A separate
three-variant sweep tests every natural builder-count placement around that
Y-then-X spelling. Two forms lose 13.302325581395337 weighted bytes; placing
the increment after both coordinates loses the full 39.90697674418604-byte
baseline gap and one reference. The spec SHA-256 is
`7d176dadb49614a566fe21e64b02c7894488c9de2865edaa1b65e8d645cb12e6`.
This falsifies the apparent source-order clue and leaves the current
X/count/Y spelling as the evidence-backed best form.
