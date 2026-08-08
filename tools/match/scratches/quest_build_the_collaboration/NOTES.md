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
loop bound, and trigger arithmetic. It matches all 86 native instructions and
all eight audited references exactly.

The decisive house style completes each record through repeated
`builder.spawns[builder.count]` expressions before publishing the count. The
bottom entry writes its terrain-derived y coordinate before x, and the final
fixed-position zombie uses direct metadata fields. Together those ordinary
source boundaries reproduce the native latency-filling schedule without a
captured record pointer or dependency-only constraint.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

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

## 2026-08-08 exact indexed-publication recovery

The earlier Y-before-X and direct-metadata probes were evaluated while each
entry still shared a captured record pointer and published its count early.
Replacing all four entries with complete indexed publication raises the score
from 86.05% to 90.70%. Under that recovered ownership, Y-before-X for the
bottom entry reaches 97.67%, and direct metadata on the final zombie removes
the last schedule cluster. The result is exact at 86/86 instructions with
references `8/0/0`. Retained source SHA-256:
`36315f1f1b29c7703bad2c63e0eea082fc8551db8510ebea830b18fe412e471c`.
