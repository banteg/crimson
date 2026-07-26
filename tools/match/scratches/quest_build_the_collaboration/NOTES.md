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
all seven references, and preserves a 22-instruction prefix at 77.91%.

The residual is independent scheduling after the first x coordinate: VC6
interleaves metadata stores, later coordinate conversions, count increments,
wave bookkeeping, and the final fixed entry differently. Reversing the second
entry's source assignments, using `pos.set(x, y)`, and moving the wave increment
to its scheduled native location all degrade the proven x87/reference shape.
The direct 86-instruction candidate remains an honest WIP without dependencies
added solely to fill conversion latency.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
