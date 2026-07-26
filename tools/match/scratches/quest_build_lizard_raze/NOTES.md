# `quest_build_lizard_raze`

Native target: `crimsonland.exe` at `0x00438840` (254 bytes).

Live Binary Ninja evidence recovers paired template `0x2e` lizard waves from
the right and left edge midpoints. Triggers begin at 1500 ms, advance by 6000
ms, and stop before 91500 ms; every wave has count six. The loop is followed
by three template `0x0c` alien spawners at `(128, 256)`, `(128, 384)`, and
`(128, 512)`, all at 10000 ms with count one. The final count is 33.

The candidate preserves the native base-plus-count record builder, signed
width-halving sequence, integer-to-float x87 conversions, 24-byte record
stride, loop boundary, fixed tail, and output count. It compiles to the same
77 instructions and resolves all three constant references.

The remaining difference is independent-store scheduling: VC6 fills the x87
conversion latency with template, trigger, count, loop-update, and epilogue
work in a different order. Direct fields and a metadata-only setter produce
the same best result. Builder post-increment, `pos.set(x, y)`, a five-argument
entry setter, and the established vector-temporary entry setter were checked;
they move the counter too early, alter register allocation, or introduce
temporary copies. The 79.22% candidate remains an honest WIP without volatile
state, dummy dependencies, or other scheduler steering.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
