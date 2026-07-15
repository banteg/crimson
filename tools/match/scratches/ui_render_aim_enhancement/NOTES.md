# `ui_render_aim_enhancement`

Native target: `crimsonland.exe` at `0x0041a320` (518 bytes).

Recovered as an exact 131/131-instruction match with all 35 native references
audited.

The sole callsite pushes a position pointer, correcting the former no-argument
decompiler signature. Live disassembly establishes two phase accumulators, a
strict clamp of `cv_aimEnhancementFade` into `[0, 1]`, and two centered layers:
a 64-pixel particle quad selected through effect frame 13 and a 20-pixel aim
texture quad. Both use the clamped fade as alpha and their own Grim render-state
setup and batch.
