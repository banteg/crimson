# `bonus_hud_slot_update_and_render`

Native target: `crimsonland.exe` at `0x0041a8b0` (1566 bytes).

Live Binary Ninja evidence recovers a three-argument function: a pointer to the
current HUD Y cursor, a slot index, and the caller's transition alpha. The
callsite at `0x0041c7a9` pushes the transition alpha, slot index, and Y pointer
before the call. The previous two-argument analysis signature omitted the alpha
read from the third stack argument; `analysis/ghidra/maps/name_map.json` now
records the corrected prototype.

The function advances a 0x20-byte bonus slot's slide X from its primary and
optional alternate timer, clamps it at -2, retires it below -184 only when no
later slot remains active, draws the normal or compact indicator panel and icon,
then renders one or two timer bars. Normal indicators also draw the slot label;
compact indicators intentionally omit it.

The recovered source compiles to 77.83% with the calibrated
`msvc6.5 /O2 /GB` profile: 407 candidate instructions against 405 native,
an exact 0x18-byte local frame, and 69/0/0 audited references. Declaring the
bar color before its position is supported by the native branch placement and
raises the score without adding artificial dependencies.

The remaining delta is compiler-shaped. Native VC6 shrink-wraps the `edi` save
until the render path after the off-screen retirement return, while the
available compiler saves it in the prologue. Repeated color/vector temporary
stores are also scheduled differently around the progress-bar calls. VC6.6 is
identical; `msvc6.5pp`, MSVC 7.0, `/G6`, and an explicit shared-tail rewrite all
regress, so no compiler override or ordering-only construct is retained.
