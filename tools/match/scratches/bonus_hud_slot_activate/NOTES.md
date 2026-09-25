# bonus_hud_slot_activate

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare; the duplicate scan still starts at the out-of-range `check_index = 16`. It reads `quest_stage_label_buffer` as slot 16. See [original bug #26](../../../../docs/rewrite/original-bugs.md). The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Native target: `crimsonland.exe` at `0x0041a810` (159 bytes).

The helper claims the first inactive HUD slot, binds its label, icon, and timer
pointers, starts it offscreen at x = -184, and drops the alternate timer in
single-player mode. It then removes older active slots that point at the same
primary timer, preventing duplicate bonus gauges.

Binary Ninja shows `bonus_hud_slot_table` is exactly 0x200 bytes (16 records),
while the backward duplicate scan starts at record index 16. That first probe
therefore overlays the adjacent `quest_stage_label_buffer` before walking the
real slots 15 through 0. The scratch preserves this native one-past-table
behavior rather than silently repairing it; changing the scan to start at 15
does not match and would be a port-parity change.

The unsized extern is intentional source recovery: it lets the natural VC6
optimizer retain the alias between the current and scanned records. The result
matches all 54 native instructions and all eight static references exactly.
