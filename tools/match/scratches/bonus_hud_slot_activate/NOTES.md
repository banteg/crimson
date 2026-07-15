# bonus_hud_slot_activate

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
