# `quest_build_land_hostile`

Native target: `crimsonland.exe` at `0x00435bd0` (239 bytes).

Live Binary Ninja evidence recovers four pale-green alien entries: the bottom
edge midpoint at 500 ms/count 1, bottom-left at 2500 ms/count 2, top-left at
6500 ms/count 3, and top-right at 11500 ms/count 4. The first position uses
`terrain_texture_width / 2` and `terrain_texture_height + 64`; the three corner
positions are `(-64, 1088)`, `(-64, -64)`, and `(1088, -64)`.

An inlined two-float constructor plus entry `set` method reproduces the
native's 12-byte local frame, integer-to-float conversions, float-word copies,
and shared template register. The candidate has the same 53 instructions and
scores 92.45%. The remaining differences are three independent scheduling
choices between metadata stores for one entry and construction of the next
entry's position. They are left unconstrained.
