# `ui_menu_assets_init`

Native target: `crimsonland.exe` at `0x00419dd0` (551 bytes).

Live Binary Ninja evidence recovers the three JAZ resources and placements,
the 0xe8-byte template copy topology, slot duplication, UV bands, vertical
offsets, and the eight-slot horizontal translation. Modeling the translation as
the inlined C++ `vec2 += (-84, 0)` operation reproduces the native loop,
including its otherwise-surprising `y` self-copy.

The candidate has the same 110 normalized instructions, an 89-instruction
exact prefix, and scores 98.18%. The sole residual region is scheduling: VC6
hoists the first `-100` x87 calculation across the second 0xe8-byte structure
copy. Its two reference mismatches are alignment fallout from that move. This
remains an honest WIP; no operand masking or dead dependencies are used.
