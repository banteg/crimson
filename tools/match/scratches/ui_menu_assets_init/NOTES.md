# `ui_menu_assets_init`

Native target: `crimsonland.exe` at `0x00419dd0` (551 bytes).

Live Binary Ninja evidence recovers the three JAZ resources and placements,
the 0xe8-byte template copy topology, slot duplication, UV bands, vertical
offsets, and the eight-slot horizontal translation. Modeling the translation as
the inlined C++ `vec2 += (-84, 0)` operation reproduces the native loop,
including its otherwise-surprising `y` self-copy.

The six contiguous 0xe8-byte subtemplates are modeled as one array view, and
the slot type retains the empty user-defined constructor established by
`ui_menu_template_pool_init`. That ordinary object model prevents VC6 from
hoisting the first `-100` calculation across the block-01-to-block-02 copy.
The candidate now aligns all 110 normalized instructions with a 110-instruction
prefix and scores 100.00%.

This remains an honest WIP because two static references still differ
(`refs=64/0/2`). For the first two `+124` adjustments, native reloads copied
destination slots 4 and 5 (`0x0048fdec`, `0x0048fe08`), while VC6 propagates
the equal source values from slots 3 and 2 (`0x0048fdd0`, `0x0048fdb4`). The
full-vector `+= (0, 124)` spelling forces the native references but emits eight
non-native x self-copies; `memmove` forces the references but emits calls.
Neither is retained, and no volatile or artificial dependency is used.
