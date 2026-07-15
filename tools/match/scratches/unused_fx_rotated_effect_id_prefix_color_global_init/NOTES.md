# `unused_fx_rotated_effect_id_prefix_color_global_init`

Native target: `crimsonland.exe` at `0x0041dfc0` (41 bytes).

Initializes the otherwise unreferenced RGBA object at `0x0049ba20` to
`(0.5, 0.5, 0.5, 1)`. It immediately precedes `fx_rotated_effect_id`; live
Binary Ninja xrefs find no reads outside this CRT initializer.
