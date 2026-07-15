# `unused_fx_rotated_scale_prefix_color_global_init`

Native target: `crimsonland.exe` at `0x0041e040` (41 bytes).

Initializes the otherwise unreferenced RGBA object at `0x00490690` to
`(0.5, 0.5, 0.5, 1)`. It lies in the gap immediately before
`fx_rotated_scale`; live Binary Ninja xrefs find no reads outside this CRT
initializer.
