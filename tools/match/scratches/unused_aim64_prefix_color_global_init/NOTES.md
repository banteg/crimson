# `unused_aim64_prefix_color_global_init`

Native target: `crimsonland.exe` at `0x0041e000` (41 bytes).

Initializes the otherwise unreferenced RGBA object at `0x00496688` to opaque
black. It immediately precedes `aim64_texture`; live Binary Ninja xrefs find
no reads outside this CRT initializer.
