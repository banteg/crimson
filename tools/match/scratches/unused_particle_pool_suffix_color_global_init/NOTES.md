# `unused_particle_pool_suffix_color_global_init`

Native target: `crimsonland.exe` at `0x0041e0e0` (41 bytes).

Initializes the otherwise unreferenced RGBA object at `0x00495ab8` to
`(0.6, 0.6, 0.6, 0.5)`. The object immediately follows the 128-entry particle
pool. Pool scans also compare against its address as the natural one-past-end
bound, but no native code reads the four color fields.
