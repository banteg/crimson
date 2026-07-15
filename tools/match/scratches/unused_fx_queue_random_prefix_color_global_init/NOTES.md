# `unused_fx_queue_random_prefix_color_global_init`

Native target: `crimsonland.exe` at `0x0041df80` (41 bytes).

Initializes the otherwise unreferenced RGBA object at `0x00490408` to opaque
white. The object immediately precedes the already identified unused FX queue
prefix vector, and live Binary Ninja xrefs find no reads outside this CRT
initializer.
