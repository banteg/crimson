# console_cmd_generate_terrain

Native target: `crimsonland.exe` at `0x0042a970` (5 bytes).

The command is a direct `void` wrapper around `terrain_generate_random`.
MSVC emits it as the native one-instruction tailcall with its sole reference
aligned.
