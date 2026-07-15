# `mod_load_mod`

Native target: `crimsonland.exe` at `0x0040e860` (219 bytes).

Live Binary Ninja evidence shows the complete CMOD interface load path. It
builds `mods\\%s` in a 512-byte stack buffer, loads the DLL, resolves and calls
`CMOD_GetMod`, installs the game's `mod_api_context` pointer in the returned
interface at offset `+4`, and retains the module handle for the plugin runtime.
The native failure paths log the distinct load, export, and null-interface
errors; only export failure unloads the module immediately.

The C++ projection uses the already recovered three-slot `mod_interface_cpp_t`
layout. No dummy references, inline assembly, volatile ordering constraints, or
dead expressions are used.
