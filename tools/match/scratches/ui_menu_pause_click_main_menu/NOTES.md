# ui_menu_pause_click_main_menu

Native target: `crimsonland.exe` at `0x004474e0` (160 bytes).

## Recovered source shape

- When a plugin is active, its pause flag and runtime latch are cleared before
  invoking virtual `Shutdown` through the native C++ interface.
- Plugin music is muted, the DLL is freed, interface/module globals are nulled,
  and the runtime is marked for reinitialization before returning to the mods
  menu. Without a plugin, the destination is the main menu.
- Both paths clear transition/render flags, mute the three menu tracks, and
  restart the Crimson theme exclusively.
- Re-reading `plugin_interface_ptr` for the virtual call is the natural global
  access shape visible in the native function; it also exposes the `onPause`
  byte at interface offset `0x9` and the `__thiscall` shutdown slot at vtable
  offset `0x4`.

Natural VC6 code matches all 40 instructions and references `22/0/0` without
inline assembly, volatile state, or dummy dependencies.
