# ui_menu_pause_click_resume

Native target: `crimsonland.exe` at `0x00447490` (67 bytes).

The callback clears a loaded plugin's `on_pause` byte, re-enables the Crimson
sign, and queues either ordinary gameplay or plugin runtime. Typ-o Shooter
overrides both with its dedicated gameplay state. Natural C++ matches all 18
instructions and references `7/0/0`.
