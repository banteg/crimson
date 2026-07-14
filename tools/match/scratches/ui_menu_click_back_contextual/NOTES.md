# ui_menu_click_back_contextual

Native target: `crimsonland.exe` at `0x00447420` (45 bytes).

The callback always clears the transition direction. An active plugin returns
to the pause menu; otherwise a nonzero render-pass mode selects the pause menu
and zero selects the main menu. The callback is naturally `void`; the stale
EAX value led decompilers to infer a return. Natural C++ matches all 12
instructions and references `5/0/0`.
