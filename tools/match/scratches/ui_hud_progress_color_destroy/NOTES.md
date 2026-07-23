# `ui_hud_progress_color_destroy`

Native target: `crimsonland.exe` at `0x0041ca80` (1 byte).

This one-instruction `ret` is the empty destructor that MSVC registers through
`atexit` for `ui_render_hud`'s function-local static quest-progress color.
The caller and compiler-generated `$E2` relocation identify the ownership.

The natural empty C++ function is an exact 1/1-instruction match.
