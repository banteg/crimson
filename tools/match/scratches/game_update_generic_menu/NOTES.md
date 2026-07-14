# `game_update_generic_menu`

Exact 72-byte, 19-instruction match with MSVC 6.5 `/O2 /GB`; all nine masked
references align.

Live Binary Ninja shows one caller, `game_frame_update`. The helper renders the
full gameplay world when a render pass is active or the game is paused, and
otherwise draws only the terrain. It then overlays the shared fullscreen fade
and updates the generic UI elements, perk prompt, and cursor in order.

The final `ui_cursor_render` is a tail call and the caller ignores the result,
so the earlier `int` signature was decompiler residue; the native source shape
is a `void` coordinator. The Grim virtual call is represented through the
recovered C++ interface rather than a synthetic indirect-call shim.
