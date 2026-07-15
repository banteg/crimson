# `ui_render_aim_indicators`

Native target: `crimsonland.exe` at `0x0040a510` (1,402 bytes).

Live Binary Ninja evidence shows three distinct player passes over the shared
0x360-byte player records. The first draws the spread radius, textured outline,
and reload gauge at the camera-adjusted aim point. The second draws the optional
per-player direction arrow, using the configured move target for point-and-click
players and a 60-unit heading projection otherwise. The third delegates the
camera-adjusted aim point to `ui_render_aim_enhancement`.

The two one-shot flag bits and adjacent empty cleanup thunks are ordinary VC6
function-local-static lifetime machinery. The recovered source retains real C++
statics so the compiler emits those guards and `atexit` registrations naturally.
The direction-arrow colors and 0.3/0.6 alpha policy agree with the existing
native-derived port implementation in `src/crimson/render/world/overlays.py`.

The exact VC6.5 result is 343/343 instructions with references `105/0/0`.
Restoring vector addition also recovers the otherwise non-obvious evaluation
order in the heading path: `(camera_offset + player_position) + direction * 60`
is evaluated as the native x87 stack sequence before subtracting the 16-pixel
quad inset.
