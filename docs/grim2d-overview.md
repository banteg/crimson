# Grim2D overview

Grim2D is the game's 2D rendering + input facade exposed by `grim.dll`.
`crimsonland.exe` calls `GRIM__GetInterface` to obtain a vtable-backed object
and then drives all rendering, text, textures, and input queries through the
vtable.

At a high level, Grim2D provides:

- 2D rendering on a Direct3D8 device: textured quads, lines, circles, and UI
  primitives with batching and per-vertex color/UV state.
- Bitmap text rendering for mono and small fonts, with width tables and
  formatted wrappers.
- Texture lifecycle helpers (create, load, validate, destroy) and render target
  switching for offscreen draws.
- Input/config/time helpers: keyboard/mouse/joystick queries, config floats,
  and timing values used by the game loop.
