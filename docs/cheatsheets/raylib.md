# raylib (Python) cheatsheet

This cheatsheet is written for the **PyPI package named `raylib`** (a.k.a. *raylib-python-cffi*), whose public, “pythonic” API lives in the **`pyray`** module and targets **raylib 5.5**. ([Electron Studio][1])
raylib itself is currently at **v5.5** (latest release on the official raylib repo). ([GitHub][2])

---

## 0) Quick start: install + one-file template

### Install

```bash
uv add raylib
```

(That installs the binding; you'll write code using `pyray`.) ([PyPI][3])

### Idiomatic import style

Prefer a module alias (clean namespace, easy grepping):

```py
import pyray as rl
```

The docs/quickstart often use `from pyray import *` for brevity, but it’s not ideal for larger projects. ([PyPI][3])

---

### Type-checker friendly constants (important)

`pyray` exposes many module-level shorthand constants (for example `rl.BLEND_ADDITIVE`), but for typed code you should prefer enum-qualified names:

* Mouse buttons: `rl.MouseButton.MOUSE_BUTTON_*`
* Blend modes: `rl.BlendMode.BLEND_*`
* Texture filters: `rl.TextureFilter.TEXTURE_FILTER_*`
* Texture wraps: `rl.TextureWrap.TEXTURE_WRAP_*`
* Shader uniforms: `rl.ShaderUniformDataType.SHADER_UNIFORM_*`
* Shader locations: `rl.ShaderLocationIndex.SHADER_LOC_*`

`SHADER_LOC_MAP_DIFFUSE` is a backward-compat alias; prefer `SHADER_LOC_MAP_ALBEDO`.

Note: some low-level `RL_*` constants used by `rlgl` calls (for example `RL_FUNC_ADD`, `RL_ZERO`, `RL_ONE`, `RL_SRC_ALPHA`, `RL_ONE_MINUS_SRC_ALPHA`, `RL_QUADS`) exist at runtime but may be missing in stubs, so type checkers can still complain.

---

## 1) The canonical raylib loop (Python)

### Minimal, “always correct” skeleton

```py
import pyray as rl

def main() -> None:
    rl.init_window(960, 540, "raylib-python-cffi template")
    rl.set_target_fps(60)

    try:
        while not rl.window_should_close():
            rl.begin_drawing()
            rl.clear_background(rl.RAYWHITE)

            rl.draw_text("Hello raylib!", 20, 20, 20, rl.DARKGRAY)

            rl.end_drawing()
    finally:
        rl.close_window()

if __name__ == "__main__":
    main()
```

Core lifecycle calls shown above are the ones you *always* want in the right order:

* `init_window(...)` ([Electron Studio][1])
* `set_target_fps(...)` ([Electron Studio][1])
* `window_should_close()` ([Electron Studio][1])
* `begin_drawing()` / `end_drawing()` ([Electron Studio][1])
* `clear_background(...)` ([Electron Studio][1])
* `draw_text(...)` ([Electron Studio][1])
* `close_window()` ([Electron Studio][1])

**Idiomatic Python tip:** wrap the loop with `try/finally` so you *always* close the window, even if you hit an exception.

---

## 2) “Idiomatic Python” structure for raylib games

raylib is fundamentally a C-style “do stuff every frame” library. In Python, the most maintainable pattern is:

* **Keep state in a dataclass**
* **Split update and draw**
* **Use explicit dependencies** (pass state in/out) instead of globals

### A clean structure you can scale

```py
from dataclasses import dataclass
import pyray as rl

@dataclass
class Game:
    pos: rl.Vector2
    vel: rl.Vector2
    radius: float = 24.0

def update(g: Game, dt: float) -> None:
    speed = 240.0
    if rl.is_key_down(rl.KeyboardKey.KEY_A): g.pos.x -= speed * dt
    if rl.is_key_down(rl.KeyboardKey.KEY_D): g.pos.x += speed * dt
    if rl.is_key_down(rl.KeyboardKey.KEY_W): g.pos.y -= speed * dt
    if rl.is_key_down(rl.KeyboardKey.KEY_S): g.pos.y += speed * dt

def draw(g: Game) -> None:
    rl.clear_background(rl.RAYWHITE)
    rl.draw_circle(int(g.pos.x), int(g.pos.y), g.radius, rl.BLUE)
    rl.draw_text("WASD to move", 20, 20, 20, rl.DARKGRAY)

def main() -> None:
    rl.init_window(960, 540, "Idiomatic raylib Python")
    rl.set_target_fps(60)

    g = Game(pos=rl.Vector2(480, 270), vel=rl.Vector2(0, 0))
    try:
        while not rl.window_should_close():
            dt = rl.get_frame_time()

            update(g, dt)

            rl.begin_drawing()
            draw(g)
            rl.end_drawing()
    finally:
        rl.close_window()

if __name__ == "__main__":
    main()
```

Relevant API pieces used here:

* `Vector2(x, y)` exists as a real type (not just tuples). ([Electron Studio][1])
* Key input: `is_key_down(key)` ([Electron Studio][1])
* Keyboard constants live under `KeyboardKey` (e.g. `KEY_A`, `KEY_W`, …). ([Electron Studio][1])
* `draw_circle(...)` ([Electron Studio][1])
* `get_frame_time()` for delta time ([Electron Studio][1])

---

## 3) Data types & “Pythonic” arguments (tuples vs structs)

A big convenience of this binding is that many functions accept **either**:

* a proper struct class (`Vector2`, `Rectangle`, `Camera2D`, …)
* **or** a plain `(x, y)` tuple / list

Examples (types from the docs):

* `Camera2D(offset: Vector2 | list | tuple, target: Vector2 | list | tuple, ...)` ([Electron Studio][1])
* `Rectangle(x, y, width, height)` ([Electron Studio][1])
* `Vector3(x, y, z)` ([Electron Studio][1])

### Rule of thumb

* **Prototyping / tiny scripts:** tuples are fine.
* **Real games / hot loops:** prefer struct instances to avoid repeated conversions and to keep your code self-documenting.

---

## 4) Window configuration & app behavior

### Config flags (vsync, resizable window, etc.)

Use `set_config_flags(flags: int)` to set init-time window flags. ([Electron Studio][1])
Flags live in `ConfigFlags` (e.g. `FLAG_VSYNC_HINT`, `FLAG_WINDOW_RESIZABLE`, …). ([Electron Studio][1])

Example:

```py
import pyray as rl

rl.set_config_flags(
    rl.ConfigFlags.FLAG_VSYNC_HINT | rl.ConfigFlags.FLAG_WINDOW_RESIZABLE
)
rl.init_window(960, 540, "Flags example")
```

([Electron Studio][1])

### Change exit key (default ESC)

```py
rl.set_exit_key(rl.KeyboardKey.KEY_Q)  # quit with Q
```

([Electron Studio][1])

### Toggle fullscreen

```py
if rl.is_key_pressed(rl.KeyboardKey.KEY_F11):
    rl.toggle_fullscreen()
```

([Electron Studio][1])

---

## 5) Input cheatsheet (keyboard + mouse)

### Keyboard

* Held: `is_key_down(key)` ([Electron Studio][1])
* Pressed this frame: `is_key_pressed(key)` ([Electron Studio][1])
* Keys: `KeyboardKey.KEY_*` ([Electron Studio][1])

### Mouse

* Mouse position: `get_mouse_position() -> Vector2` ([Electron Studio][1])
* Button pressed: `is_mouse_button_pressed(button)` ([Electron Studio][1])
* Buttons enum: `MouseButton.MOUSE_BUTTON_LEFT` etc. ([Electron Studio][1])
* Wheel: `get_mouse_wheel_move()` ([Electron Studio][1])

Example:

```py
mp = rl.get_mouse_position()
if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
    print("Clicked at", mp.x, mp.y)
```

([Electron Studio][1])

---

## 6) Drawing cheatsheet (2D essentials)

### Always draw inside `begin_drawing()` / `end_drawing()`

* `begin_drawing()` starts a frame ([Electron Studio][1])
* `end_drawing()` swaps buffers ([Electron Studio][1])

### Clear the frame

```py
rl.clear_background(rl.RAYWHITE)
```

([Electron Studio][1])

### Common primitives

* `draw_text(text, x, y, size, color)` ([Electron Studio][1])
* `draw_rectangle(x, y, w, h, color)` ([Electron Studio][1])
* `draw_circle(x, y, r, color)` ([Electron Studio][1])

### Colors

This binding exposes common named colors like `RAYWHITE`, `DARKGRAY`, etc. ([Electron Studio][1])

---

## 7) Textures & sprites

### Load / draw / unload a texture

```py
tex = rl.load_texture("assets/player.png")
# ...
rl.draw_texture(tex, 100, 100, rl.WHITE)
# ...
rl.unload_texture(tex)
```

API:

* `load_texture(fileName) -> Texture` ([Electron Studio][1])
* `draw_texture(texture, x, y, tint)` ([Electron Studio][1])
* `unload_texture(texture)` ([Electron Studio][1])

### Transform a sprite (position/rotation/scale)

Use `draw_texture_ex(...)`. ([Electron Studio][1])

```py
rl.draw_texture_ex(tex, (200, 200), rotation=45.0, scale=2.0, tint=rl.WHITE)
```

([Electron Studio][1])

### Sprite sheets (source/dest rectangles)

Use `draw_texture_pro(...)` (source rect, dest rect, origin, rotation, tint). ([Electron Studio][1])

```py
src = rl.Rectangle(0, 0, 32, 32)
dst = rl.Rectangle(200, 200, 64, 64)     # scale x2
origin = (32, 32)                        # rotate about center
rl.draw_texture_pro(tex, src, dst, origin, rotation=0.0, tint=rl.WHITE)
```

([Electron Studio][1])

---

## 8) Cameras (2D & 3D)

### 2D Camera

Create a `Camera2D` and draw your world inside `begin_mode_2d(camera)` / `end_mode_2d()`. ([Electron Studio][1])

```py
cam = rl.Camera2D(
    offset=(480, 270),   # screen center
    target=(0, 0),       # world point at center
    rotation=0.0,
    zoom=1.0
)

rl.begin_drawing()
rl.clear_background(rl.RAYWHITE)

rl.begin_mode_2d(cam)
# draw WORLD here (positions in world space)
rl.draw_circle(0, 0, 10, rl.RED)
rl.end_mode_2d()

# draw UI here (screen space)
rl.draw_text("2D camera", 20, 20, 20, rl.DARKGRAY)
rl.end_drawing()
```

([Electron Studio][1])

### 3D Camera

Create `Camera3D` and draw inside `begin_mode_3d(camera)` / `end_mode_3d()`. ([Electron Studio][1])

Minimal 3D scene helpers:

* `draw_grid(slices, spacing)` ([Electron Studio][1])
* `draw_cube(position, w, h, length, color)` ([Electron Studio][1])

```py
cam3 = rl.Camera3D(
    position=(4, 4, 4),
    target=(0, 0, 0),
    up=(0, 1, 0),
    fovy=45.0,
    projection=rl.CameraProjection.CAMERA_PERSPECTIVE
)

rl.begin_drawing()
rl.clear_background(rl.RAYWHITE)

rl.begin_mode_3d(cam3)
rl.draw_grid(20, 1.0)
rl.draw_cube((0, 0.5, 0), 1.0, 1.0, 1.0, rl.BLUE)
rl.end_mode_3d()

rl.end_drawing()
```

([Electron Studio][1])

---

## 9) Render textures (draw to a texture, then draw that texture)

### Core calls

* `load_render_texture(w, h) -> RenderTexture` ([Electron Studio][1])
* `begin_texture_mode(target)` / `end_texture_mode()` ([Electron Studio][1])
* `unload_render_texture(target)` ([Electron Studio][1])
* `RenderTexture` has a `.texture` field you can draw like a normal texture. ([Electron Studio][1])

Example:

```py
rt = rl.load_render_texture(320, 180)

# draw scene into rt
rl.begin_texture_mode(rt)
rl.clear_background(rl.BLANK)
rl.draw_circle(160, 90, 40, rl.RED)
rl.end_texture_mode()

# draw rt.texture onto screen
rl.begin_drawing()
rl.clear_background(rl.RAYWHITE)
rl.draw_texture_ex(rt.texture, (0, 0), 0.0, 3.0, rl.WHITE)  # scale up 3x
rl.end_drawing()
```

([Electron Studio][1])

---

## 10) Audio (sounds + streaming music)

### One-time init/teardown

* `init_audio_device()` ([Electron Studio][1])
* `close_audio_device()` ([Electron Studio][1])

### Sound effects

* `load_sound(fileName) -> Sound` ([Electron Studio][1])
* `play_sound(sound)` ([Electron Studio][1])
* `unload_sound(sound)` ([Electron Studio][1])

### Music streams (must be updated every frame)

* `load_music_stream(fileName) -> Music` ([Electron Studio][1])
* `play_music_stream(music)` ([Electron Studio][1])
* `update_music_stream(music)` ([Electron Studio][1])
* `unload_music_stream(music)` ([Electron Studio][1])

Example:

```py
rl.init_audio_device()
snd = rl.load_sound("assets/jump.wav")
msc = rl.load_music_stream("assets/theme.ogg")
rl.play_music_stream(msc)

try:
    while not rl.window_should_close():
        rl.update_music_stream(msc)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            rl.play_sound(snd)

        rl.begin_drawing()
        rl.clear_background(rl.RAYWHITE)
        rl.draw_text("SPACE: play sound", 20, 20, 20, rl.DARKGRAY)
        rl.end_drawing()
finally:
    rl.unload_sound(snd)
    rl.unload_music_stream(msc)
    rl.close_audio_device()
```

([Electron Studio][1])

---

## 11) Collision helpers (2D)

Two common ones:

* Rectangle-vs-rectangle: `check_collision_recs(rec1, rec2) -> bool` ([Electron Studio][1])
* Point-in-triangle: `check_collision_point_triangle(...) -> bool` ([Electron Studio][1])

Pattern:

```py
r1 = rl.Rectangle(10, 10, 50, 50)
r2 = rl.Rectangle(40, 40, 50, 50)

if rl.check_collision_recs(r1, r2):
    rl.draw_text("hit!", 20, 80, 20, rl.RED)
```

([Electron Studio][1])

---

## 12) Must-remember “paired calls” (don’t leak resources)

**Frames**

* `begin_drawing()` ↔ `end_drawing()` ([Electron Studio][1])

**Camera modes**

* `begin_mode_2d(cam)` ↔ `end_mode_2d()` ([Electron Studio][1])
* `begin_mode_3d(cam)` ↔ `end_mode_3d()` ([Electron Studio][1])

**Render textures**

* `begin_texture_mode(rt)` ↔ `end_texture_mode()` ([Electron Studio][1])
* `load_render_texture(...)` ↔ `unload_render_texture(...)` ([Electron Studio][1])

**GPU textures**

* `load_texture(...)` ↔ `unload_texture(...)` ([Electron Studio][1])

**Window**

* `init_window(...)` ↔ `close_window()` ([Electron Studio][1])

**Audio**

* `init_audio_device()` ↔ `close_audio_device()` ([Electron Studio][1])

---

## 13) Performance & “idiomatic Python” pitfalls (important!)

### 1) Avoid doing “a thousand tiny C calls” per frame

Crossing the Python↔C boundary costs time. The project’s own performance notes call this out and recommend doing most calculations in Python and only calling into raylib when you actually need to draw/play audio/etc. ([PyPI][3])

**Practical advice:**

* Batch your drawing where possible.
* Avoid per-frame allocations of lots of new `Vector2`/`Rectangle` objects in tight loops.
* Keep your update logic in Python data (floats, lists), then convert to raylib structs when drawing.

### 2) Prefer explicit imports

For real projects:

```py
import pyray as rl
```

Star imports are fine for learning, but they make refactors harder (and can shadow names). (The official quickstart uses star import for simplicity.) ([PyPI][3])

### 3) Centralize resource ownership

Have one place that loads/unloads textures, sounds, fonts. Make it impossible to “forget” an unload.

---

## 14) “Latest API” notes (what to rely on)

* **raylib upstream:** currently **v5.5**. ([GitHub][2])
* **Python binding docs used here:** explicitly “Python Bindings for Raylib 5.5”. ([Electron Studio][1])
* **PyPI package:** `raylib` (raylib-python-cffi), with a 5.5.x release line (e.g. **5.5.0.4** shown in the PyPI release history). ([PyPI][3])

If you stick to the function names/signatures shown above (all pulled from the binding’s current docs), you’re aligned with the **latest documented Python API for raylib 5.5**. ([Electron Studio][1])

---

If you want, tell me whether you’re building **2D-only**, **3D**, or a **tools/UI app**, and I’ll condense this into a one-page “printable” cheatsheet tailored to that use case (with just the functions you’ll touch daily).

[1]: https://electronstudio.github.io/raylib-python-cffi/pyray.html "https://electronstudio.github.io/raylib-python-cffi/pyray.html"
[2]: https://github.com/raysan5/raylib/releases "https://github.com/raysan5/raylib/releases"
[3]: https://pypi.org/project/raylib/ "https://pypi.org/project/raylib/"
