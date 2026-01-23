---
tags:
  - status-analysis
---

# Terrain pipeline

Below is the **full terrain pipeline** as implemented in the codebase inside your `crimson.zip` (Crimsonland.exe + Grim2D). I’m going to describe it the way you’d need to **rebuild it from scratch**: data/layout, initialization, generation, the decal baking pass, and final draw to the screen — including the exact constants, PRNG, blend/filter states, coordinate conventions, and the slightly weird edge-case behaviors.

---

## 1) What “terrain” is in this engine

The “terrain” is not geometry. It is a **single texture** representing the whole 1024×1024 world background:

* **Normal mode (best quality):**

  * A **render-target texture** named `"ground"` is created.
  * On level start, the game **renders procedural “noise”** into that texture by stamping many rotated quads (3 layers).
  * During gameplay, various decals (blood, scorch, corpses/shadows) are **baked into that same texture** every frame via an FX queue, then the texture is drawn to the screen with camera UV scrolling.

* **Fallback mode (terrain_texture_failed):**

  * No render target is available.
  * The game does not generate terrain; it just chooses a preloaded **tile texture** and draws it repeatedly (256×256 tiles) behind everything.

---

## 2) Key globals / constants

### World size

```c
terrain_texture_width  = 1024;  // 0x400
terrain_texture_height = 1024;  // 0x400
```

These are the **world dimensions** used everywhere (spawns, camera clamp, UV scaling). Terrain is assumed square.

### Terrain render target

* `terrain_render_target` = texture handle to `"ground"` (render target) if available.
* `terrain_texture_failed` = byte flag:

  * `0` → render target works; procedural generation + baked decals.
  * `!=0` → fallback tiling.

### Terrain resolution scaling (important)

Config float: `config_blob.reserved0._112_4_` (I’ll call it `terrain_scale`).

* Clamped to **[0.5, 4.0]**
* Render target size is:

```c
rt_size = (int) (1024.0f / terrain_scale); // truncation toward 0 (__ftol)
```

* When drawing *into* the render target (generation and decals), the game multiplies all positions/sizes by:

```c
inv_scale = 1.0f / terrain_scale;
```

Crucial: when sampling the texture on screen, UV math uses **1024** (world size), so the scale cancels out (because texture size is ~1024/scale and you draw at world/scale).

---

## 3) Asset mapping: terrain texture handles array

There is a contiguous array of 8 terrain stamp textures at `DAT_0048f548`:

Index → texture name loaded in stage 5:

0. `ter_q1_base.jaz`
1. `ter_q1_tex1.jaz`
2. `ter_q2_base.jaz`
3. `ter_q2_tex1.jaz`
4. `ter_q3_base.jaz`
5. `ter_q3_tex1.jaz`
6. `ter_q4_base.jaz`
7. `ter_q4_tex1.jaz`

Fallback mode loads **different** textures:

* `ter_fb_q1.jaz`
* `ter_fb_q2.jaz`
* `ter_fb_q3.jaz`
* `ter_fb_q4.jaz`

…and stores them starting at the same base address. (Only the first four are explicitly assigned in the decompile; this is one of the reasons fallback mode is a bit sketchy if you expect indices like 4/6. More on that later.)

---

## 4) The quest/terrain descriptor structure (what `terrain_generate(desc)` reads)

`terrain_generate(desc)` reads **three int indices** out of the descriptor at:

* `desc + 0x10` → `tex0_index`
* `desc + 0x14` → `tex1_index`
* `desc + 0x18` → `tex2_index`

These indices select entries from the terrain texture handle array above.

In the quest database init helper (`FUN_00430a20`), for tier `t = arg2` and quest-in-tier `q = arg3`:

```c
base = t*2 - 2;   // 0,2,4,6 for t=1..4
alt  = t*2 - 1;   // 1,3,5,7 for t=1..4

tex0 = base;
if (q < 6) { tex1 = alt;  tex2 = base; }
else       { tex1 = base; tex2 = alt;  }
```

So every quest effectively picks:

* Layer 1 texture = base
* Layer 2 texture = either alt or base
* Layer 3 texture = the other one

---

## 5) Initialization: creating the `"ground"` render target

Function: `init_audio_and_terrain @ 0042a9f0`

Core logic:

```c
terrain_texture_width  = 1024;
terrain_texture_height = 1024;

// clamp terrain_scale to [0.5, 4.0]
terrain_scale = clamp(terrain_scale, 0.5f, 4.0f);

if (!terrain_texture_failed) {
    int size1 = (int)(1024.0f / terrain_scale);
    if (!grim_create_texture("ground", size1, size1)) {
        float old = terrain_scale;
        terrain_scale = terrain_scale + terrain_scale; // double (lower res)
        int size2 = (int)(1024.0f / terrain_scale);
        if (!grim_create_texture("ground", size2, size2)) {
            terrain_texture_failed = 1;
            terrain_scale = old; // revert
        }
    }
}
```

So it tries **at most twice**:

* preferred resolution
* half resolution (by doubling scale)
  If both fail → fallback mode.

In later texture-loading stage:

* If success: `terrain_render_target = grim_get_texture_handle("ground")`
* If failure: `terrain_render_target = first fallback tile handle`

---

## 6) PRNG used by terrain generation (exact MSVC rand)

The procedural stamping uses `crt_rand()` which is the MSVC LCG:

```c
static uint32_t g_seed;

void crt_srand(uint32_t seed) { g_seed = seed; }

int crt_rand(void) {
    g_seed = g_seed * 214013u + 2531011u;
    return (g_seed >> 16) & 0x7fff;  // 0..32767
}
```

Terrain generation calls `crt_rand()` in a specific order per stamp:

1. rotation
2. x position
3. y position

If you want byte-for-byte reproducibility, match this.

---

## 7) Terrain generation (procedural) — `terrain_generate(desc) @ 00417b80`

### 7.1 Fallback short-circuit

If `terrain_texture_failed != 0`:

```c
terrain_render_target = terrain_textures[ desc->tex0_index ];
return;
```

No generation. It just picks a tile texture handle to use in the fallback tiler.

### 7.2 Normal mode: draw into the `"ground"` render target

**State setup (exact values):**

* Alpha blend enabled (`config_var 0x12 = 1`)
* Src blend = `5`
* Dst blend = `6`
* Texture filter = `1`
* UV = (0,0)-(1,1)

These values are ultimately Direct3D blend/filter enums (the engine uses numeric constants; typical D3D meaning is: `5 = SRCALPHA`, `6 = INVSRCALPHA`, filter `1 = POINT`, `2 = LINEAR`). ([Microsoft Learn][1])

Then:

* `grim_set_render_target(terrain_render_target)`
* `grim_clear( r=0.24705882, g=0.21960784, b=0.09803922, a=1.0 )`

That clear color equals bytes:

* R = 63/255
* G = 56/255
* B = 25/255
* A = 255/255

### 7.3 The 3 procedural stamp layers

Shared parameters:

```c
inv_scale = 1.0f / terrain_scale;
stamp_size = 128.0f * inv_scale;

// random coordinate range is based on world size (1024), not RT size:
int range = terrain_texture_width + 128; // 1152
// x,y integer random in [-64 .. 1087], then multiplied by inv_scale
```

Rotation per stamp:

```c
rotation = (crt_rand() % 314) * 0.01f; // 0 .. ~3.13 radians (≈ pi)
```

Stamp positions:

```c
x = ( (crt_rand() % (1024+128)) - 64 ) * inv_scale;
y = ( (crt_rand() % (1024+128)) - 64 ) * inv_scale;
```

> Note: it uses width for both axes. Since width==height it’s fine.

---

### Layer 1 (the "heavy" layer)

* Bind texture: `terrain_textures[ desc->tex0_index ]`
* Set vertex color: `(0.7, 0.7, 0.7, 0.9)`
* Stamp count:

```c
count = (terrain_texture_width * terrain_texture_height * 0x320) >> 19;
// Example (1024x1024): (1024*1024*800) >> 19 = 1600
//
// Runtime evidence (Frida, 2026-01-23, `analysis/frida/raw/terrain_trace_rt2.jsonl`):
// observed 1600 stamps in the main-menu generator (`terrain_generate_random`),
// return address `0x418493` (call at `0x41848d`).
```

> **Evidence (Binary Ninja @ 0x417cef):**
> ```c
> edx_7:eax_14 = sx.q(terrain_texture_height * terrain_texture_width * 0x320)
> if ((eax_14 + (edx_7 & 0x7ffff)) s>> 0x13 s> 0)  // 0x13 = 19
> ```

---

### Layer 2 (medium density)

* Bind texture: `terrain_textures[ desc->tex1_index ]`
* Color: `(0.7, 0.7, 0.7, 0.9)`
* Count:

```c
count = (terrain_texture_width * terrain_texture_height * 0x23) >> 19;
// Example (1024x1024): (1024*1024*35) >> 19 = 70
//
// Runtime evidence (Frida, 2026-01-23, `analysis/frida/raw/terrain_trace_rt2.jsonl`):
// observed 70 stamps in the main-menu generator (`terrain_generate_random`),
// return address `0x4185f0` (call at `0x4185ea`).
```

---

### Layer 3 (sparse detail, lower alpha)

* Bind texture: `terrain_textures[ desc->tex2_index ]`
* Color: `(0.7, 0.7, 0.7, 0.6)`
* Count:

```c
count = (terrain_texture_width * terrain_texture_height * 0x0f) >> 19;
// Example (1024x1024): (1024*1024*15) >> 19 = 30
//
// Runtime evidence (Frida, 2026-01-23, `analysis/frida/raw/terrain_trace_rt2.jsonl`):
// observed 30 stamps in the main-menu generator (`terrain_generate_random`),
// return address `0x41874d` (call at `0x418747`).
```

> **Note:** Layer 3 uses `tex2_index` which in the default/random case
> points to the **base texture** (same as layer 1), not the overlay texture.

---

### 7.3.1 Runtime validation: procedural stamp counts (Frida)

In `analysis/frida/raw/terrain_trace_rt2.jsonl` we captured the full procedural
generation pass (three consecutive `set_render_target(0)` sessions). Per pass:

- 1600 stamps @ callsite `0x418493` (layer 1), texture `ter\\ter_q1_base.jaz`, color `(0.7,0.7,0.7,0.9)`
- 70 stamps @ callsite `0x4185f0` (layer 2), texture `ter\\ter_q1_tex1.jaz`,  color `(0.7,0.7,0.7,0.9)`
- 30 stamps @ callsite `0x41874d` (layer 3), texture `ter\\ter_q1_base.jaz`, color `(0.7,0.7,0.7,0.6)`

Each stamp is a 128×128 quad with `x/y ∈ [-64 .. 1087]` (matching the static
range and the intentional overdraw at edges).

Important for interpreting traces: Grim’s `draw_quad_xy` (vtable `0x120`)
immediately calls `draw_quad` (vtable `0x11c`), so you will see **two draw
events per stamp** if you hook both. Count stamps by `draw_quad_xy`.

### 7.4 The exact inner stamp loop

For each layer:

* `grim_begin_batch()`
* Repeat `count` times:

  * compute random `rotation, x, y`
  * `grim_set_rotation(rotation)`
  * `grim_draw_quad_xy(&xy, stamp_size, stamp_size)` (vtable `0x120`)
* `grim_end_batch()`

Important: **x,y are the quad’s top-left**, not center.

---

### 7.5 State restore at end of terrain_generate

After the last batch:

* restore camera offsets (the function temporarily sets `_camera_offset_x/y = 0` while generating)
* restore render state:

The code ends with:

* set srcblend/dstblend back to 5/6
* set filter back to `2` (linear)
* `grim_set_render_target(-1)` (backbuffer)

There is also a weird “toggle” where it sets srcblend to `1` then back to `5` before ending — it has no net effect; replicate if you want bit-identical state churn.

---

## 8) Dynamic terrain decals baked each frame — `fx_queue_render @ 00427920`

This is part of the terrain pipeline because decals are rendered **into** the terrain render target *before* terrain is drawn to screen.

Runtime evidence (Frida, 2026-01-23, `analysis/frida/raw/terrain_trace_rt2.jsonl`):
after the procedural pass, we observed 29 render-target sessions (`set_render_target(0)` → draw → `set_render_target(-1)`)
with 332 total stamped quads, mostly `game\\particles.jaz` (326) plus a few `bodyset` draws (6).

### 8.1 When it runs (render order)

In world rendering, the engine calls:

1. `fx_queue_render()`  ← bakes into terrain texture
2. `terrain_render()`   ← draws the updated terrain to backbuffer
3. draw actors/particles/etc on top

So decals baked this frame appear immediately in the terrain background.

### 8.2 Two separate queues

#### A) Non-rotated FX queue (`fx_queue_count`, max 128)

Struct size is 0x28 (40 bytes), effectively:

```c
struct FxQueueEntry {
    int   effect_id;
    float rotation;     // radians
    float pos_x;        // CENTER position in world coords
    float pos_y;
    float height;       // size
    float width;
    float r, g, b, a;   // vertex tint
};
```

When rendered into terrain RT:

* Convert world center → top-left:

  * `x = (pos_x - width*0.5) * inv_scale`
  * `y = (pos_y - height*0.5) * inv_scale`
  * `w = width * inv_scale`
  * `h = height * inv_scale`

#### B) Rotated “corpse” queue (`fx_queue_rotated`, max 63)

This one is used mainly for **baked corpses** (and their darkening “shadow” pass).

Important convention: **position is already top-left** for rotated entries (call sites subtract size/2 before enqueueing).

Stored arrays effectively represent:

```c
struct FxRotEntry {
    float top_left_x;
    float top_left_y;
    float r,g,b,a;
    float rotation; // radians
    float size;     // drawn as square
    int   creature_type_id; // used to lookup corpse frame
};
```

### 8.3 Alpha adjustment: `terrainBodiesTransparency`

In `fx_queue_add_rotated` (enqueue), alpha is modified:

* If cvar `terrainBodiesTransparency != 0`:

  ```c
  a = a / terrainBodiesTransparency;
  ```
* Else:

  ```c
  a = a * 0.8f;
  ```

This only applies to the rotated/corpse queue.

### 8.4 Baking pass in normal mode (render target available)

If `terrain_texture_failed == 0` and there’s anything queued:

* `grim_set_render_target(terrain_render_target)`
* `set_filter(1)` (POINT) for baking

Then two sub-passes:

---

#### Pass 1: non-rotated FX entries into terrain

State:

* srcblend=5, dstblend=6 (standard alpha blend) ([Microsoft Learn][1])
* bind `particles_texture` (sprite atlas)

Loop:

* `grim_set_color(r,g,b,a)`
* `grim_set_rotation(rotation)`
* `effect_select_texture(effect_id)` sets UV rect based on atlas grid & frame index
* `grim_draw_quad(x, y, w, h)` (with inv_scale applied)

---

#### Pass 2: rotated corpse baking (two draws per corpse)

If there are rotated entries:

* bind `bodyset_texture` (corpse atlas)

Corpse frame selection:

* uses `creature_type_corpse_frame[creature_type_id * 0x11]`

  * meaning creature type records are 17 ints each; the first int is corpse frame index.

UV mapping:

* 4×4 atlas:

  * `u0 = (frame % 4) * 0.25`
  * `v0 = (frame / 4) * 0.25`
  * `u1 = u0 + 0.25`, `v1 = v0 + 0.25`

Rotation:

* uses `rotation - (pi/2)` i.e. `rotation - 1.57079637f`

**There are two draws:**

##### 2A) Darkening “shadow” / imprint pass

State:

* srcblend = `1`
* dstblend = `6`

In D3D terms this is `ZERO` / `INVSRCALPHA`, which means:

> `out = dst * (1 - srcAlpha)`
> So it *darkens* whatever is already in the terrain RT, using the corpse alpha mask. ([Microsoft Learn][1])

Per entry:

* `set_uv(frameRect)`
* `set_color(r,g,b, a * 0.5)`
* `set_rotation(rotation - pi/2)`
* position:

  * There’s a tiny additional offset value:

    ```c
    offset = 1.0f / ( (1024.0f/terrain_scale) * 0.5f );
           = 2.0f * terrain_scale / 1024.0f;
           = terrain_scale / 512.0f;
    ```
  * and they also subtract `0.5` from x/y before scaling:

    ```c
    x = ((top_left_x - 0.5f) * inv_scale) - offset;
    y = ((top_left_y - 0.5f) * inv_scale) - offset;
    ```
* size:

  ```c
  s = size * inv_scale * 1.064f;
  ```
* draw:

  ```c
  draw_quad(x, y, s, s);
  ```

##### 2B) Actual corpse color pass

State:

* srcblend = 5
* dstblend = 6 (normal alpha blend)

Per entry:

* same UV/rotation
* `set_color(r,g,b,a)` (full adjusted alpha)
* position (no `-0.5` here, but still subtracts `offset`):

  ```c
  x = (top_left_x * inv_scale) - offset;
  y = (top_left_y * inv_scale) - offset;
  ```
* size:

  ```c
  s = size * inv_scale;
  ```
* draw quad

---

After baking:

* `fx_queue_count = 0`
* `fx_queue_rotated = 0`
* `grim_set_render_target(-1)`
* restore filter to `2` (linear)

### 8.5 “terrain_texture_failed” branch inside fx_queue_render

There is also code that can draw rotated entries directly to the backbuffer if render targets are unavailable, but:

* `fx_queue_add_rotated` refuses to enqueue if `terrain_texture_failed != 0`, so in practice this branch is typically dead unless something else populates the arrays.

Still, if you want to match behavior, the fallback branch draws a shadow with:

* +2 pixel offset
* scale *1.04
* then draws actual corpse

---

## 9) Drawing terrain to the screen — `terrain_render @ 004188a0`

### 9.1 Optional point filtering for terrain display: `terrainFilter`

There is a console var `terrainFilter`.
If its float value equals **2.0**, then for terrain drawing the engine temporarily does:

```c
set_filter(1); // POINT
```

and afterwards:

```c
set_filter(2); // LINEAR
```

(filter enum values match D3DTEXTUREFILTERTYPE numeric constants ([Microsoft Learn][2]))

### 9.2 Normal mode (render target exists)

Steps:

1. `grim_bind_texture(terrain_render_target)`
2. `grim_set_rotation(0)`
3. `grim_set_color(1,1,1,1)`
4. Compute UV rectangle from camera offset:

```c
u0 = -camera_offset_x / 1024.0f;
v0 = -camera_offset_y / 1024.0f;

u1 = (screen_width  / 1024.0f) + u0;
v1 = (screen_height / 1024.0f) + v0;
```

5. `grim_set_uv(u0,v0,u1,v1)`
6. draw one fullscreen quad (`grim_draw_fullscreen_quad()`):

* geometry is screen-sized
* UV picks the camera window out of the big terrain texture

7. restore filter to linear

**This is the key performance trick:** terrain is always one quad.

### 9.3 Fallback mode (no render target): tile draw

If `terrain_texture_failed != 0`:

1. `grim_bind_texture(terrain_render_target)` (a tile texture)
2. disable alpha blending (config var 0x12 = 0)
3. `grim_begin_batch()`
4. For a 1024×1024 world, tile size is 256.
   Loop:

```c
int tiles_x = (1024 >> 8) + 1; // 4 + 1 = 5
int tiles_y = (1024 >> 8) + 1; // 5

for (int ty=0; ty<tiles_y; ty++) {
  for (int tx=0; tx<tiles_x; tx++) {
    draw_quad(
      tx*256 + camera_offset_x,
      ty*256 + camera_offset_y,
      256, 256
    );
  }
}
```

5. `grim_end_batch()`
6. restore filter=2, alphaBlendEnable=1

---

## 10) Camera offset math (needed because terrain UV scrolling depends on it)

The terrain UV scroll formula assumes `_camera_offset_x/y` are the same offsets used for world→screen of sprites (everything is drawn at `world + camera_offset`).

From `camera_update` logic:

* Desired camera center is player position (or average of players), in world coords.
* Camera offset is:

```c
camera_offset_x = screen_width  * 0.5f - camera_center_x;
camera_offset_y = screen_height * 0.5f - camera_center_y;
```

Then clamped:

```c
// max (don’t go past top/left)
if (camera_offset_x > -1.0f) camera_offset_x = -1.0f;
if (camera_offset_y > -1.0f) camera_offset_y = -1.0f;

// min (don’t go past bottom/right)
float min_x = screen_width  - 1024.0f;
float min_y = screen_height - 1024.0f;

if (camera_offset_x < min_x) camera_offset_x = min_x;
if (camera_offset_y < min_y) camera_offset_y = min_y;
```

That specific “-1” clamp is real and affects UV by 1/1024.

---

## 11) Grim2D “quad + rotation” details you must match for identical visuals

You can’t just do arbitrary rotation and expect exact match: Grim2D implements rotation in a specific way optimized for **square sprites**.

### `grim_set_rotation(radians)`

It internally stores:

* `_grim_rotation_radians = radians`
* `_grim_rotation_cos = cos(radians + π/4)`
* `_grim_rotation_sin = sin(radians + π/4)`

### `grim_draw_quad(x,y,w,h)`

* If rotation == 0 → axis-aligned quad
* Else it computes:

  * `center = (x+w/2, y+h/2)`
  * `half_diag = 0.5 * sqrt(w*w + h*h)`
  * `dx = cos(r+π/4) * half_diag`
  * `dy = sin(r+π/4) * half_diag`
  * corners:

    * (cx - dx, cy - dy)
    * (cx + dy, cy - dx)
    * (cx + dx, cy + dy)
    * (cx - dy, cy + dx)

This produces correct results for **w==h** (which is true for:

* terrain stamps (128×128),
* corpses (square size),
* most rotated decals).

If you rotate non-square quads in this engine, it effectively rotates a “square equivalent”, not a true rectangle. If you’re reimplementing “exactly”, do the same.

---

## 12) Edge cases / gotchas you should preserve (if you want “exact”)

### A) Terrain stamps extend beyond edges

Random x/y range is [-64..1087] (scaled), stamp size is 128 (scaled), so stamps can overlap outside the world texture. That is intentional to avoid edge artifacts.

### B) Rotation range is only ~π, not 2π

`(rand % 314) * 0.01` gives 0..3.13 (≈ π). That’s exact.

### C) Fallback mode texture index mismatch (likely a bug / “never used” path)

* In fallback mode, `terrain_generate(desc)` selects `terrain_textures[desc->tex0_index]`.
* Quest meta generation sets `tex0_index = tier*2-2` which is **0,2,4,6** for tiers 1..4.
* But fallback loading code only clearly sets the first **four** terrain slots.
  If fallback mode is ever used with tier>=3, it may bind unintended textures unless those slots happen to be populated elsewhere.

If you want exact behavior, preserve this as-is.
If you want a *sane* fallback, you’d map `tex0_index_even` → `(tex0_index_even/2)` when in fallback mode.

### D) Tiny offsets in corpse baking

The corpse baking uses:

* `-0.5` shift (shadow pass only)
* subtraction of `offset = terrain_scale/512`
  These are tiny, but if you’re matching pixel-perfect output, replicate them.

---

## 13) Minimal reimplementation checklist

If you’re rebuilding from scratch, you need these components:

1. **Texture manager** returning integer handles (or pointers) by name.
2. **Render target texture** support (“ground”) sized `int(1024/terrain_scale)`.
3. Quad renderer with:

   * global color (RGBA float)
   * global UV rect
   * global rotation implemented like Grim2D (cos/sin with +π/4 trick)
   * alpha blend state control (enable + src/dst factors)
   * filter control (point/linear)
4. **Terrain generator** that:

   * clears RT to (63,56,25)
   * stamps 3 layers with exact counts and random math above
5. **FX queue baking pass** that:

   * draws queued particles and corpses into RT with correct blending
   * resets queues
6. **Terrain draw** that:

   * draws a fullscreen quad with UV based on camera offset / 1024
   * optional point filtering when terrainFilter==2
7. **Camera update** that produces `_camera_offset_x/y` as described.

---

## 14) Rewrite mapping (Python + raylib)

The reference rewrite models this pipeline in:

- `src/grim/terrain_render.py` (generation, decal baking helpers, and screen blit)
- `docs/rewrite/terrain.md` (rewrite-specific notes and TODOs)

---

If you want, I can also output **drop-in C/C++ code** (engine-agnostic) for:

* the exact PRNG,
* the terrain generator,
* the decal queues,
* the UV math + camera clamp,
* and the Grim2D-style rotated-quad vertex builder (so you can feed it to your renderer).

[1]: https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dblend "https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dblend"
[2]: https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dtexturefiltertype "https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dtexturefiltertype"
