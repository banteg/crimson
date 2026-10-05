---
tags:
  - status-analysis
---

# Terrain pipeline

This page describes the terrain pipeline of `crimsonland.exe` + `grim.dll`
(v1.9.93): data layout, initialization, generation, decal baking and the final
draw. Recovered sources:

- `decomp/1.9/crimsonland/crimsonland/init_audio_and_terrain.cpp`
- `decomp/1.9/crimsonland/crimsonland/load_textures_step.cpp`
- `decomp/1.9/crimsonland/quests/quest_meta_init_entry.cpp`
- `decomp/1.9/crimsonland/ui_render/terrain_generate.cpp`
- `decomp/1.9/crimsonland/ui_render/terrain_generate_random.cpp`
- `decomp/1.9/crimsonland/crimsonland/fx_queue_add.cpp`,
  `decomp/1.9/crimsonland/crimsonland/fx_queue_add_rotated.c`,
  `decomp/1.9/crimsonland/crimsonland/fx_queue_render.cpp`
- `decomp/1.9/crimsonland/ui_render/terrain_render.cpp`
- `decomp/1.9/crimsonland/game/camera_update.cpp`
- `decomp/1.9/grim/render/set_rotation.cpp`, `decomp/1.9/grim/render/draw_quad.cpp`

---

## 1) What “terrain” is in this engine

The “terrain” is not geometry. It is a **single texture** representing the whole 1024×1024 world background:

* **Normal mode:**

  * A **render-target texture** named `"ground"` is created.
  * On level start, the game **renders procedural “noise”** into that texture by stamping many rotated quads (3 layers).
  * During gameplay, decals (blood, scorch, corpses) are **baked into that same texture** every frame via an FX queue, then the texture is drawn to the screen with camera UV scrolling.

* **Fallback mode (`terrain_texture_failed`, “safemode”):**

  * No render target is available.
  * The game does not generate terrain; it picks a preloaded **tile texture** and draws it repeatedly (256×256 tiles) behind everything.

---

## 2) Key globals / constants

### World size

```c
terrain_texture_width  = 1024;  // 0x400
terrain_texture_height = 1024;  // 0x400
```

These are the **world dimensions** used everywhere (spawns, camera clamp, UV scaling).

### Terrain render target

* `terrain_render_target` = texture handle of `"ground"` (render target), or a tile texture in fallback mode.
* `terrain_texture_failed` = byte flag:

  * `0` → render target works; procedural generation + baked decals.
  * `!=0` → fallback tiling.

### Terrain resolution scaling

Config float: `config_blob.texture_scale` (`config_texture_scale`).

* Clamped to **[0.5, 4.0]**
* Render target size is:

```c
rt_size = (int) (1024.0f / texture_scale); // truncation toward 0 (__ftol)
```

* When drawing *into* the render target (generation and decals), positions and sizes are multiplied by:

```c
inv_scale = 1.0f / texture_scale;
```

When sampling the texture on screen, UV math uses **1024** (world size), so the scale cancels out.

---

## 3) Terrain texture handles

`terrain_texture_handles` is a contiguous array of 8 stamp textures, loaded in
`load_textures_step` stage 5:

0. `ter\ter_q1_base.jaz`
1. `ter\ter_q1_tex1.jaz`
2. `ter\ter_q2_base.jaz`
3. `ter\ter_q2_tex1.jaz`
4. `ter\ter_q3_base.jaz`
5. `ter\ter_q3_tex1.jaz`
6. `ter\ter_q4_base.jaz`
7. `ter\ter_q4_tex1.jaz`

In fallback mode the same stage loads only four tiles into slots `0..3`
(`ter\fb_q1.jaz` … `ter\fb_q4.jaz`) and sets `terrain_render_target` to slot `0`.
Slots `4..7` are not loaded in fallback mode.

---

## 4) Terrain ids in `quest_meta_t`

`terrain_generate(quest_meta_t *quest)` reads three slot indices from the quest
descriptor (`quest_meta_t` in `third_party/headers/crimsonland_types.h`):

* `+0x10` → `terrain_id` (layer 1)
* `+0x14` → `terrain_id_b` (layer 2)
* `+0x18` → `terrain_id_c` (layer 3)

`quest_meta_init_entry` (`0x00430a20`) fills them for tier `t` and quest index `q` (both 1-based):

```c
terrain_id = t*2 - 2;               // base: 0,2,4,6 for t=1..4
if (q > 5) { terrain_id_b = t*2 - 2; terrain_id_c = t*2 - 1; }
else       { terrain_id_b = t*2 - 1; terrain_id_c = t*2 - 2; }

if (t >= 5) { terrain_id = q % 4; terrain_id_b = 1; terrain_id_c = 3; }
```

So quests 1–5 of a tier use `(base, overlay, base)` and quests 6–10 use
`(base, base, overlay)`. The rewrite mirrors this in `terrain_slots_for_quest`
(`src/crimson/terrain_slots.py`).

---

## 5) Initialization: creating the `"ground"` render target

Function: `init_audio_and_terrain @ 0x0042a9f0`

```c
terrain_texture_width  = 1024;
terrain_texture_height = 1024;

texture_scale = clamp(texture_scale, 0.5f, 4.0f);

if (!terrain_texture_failed) {
    int size1 = (int)(1024.0f / texture_scale);
    if (!grim_create_texture("ground", size1, size1)) {
        float old = texture_scale;
        texture_scale = texture_scale + texture_scale; // half resolution
        int size2 = (int)(1024.0f / texture_scale);
        if (!grim_create_texture("ground", size2, size2)) {
            terrain_texture_failed = 1;
            texture_scale = old;
        }
    }
}
```

It tries the preferred resolution, then half resolution; if both fail it logs
`"Running in safemode, using static terrain textures."` and uses fallback mode.

`load_textures_step` stage 8 then sets `terrain_render_target = grim_get_texture_handle("ground")`
when the render target exists (fallback mode already set it in stage 5).

---

## 6) PRNG

Stamping uses `crt_rand()`, the MSVC LCG:

```c
static uint32_t g_seed;

void crt_srand(uint32_t seed) { g_seed = seed; }

int crt_rand(void) {
    g_seed = g_seed * 214013u + 2531011u;
    return (g_seed >> 16) & 0x7fff;  // 0..32767
}
```

Per stamp the draws are **rotation, then y, then x**: the position is built as
`terrain_vec2_t(rand_x_expr, rand_y_expr)` and MSVC evaluates constructor
arguments right to left.

---

## 7) Terrain generation — `terrain_generate(desc) @ 0x00417b80`

### 7.1 Fallback short-circuit

`camera_offset` is zeroed first. If `terrain_texture_failed != 0`:

```c
terrain_render_target = terrain_texture_handles[desc->terrain_id];
return;
```

No generation; the fallback tiler draws that handle. Because only slots `0..3`
are loaded in fallback mode, quest tiers 1–2 pick `fb_q1` / `fb_q3` and tiers
3–4 pick the unloaded slots `4` / `6`.

### 7.2 Normal mode: state setup

* `grim_set_config_var(0x12, 1)` — alpha blend on
* `0x13` (src blend) = `5` (`D3DBLEND_SRCALPHA`)
* `0x14` (dst blend) = `6` (`D3DBLEND_INVSRCALPHA`)
* `0x15` (texture filter) = `1` (`D3DTEXF_POINT`)
* UV = (0,0)-(1,1)
* `grim_set_render_target(terrain_render_target)`
* `grim_clear_color(0.24705882, 0.21960784, 0.09803922, 1.0)` — bytes `(63, 56, 25, 255)`

### 7.3 The 3 stamp layers

Shared parameters:

```c
stamp_size = 128.0f * inv_scale;
rotation   = (crt_rand() % 314) * 0.01f;                      // 0 .. 3.13 rad (~pi)
y          = ((crt_rand() % (terrain_texture_width + 128)) - 64) * inv_scale;
x          = ((crt_rand() % (terrain_texture_width + 128)) - 64) * inv_scale;
```

Both axes use the width (fine, the world is square). Coordinates are in
`[-64 .. 1087]` before scaling, so stamps overdraw the edges.

| Layer | Texture | Color | Count (`w*h*k / 0x80000`) | 1024×1024 |
| --- | --- | --- | --- | --- |
| 1 | `terrain_id` | `(0.7, 0.7, 0.7, 0.9)` | `k = 800` | 1600 |
| 2 | `terrain_id_b` | `(0.7, 0.7, 0.7, 0.9)` | `k = 35` | 70 |
| 3 | `terrain_id_c` | `(0.7, 0.7, 0.7, 0.6)` | `k = 15` | 30 |

Each layer is:

* `grim_bind_texture(handle)`, `grim_set_color(...)`, `grim_begin_batch()`
* repeat `count` times: `grim_set_rotation(rotation)`, then
  `grim_draw_quad_xy(&xy, stamp_size, stamp_size)` (vtable `0x120`, which
  forwards to `grim_draw_quad`, vtable `0x11c`)
* `grim_end_batch()`

**x,y are the quad’s top-left**, not its center.

### 7.4 End of `terrain_generate`

* `camera_offset` is zeroed again (it is not saved/restored)
* src/dst blend `5`/`6`, color `(1,1,1,1)`, then src blend `1` and back to `5`
  (no net effect), dst blend `6`
* filter back to `2` (`D3DTEXF_LINEAR`)
* `grim_set_render_target(-1)` (backbuffer)

---

## 8) Menu terrain — `terrain_generate_random @ 0x004181b0`

1. Three `crt_rand() % 7` values are drawn into `terrain_texture_selectors`
   and then overwritten with `0, 1, 0`, so the default slots are always
   `(q1 base, q1 tex1, q1 base)` but three RNG values are consumed.
2. Progression may substitute a quest descriptor, each check drawing a
   `crt_rand()` only when its unlock threshold is met:
   * `quest_unlock_index >= 40` and `(crt_rand() & 7) == 3` → quest 4.2 descriptor `(6,7,6)`
   * else `>= 30` and `(crt_rand() & 7) == 3` → quest 3.2 descriptor `(4,5,4)`
   * else `>= 20` and `(crt_rand() & 7) == 3` → quest 2.2 descriptor `(2,3,2)`

   A hit calls `terrain_generate(desc)` and returns.
3. Otherwise it zeroes `camera_offset`, returns early in fallback mode (leaving
   `terrain_render_target` unchanged), and runs the same three-layer stamping
   as section 7 with the default slots. With `verbose` set it logs `"- Generated terrain."`.

Callers: `game_startup_init_prelude`, `gameplay_reset_state`, the
`generateterrain` console command, and `ui_elements_update_and_render` when
leaving demo mode for the main menu. `quest_start_selected` and the demo setups
call `terrain_generate` directly. See also
[Main menu: menu terrain selection](main-menu.md#menu-terrain-selection-terrain_generate_random).

### Regeneration after render-target loss

Grim sets config slot `0x57` when the device is reset or texture contents
cannot be restored. `game_frame_update` checks it every frame, regenerates the
terrain and clears it: in quest mode (while `run_active` is set) it calls
`terrain_generate(&quest_meta_table[(quest_stage_minor-1)%10 * 10 + (quest_stage_major-1)%4])`
— major and minor are swapped relative to the table layout (`(tier-1)*10 + (index-1)`),
so the regenerated ground generally belongs to a different quest — and otherwise
`terrain_generate_random()`. Baked decals are lost either way.

---

## 9) Dynamic decals baked each frame — `fx_queue_render @ 0x00427920`

Decals are rendered **into** the terrain render target before the terrain is
drawn to the screen. In `gameplay_render_world` the order is:

1. `fx_queue_render()` ← bakes into the terrain texture
2. `terrain_render()`  ← draws the updated terrain to the backbuffer
3. players, creatures, projectiles, bonuses on top

So decals baked this frame appear immediately.

### 9.1 Two queues

#### A) Non-rotated FX queue (`fx_queue`, `fx_queue_count`)

`fx_queue_add @ 0x0041e840` fills a `0x28`-byte `fx_queue_entry_t`:

```c
struct fx_queue_entry_t {
    int   effect_id;
    float rotation;     // radians
    float pos_x;        // CENTER position in world coords
    float pos_y;
    float height;
    float width;
    float r, g, b, a;   // vertex tint
};
```

The queue holds 128 entries: when the count reaches `0x80` it is clamped to
`0x7f` and the call returns `0`, so further adds overwrite the last slot.

#### B) Rotated corpse queue (`fx_queue_rotated`, max 63)

`fx_queue_add_rotated @ 0x00427840` fills parallel arrays:
`fx_rotated_pos_x` (top-left `vec2`; call sites subtract size/2), `fx_rotated_color_r`
(RGBA), `fx_rotated_rotation`, `fx_rotated_scale` (drawn as a square) and
`fx_rotated_creature_type_id` (a creature type id used to look up the corpse frame).

It does nothing (but still returns `1`) when `terrain_texture_failed != 0`, and
returns `0` when the queue already holds `0x3f` entries. Alpha is adjusted on
enqueue by the `terrainBodiesTransparency` cvar:

```c
if (terrainBodiesTransparency == 0) a *= 0.8f;
else                                a *= 1.0f / terrainBodiesTransparency;
```

### 9.2 Baking pass (render target available)

If either queue is non-empty: `grim_set_render_target(terrain_render_target)`
and bind `particles_texture`. Blend and filter state are inherited from the
caller (no filter change here).

**Pass 1: non-rotated entries** (inside one batch, UV reset to (0,0)-(1,1)):

* `grim_set_color_ptr(&entry->color)`
* `grim_set_rotation(entry->rotation)`
* `effect_select_texture(effect_id)` sets the atlas UV rect
* `grim_draw_quad((pos_x - width*0.5) * inv_scale, (pos_y - height*0.5) * inv_scale, width * inv_scale, height * inv_scale)`

**Pass 2: rotated corpses** (two draws per corpse), bound to `bodyset_texture`:

* frame = `creature_type_table[effect_id].corpse_frame`
* UV = `effect_uv4[frame]` to `effect_uv4[frame] + (0.25, 0.25)` (4×4 atlas)
* rotation = `rotation - 1.5707964f`
* `half_texel = 1.0f / ((terrain_texture_width / texture_scale) * 0.5f)` (= `texture_scale / 512`)

2A) Darkening imprint, src blend `1` (`ZERO`), dst blend `6` (`INVSRCALPHA`),
so `out = dst * (1 - srcAlpha)`:

```c
set_color(r, g, b, a * 0.5f);
x = (pos.x - 0.5f) * inv_scale - half_texel;
y = (pos.y - 0.5f) * inv_scale - half_texel;
s = size * inv_scale * 1.064f;
draw_quad(x, y, s, s);
```

2B) Corpse color, src/dst blend `5`/`6`:

```c
set_color(r, g, b, a);
x = pos.x * inv_scale - half_texel;
y = pos.y * inv_scale - half_texel;
s = size * inv_scale;
draw_quad(x, y, s, s);
```

After baking: `fx_queue_count = 0`, `fx_queue_rotated = 0`,
`grim_set_render_target(-1)`.

### 9.3 Fallback branch

With `terrain_texture_failed != 0`, `fx_queue_render` would draw rotated
entries straight to the backbuffer (shadow at `+2,+2` offset and `size * 1.04`,
then the corpse, both offset by the camera), but `fx_queue_add_rotated` never
enqueues in that mode, so the branch is dead. The non-rotated queue is neither
drawn nor cleared there; it is only reset by `gameplay_reset_state` and
`quest_start_selected`.

---

## 10) Drawing terrain to the screen — `terrain_render @ 0x004188a0`

If the `terrainFilter` cvar equals **2.0**, the filter is set to `1` (point)
first. Both branches set it back to `2` (linear) at the end.

### 10.1 Normal mode

1. `grim_bind_texture(terrain_render_target)`
2. `grim_set_rotation(0)`, `grim_set_color(1,1,1,1)`
3. UV window from the camera offset:

```c
u0 = -camera_offset_x / terrain_texture_width;
v0 = -camera_offset_y / terrain_texture_height;
u1 = screen_width  / (float)terrain_texture_width  + u0;
v1 = screen_height / (float)terrain_texture_height + v0;
```

4. `grim_set_uv(u0, v0, u1, v1)` and `grim_draw_fullscreen_quad(0)`

Terrain is always one quad.

### 10.2 Fallback mode: tiles

1. `grim_bind_texture(terrain_render_target)` (a tile texture)
2. alpha blending off (`0x12 = 0`), `grim_begin_batch()`, color white, UV (0,0)-(1,1), rotation 0
3. draw `(height/256 + 1) × (width/256 + 1)` = 5×5 tiles:

```c
for (ty = 0; ty < 1024/256 + 1; ty++)
  for (tx = 0; tx < 1024/256 + 1; tx++)
    draw_quad(tx*256 + camera_offset_x, ty*256 + camera_offset_y, 256, 256);
```

4. `grim_end_batch()`, filter `2`, alpha blending back on

---

## 11) Camera offset — `camera_update @ 0x00409500`

All world sprites are drawn at `world + camera_offset`, and the terrain UVs
use the same offset.

```c
camera_offset_x = (screen_width  / 2) - center_x;   // integer halving
camera_offset_y = (screen_height / 2) - center_y;
```

The center is the single player, the surviving player, or the midpoint of both
living players (if both are dead, `x` is kept from the last value and `y` is
preserved). Camera shake is added, then:

```c
if (camera_offset_x > -1.0f) camera_offset_x = -1.0f;
if (camera_offset_y > -1.0f) camera_offset_y = -1.0f;
if (camera_offset_x < screen_width  - 1024.0f) camera_offset_x = screen_width  - 1024.0f;
if (camera_offset_y < screen_height - 1024.0f) camera_offset_y = screen_height - 1024.0f;
```

The `-1` clamp shifts the UV by 1/1024.

---

## 12) Grim2D rotated quads

### `grim_set_rotation(radians)` (`grim.dll 0x10007f30`)

* `grim_rotation_radians = radians`
* `grim_rotation_cos = cos(radians + π/4)`
* `grim_rotation_sin = sin(radians + π/4)`

### `grim_draw_quad(x, y, w, h)` (`grim.dll 0x10008b10`)

* rotation == 0 → axis-aligned quad
* otherwise:

  * `center = (x + w/2, y + h/2)`
  * `length_sq = w*w + h*h`
  * `half_diag = 0.5 * length_sq * inverse_sqrt(length_sq)`, where
    `inverse_sqrt` uses the `0x5f3759df` seed and one Newton step (no CRT `sqrt`)
  * `dx = cos(r+π/4) * half_diag`, `dy = sin(r+π/4) * half_diag`
  * corners: `(cx - dx, cy - dy)`, `(cx + dy, cy - dx)`, `(cx + dx, cy + dy)`, `(cx - dy, cy + dx)`

This is exact only for **w == h** (terrain stamps, corpses, most rotated
decals); a non-square quad is rotated as its square equivalent.

---

## 13) Details to preserve for exact output

* Stamps extend beyond the edges (`[-64 .. 1087]` + 128).
* Rotation range is only `0 .. 3.13` rad.
* RNG order per stamp: rotation, y, x; `terrain_generate_random` burns three
  values before the progression checks.
* Fallback mode indexes `terrain_texture_handles` with quest slot ids `0,2,4,6`
  although only `0..3` are loaded.
* Corpse baking: the `-0.5` shift (imprint pass only) and the `half_texel`
  subtraction (both passes).

---

## 14) Rewrite mapping (Python + raylib)

The reference rewrite models this pipeline in:

- `src/crimson/sim/terrain_generate.py` (the RNG draws and the stamps of both generators)
- `src/grim/terrain_render.py` (stamp drawing, decal baking helpers, and screen blit)
- `docs/rewrite/terrain.md` (rewrite-specific notes)
