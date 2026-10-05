---
tags:
  - status-validation
---

# Sprite atlas cutting (Crimsonland)
This is based on address-keyed analysis of the native renderer and the compact
usage manifest in `analysis/reference/atlas_usage.json`.
The engine does **not** load atlas metadata from disk; all slicing is hard‑coded.

## UV grid tables

`effect_uv_tables_init` precomputes UV grids for **2×2, 4×4, 8×8, 16×16**.
It fills tables with `(u, v)` pairs for each cell in row‑major order.
Step sizes:

- 2×2: 0.5
- 4×4: 0.25
- 8×8: 0.125
- 16×16: 0.0625

`effect_spawn` uses `effect_uv_step_*` constants from the exe as a **UV clamp**,
but Grim’s `set_atlas_frame`/`set_sub_rect` use full grid cells:

- grid2: 0.4921875 (126 px of 128)
- grid4: 0.2421875 (62 px of 64)
- grid8: 0.1171875 (30 px of 32)
- grid16: 0.0546875 (14 px of 16)

This effectively insets the right/bottom edge by 2 pixels to avoid bleeding.
Atlas cells are still laid out on full grid boundaries; the clamp just shrinks
the per‑effect UV rect stored in the effect pool. Runtime capture shows
`set_atlas_frame` on `particles.png` always emits full‑cell UVs (step = 1/grid).
The renderer later uses these tables to build quads:

- `u0 = table[idx].u`, `v0 = table[idx].v`
- `u1 = u0 + step`, `v1 = v0 + step`
## Sprite table (engine‑hardcoded)

`effect_select_texture` (`0x0042e0a0`) reads a table at **VA 0x004755F0**.
Each entry is `(cell_code, group_id)`; `cell_code` maps to grid size:

- `0x80 → 2`, `0x40 → 4`, `0x20 → 8`, `0x10 → 16`.
Extracted table (effect_id → size code + frame index):

| effect_id | size code | grid | frame |
| --- | --- | --- | --- |
| `0x00` | `0x80` | 2 | `0x2` |
| `0x01` | `0x80` | 2 | `0x3` |
| `0x02` | `0x20` | 8 | `0x0` |
| `0x03` | `0x20` | 8 | `0x1` |
| `0x04` | `0x20` | 8 | `0x2` |
| `0x05` | `0x20` | 8 | `0x3` |
| `0x06` | `0x20` | 8 | `0x4` |
| `0x07` | `0x20` | 8 | `0x5` |
| `0x08` | `0x20` | 8 | `0x8` |
| `0x09` | `0x20` | 8 | `0x9` |
| `0x0a` | `0x20` | 8 | `0xa` |
| `0x0b` | `0x20` | 8 | `0xb` |
| `0x0c` | `0x40` | 4 | `0x5` |
| `0x0d` | `0x40` | 4 | `0x3` |
| `0x0e` | `0x40` | 4 | `0x4` |
| `0x0f` | `0x40` | 4 | `0x5` |
| `0x10` | `0x40` | 4 | `0x6` |
| `0x11` | `0x40` | 4 | `0x7` |
| `0x12` | `0x10` | 16 | `0x26` |

The frame index selects a row-major cell in the corresponding UV grid.
`effect_spawn` copies that cell origin and adds the effect-specific UV step to
form four corners; see `decomp/1.9/crimsonland/effects/effect_spawn.cpp`.

Visual note:

- `effect_id 0x12` (grid 16, frame `0x26`) looks like a small brass shell/casing
  sprite rather than a classic muzzle flash.

## Non-uniform sub-rects (grim_set_sub_rect)

The engine sometimes uses Grim2D vtable `0x108` (`grim_set_sub_rect`) to pick a
rectangle that spans multiple grid cells (not a single cell).

Known uses:

- `artifacts/assets/crimson/ui/ui_wicons.png` uses an **8×8** grid but selects **2×1**
  sub-rects. The `frame` argument is derived from the weapon table
  (`weapon_id * 2`) and is reused across HUD + menu renders.

- Some UI paths call `grim_set_sub_rect` twice in a row to draw two adjacent
  slices from the same sheet (split-screen layouts).

## Manual UV overrides (grim_set_uv_point)

Some effects bypass atlas slicing and write UVs directly.

- In `projectile_render`, beam/chain effects (type_id `0x15/0x16/0x17/0x18/0x2d`)
  call `grim_set_uv_point` to force all U values to `0.625` and V to `0..0.25`,
  then draw a quad strip. This targets a thin vertical slice inside
  `projs.png`, so `projs/grid2/frame001` is further sub‑cut at runtime.

- The same path later resets UVs with `grim_set_uv(0,0,1,1)`.
- `grim_set_atlas_frame` itself only takes `(atlas_size, frame)` in `grim.dll`;
  any extra pointer args seen in the decompile are ignored.

## How slicing is used in practice

The engine uses **two patterns**:

1) **Direct grid selection**: calls the renderer with an explicit grid size
   (`+0x104` with first arg = 2/4/8) and a frame index.

2) **Sprite table selection**: calls `effect_select_texture` (`0x0042e0a0`, `index`) which looks up the
   grid size from the table above and passes that to the renderer.

### Known assets and grids

- `artifacts/assets/crimson/game/projs.png` (`projectile_texture` / `0x0048f7d4`)
  - Uses **grid=4** for frames `2`, `3`, and `6`.
  - Uses **grid=2** frame `0` for some effects.
  - Several projectile/beam effects draw **repeated quads** along a vector
    using a single frame (segment tiling instead of unique frames).

  - Beam segments use `grim_set_atlas_frame(4, 2)`. Direction is computed
    separately and used to place the quads; it is not an extra argument to the
    atlas setter. See `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp`.

- `artifacts/assets/crimson/game/bonuses.png` (bonus_texture)
  - Uses **sprite table index 0x10**, which maps to **grid=4**.
  - Sheet is 128×128 → 32×32 cells.

- `artifacts/assets/crimson/game/particles.png` (particles_texture)
  - Uses **grid=8** for the main particle system.
  - Uses **sprite table indices 0x10, 0x0e, 0x0d, 0x0c** for UI/overlay effects
    in UI/overlay draws. These indices map to **grid=4**.

  - Effects pool binds `particles.png` and uses the effect_id table above
    (`0x00..0x12`). Muzzle flash uses `effect_id 0x12` → grid 16, frame `0x26`
    (the sprite itself resembles a shell casing).

- `artifacts/assets/crimson/ui/ui_wicons.png` (`ui_weapon_icons_texture` / `0x0048f7e4`)
  - Uses **grid=8**, but rendered via `grim_set_sub_rect(8, 2, 1, frame)`.
  - This implies each weapon icon spans **2×1 cells** (wider than a single cell).

### Projectile frames (projs.png)

In `projectile_render`, the projectile `type_id` is stored as an int but shows
up as float constants in the decompile (e.g. `2.66247e-44` = `0x13`).

Known `projs.png` frame selections:

| type_id | grid | frame | Source | Notes |
| --- | --- | --- | --- | --- |
| `0x13` | 2 | 0 | Pulse Gun | Draws a small glow/splash; size scales with life. |
| `0x1d` | 4 | 3 | Splitter Gun | Beam/segment style when life is `0.4`. |
| `0x19` | 4 | 6 | Blade Gun | Beam/segment style when life is `0.4`. |
| `0x15` | 4 | 2 | Ion Rifle | Repeated along a vector to build beam/trail segments; also used by Man Bomb (perk id 53). |
| `0x16` | 4 | 2 | Ion Minigun | Repeated along a vector to build beam/trail segments; also used by Man Bomb (perk id 53). |
| `0x17` | 4 | 2 | Ion Cannon | Repeated along a vector to build beam/trail segments. |
| `0x18` | — | — | Shrinkifier 5k | Separate plasma glow path; not a `projs.png` Ion trail. |
| `0x2d` | 4 | 2 | Fire Bullets bonus + Fire Cough perk | Used by the Fire Bullets bonus (bonus id 14) and the Fire Cough perk (perk id 54). The bonus path spawns `weapon_projectile_pellet_count[weapon_id]` pellets per shot. |

The Ion/Fire Bullets trail path first selects `grim_set_atlas_frame(2, 2)`,
then overwrites it with `(4, 2)` before drawing its segments. The initial
selection does not change the segment UVs. Shrinkifier uses the separate plasma
glow path, not this Ion trail branch.

- Enemy sheets (`artifacts/assets/crimson/game/zombie.png`, `artifacts/assets/crimson/game/lizard.png`,
  `artifacts/assets/crimson/game/alien.png`, `artifacts/assets/crimson/game/spider_sp1.png`,
  `artifacts/assets/crimson/game/spider_sp2.png`, `artifacts/assets/crimson/game/trooper.png`)

  - Drawn via **grid=8** in the creature render path.
  - Per‑enemy base frame offsets are stored in the enemy data struct
    (e.g. `creature_type_table[0].base_frame = 0x20`, `creature_type_table[1].base_frame = 0x10`).
## Replicating the atlas cutting

`src/crimson/atlas.py` provides the same slicing math used by the engine:

- `grid_size_from_code(code)`
- `grid_size_for_index(table_index)`
- `uv_for_index(grid, index)`
- `rect_for_index(width, height, grid, index)`
- `slice_index(image, grid, index)`
- `slice_grid(image, grid)`
This is sufficient to reproduce the engine’s sprite cuts for any of the
uniform grids (2/4/8/16).

## Exporting frames and manifests

`scripts/atlas_export.py` slices a sprite sheet into per‑frame PNGs and writes
out a JSON manifest with rect/UV data.

```bash
uv run scripts/atlas_export.py --image artifacts/assets/crimson/game/projs.png --grid 4
```

Outputs:

- Frames under `artifacts/atlas/projs/grid4/` (e.g. `frame_000.png`).
- `manifest.json` with `image`, `grid`, `cell_size`, and `frames` entries.

Use `--indices 0-3,8-11` to export a subset, or `--table-index 0x10` to use the
engine sprite table (grid 4).

### Bulk export

To export all textures in the tracked usage manifest into
`artifacts/atlas/frames/`, run:

```bash
just atlas-export-all
```

The output layout is:

- `artifacts/atlas/frames/<relative_path>/<texture_name>/grid<grid>/frame_###.png`
- `artifacts/atlas/frames/<relative_path>/<texture_name>/grid<grid>/manifest.json`

Manifests include `used_indices` when the static scan reported concrete frame
indices for a grid.

## Atlas usage by texture

The notes below preserve the result of the original static scan. The tracked
`analysis/reference/atlas_usage.json` includes `texture`, `direct`
(`grid`/`index`), and `table_indices` per bound texture. Update it from current
function views when new usage is recovered; it is intentionally not generated
from a whole-program decompile.

They list which grids and indices are used, but not the semantic meaning of
each frame.

- `artifacts/assets/crimson/game/projs.png` (`projs`)
  - Direct grid calls: **4×4** indices `2`, `3`, `6` (plus one call with extra
    parameters using `grid=4, index=2`), and **2×2** index `0`.

  - Table index `0x10` → **4×4**.

- `artifacts/assets/crimson/game/bonuses.png` (`bonuses`)
  - Direct grid calls: **4×4** index `0`, plus dynamic indices `iVar6` and
    `iVar6 + 1` (frame selection happens in code).

- `artifacts/assets/crimson/game/bodyset.png` (`bodyset`)
  - Table index `0x10` → **4×4**.

- `artifacts/assets/crimson/game/particles.png`
  - Table indices `0x10`, `0x0e`, `0x0d`, `0x0c` → **4×4**.
  - Table index `0x02` → **8×8**.
  - Direct grid calls: **2×2**, **4×4**, **8×8**, **16×16** with a dynamic
    index (`uVar2`).

- `ground` texture (terrain)
  - Direct grid call: **8×8** with dynamic index.

## Enemy animation slices (grid 8)

Enemy sheets are cut as 8×8 grids: `creature_render_type` (`0x00418b60`)
selects cells with `grim_set_atlas_frame(8, frame)`. One sheet packs several
animations for a type (the 32-frame long strip, its `+0x20` alternate strip,
and the 8-frame ping-pong strip at `base_frame + 0x10`), and type variants can
share a sheet by using different `base_frame` values.

Frame selection, the per-type `creature_type_table` fields (`anim_rate`,
`base_frame`, `corpse_frame`, `anim_flags`), and the `creature_flags_t` bits
that pick a strip are documented in [Creature animations](../creatures/animations.md).
Per-template flag assignments (from `creature_spawn_template`, keyed by
`template_id`) are in [Creature spawning](../creatures/spawning.md#spawn-template-ids-direct-typeflags-map).
