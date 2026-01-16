# Sprite atlas cutting (Crimsonland)

This is based on the decompiled engine in `output/crimsonland.exe_decompiled.c`.
The engine does **not** load atlas metadata from disk; all slicing is hard‑coded.

## UV grid tables

`FUN_0041fed0` precomputes UV grids for **2×2, 4×4, 8×8, 16×16**.
It fills tables with `(u, v)` pairs for each cell in row‑major order.
Step sizes:
- 2×2: 0.5
- 4×4: 0.25
- 8×8: 0.125
- 16×16: 0.0625

The renderer later uses these tables to build quads:
- `u0 = table[idx].u`, `v0 = table[idx].v`
- `u1 = u0 + step`, `v1 = v0 + step`

## Sprite table (engine‑hardcoded)

`FUN_0042e0a0` reads a table at **VA 0x004755F0**.
Each entry is `(cell_code, group_id)`; `cell_code` maps to grid size:
- `0x80 → 2`, `0x40 → 4`, `0x20 → 8`, `0x10 → 16`.

Extracted table (index → `(cell_code, group_id)`):
```
0:  (0x80, 0x2)
1:  (0x80, 0x3)
2:  (0x20, 0x0)
3:  (0x20, 0x1)
4:  (0x20, 0x2)
5:  (0x20, 0x3)
6:  (0x20, 0x4)
7:  (0x20, 0x5)
8:  (0x20, 0x8)
9:  (0x20, 0x9)
10: (0x20, 0xA)
11: (0x20, 0xB)
12: (0x40, 0x5)
13: (0x40, 0x3)
14: (0x40, 0x4)
15: (0x40, 0x5)
16: (0x40, 0x6)
```

The `group_id` is passed to the renderer alongside the grid size;
its semantics aren’t obvious from the decompile.

## How slicing is used in practice

The engine uses **two patterns**:

1) **Direct grid selection**: calls the renderer with an explicit grid size
   (`+0x104` with first arg = 2/4/8) and a frame index.

2) **Sprite table selection**: calls `FUN_0042e0a0(index)` which looks up the
   grid size from the table above and passes that to the renderer.

### Known assets and grids

- `game/projs.png` (DAT_0048f7d4)
  - Uses **grid=4** (e.g. `+0x104(4, …)` around `output/crimsonland.exe_decompiled.c:18448`).
  - Uses **grid=2** for some effects (e.g. `+0x104(2, 0)` around `:16479`).

- `game/bonuses.png` (DAT_0048f7f0)
  - Uses **sprite table index 0x10** (call at `:18550`), which maps to **grid=4**.
  - Sheet is 128×128 → 32×32 cells.

- `game/particles.png` (DAT_0048f7ec)
  - Uses **grid=8** for the main particle system (see `+0x104(8, …)` at `:9704`).
  - Uses **sprite table indices 0x10, 0x0e, 0x0d, 0x0c** for UI/overlay effects
    (calls at `:996?`, `:16217`, `:16854`, `:18788`, `:18824`). These indices map to **grid=4**.

- Enemy sheets (`game/zombie.png`, `game/lizard.png`, `game/alien.png`,
  `game/spider_sp1.png`, `game/spider_sp2.png`, `game/trooper.png`)
  - Drawn via **grid=8** (`+0x104(8, …)` in the enemy render path around `:9704`).
  - Per‑enemy base frame offsets are stored in the enemy data struct
    (e.g. `_DAT_00482760 = 0x20`, `_DAT_004827a4 = 0x10`, etc).

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
