# UI weapon icon atlas (ui_wicons.png)

**Source texture:** `ui_wicons.png` (`ui_weapon_icons_texture`, 256×256 RGBA).

The HUD and post‑game stats render weapon icons via:

```
grim_set_sub_rect(8, 2, 1, icon_index << 1)
```

Where `icon_index` is the `effect_subrect_frame_table` entry at weapon table
offset `0x64` (`weapon_table + 0x64 + weapon_id * 0x7c`). This means:

- The atlas is an **8×8** grid of **32×32** cells.
- Each weapon icon spans **2×1** cells → **64×32** pixels.
- Valid `icon_index` range is **0..31** (4 columns × 8 rows).
- `frame` passed to Grim is the **top‑left cell index** (`icon_index * 2`).

## Frame index → weapon IDs

| Icon index | Frame (cell) | Grid (col,row) | Pixel rect (x,y,w,h) | Weapons |
| --- | --- | --- | --- | --- |
| 0 | 0 | (0,0) | (0,0,64,32) | 0 Pistol |
| 1 | 2 | (1,0) | (64,0,64,32) | 1 Assault Rifle |
| 2 | 4 | (2,0) | (128,0,64,32) | 2 Shotgun |
| 3 | 6 | (3,0) | (192,0,64,32) | 3 Sawed-off Shotgun |
| 4 | 8 | (0,1) | (0,32,64,32) | 4 Submachine Gun |
| 5 | 10 | (1,1) | (64,32,64,32) | 5 Gauss Gun |
| 6 | 12 | (2,1) | (128,32,64,32) | 6 Mean Minigun |
| 7 | 14 | (3,1) | (192,32,64,32) | 7 Flamethrower |
| 8 | 16 | (0,2) | (0,64,64,32) | 8 Plasma Rifle |
| 9 | 18 | (1,2) | (64,64,64,32) | 9 Multi-Plasma |
| 10 | 20 | (2,2) | (128,64,64,32) | 10 Plasma Minigun |
| 11 | 22 | (3,2) | (192,64,64,32) | 11 Rocket Launcher |
| 12 | 24 | (0,3) | (0,96,64,32) | 12 Seeker Rockets |
| 13 | 26 | (1,3) | (64,96,64,32) | 13 Plasma Shotgun |
| 14 | 28 | (2,3) | (128,96,64,32) | 14 Blow Torch |
| 15 | 30 | (3,3) | (192,96,64,32) | 15 HR Flamer |
| 16 | 32 | (0,4) | (0,128,64,32) | 16 Mini-Rocket Swarmers |
| 17 | 34 | (1,4) | (64,128,64,32) | 17 Rocket Minigun |
| 18 | 36 | (2,4) | (128,128,64,32) | 18 Pulse Gun |
| 19 | 38 | (3,4) | (192,128,64,32) | 19 Jackhammer |
| 20 | 40 | (0,5) | (0,160,64,32) | 20 Ion Rifle |
| 21 | 42 | (1,5) | (64,160,64,32) | 21 Ion Minigun |
| 22 | 44 | (2,5) | (128,160,64,32) | 22 Ion Cannon |
| 23 | 46 | (3,5) | (192,160,64,32) | 23 Shrinkifier 5k |
| 24 | 48 | (0,6) | (0,192,64,32) | 24 Blade Gun |
| 25 | 50 | (1,6) | (64,192,64,32) | 25 Spider Plasma, 26 Evil Scythe, 27 Plasma Cannon |
| 26 | 52 | (2,6) | (128,192,64,32) | - |
| 27 | 54 | (3,6) | (192,192,64,32) | - |
| 28 | 56 | (0,7) | (0,224,64,32) | 28 Splitter Gun |
| 29 | 58 | (1,7) | (64,224,64,32) | 31 Flameburst |
| 30 | 60 | (2,7) | (128,224,64,32) | 29 Gauss Shotgun, 32 RayGun |
| 31 | 62 | (3,7) | (192,224,64,32) | 30 Ion Shotgun |

## Out-of-range icon indices

The weapon table initializes `icon_index` to `weapon_id` for every entry.
For weapon IDs **≥ 32**, this yields `icon_index > 31`, which would index past
the 8×8 atlas grid. In this build, those entries appear to be **unused or
reserved**, or they rely on an alternate atlas in other versions.

Out-of-range IDs (icon_index > 31): 40 (Plague Sphreader Gun), 41 (Bubblegun),
42 (Rainbow Gun), 43 (Grim Weapon), 44 (Fire bullets), 49 (Transmutator),
50 (Blaster R-300), 51 (Lighting Rifle), 52 (Nuke Launcher).
