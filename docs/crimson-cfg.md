---
tags:
  - status-draft
---

# Crimson config blob (crimson.cfg)

`crimson.cfg` is the fixed-size configuration blob used by the classic
Crimsonland executable. It is **not** the save/status file (that is `game.cfg`).

## Location and size

- Path: `game_base_path\\crimson.cfg` (built via `game_build_path`).
- Size: **0x480 bytes** (1152 bytes).
- Endianness: little-endian for integer/float fields.

Observed file:

- `game_bins/crimsonland/1.9.93-gog/crimson.cfg`
  - size 0x480
  - width 1024, height 768
  - windowed flag = 1
  - texture scale = 1.0

## Load / write behavior

From the decompile (see `docs/detangling.md`):

- `config_load_presets` reads the 0x480-byte blob into `config_blob`.
- `config_sync_from_grim`:
  - seeds a default blob (in memory)
  - reads Grim config values (vtable +0x24)
  - loads `crimson.cfg` overrides when present
  - writes the 0x480-byte blob back out
- `config_ensure_file` writes `crimson.cfg` when missing.

This means the file is treated as a **fixed struct** and rewritten wholesale.

## Field layout (partial)

Base address in the decompile is `DAT_00480348`. Offsets below are relative to
the blob start.

| Offset | Size | Default | Notes |
| --- | --- | --- | --- |
| `0x00` | `u8` | `0` | Sound disable flag (nonzero skips SFX and music init; applied via config id `0x53`). |
| `0x01` | `u8` | `0` | Music disable flag (music init requires sound flag == 0). |
| `0x02` | `u8` | `0` | High-score date validation mode. |
| `0x03` | `u8` | `0` | High-score duplicate handling. |
| `0x04` | `u8[2]` | `1,1` | Per-player HUD indicator toggle. |
| `0x08` | `u32` | `8` | Unknown; set during `config_sync_from_grim`. |
| `0x0e` | `u8` | `0/1` | FX detail toggle (set by detail preset). |
| `0x10` | `u8` | `0/1` | FX detail toggle (set by detail preset). |
| `0x11` | `u8` | `0/1` | FX detail toggle (set by detail preset). |
| `0x14` | `u32` | `1/2` | Player count. |
| `0x18` | `u32` | `1..8` | Game mode/state selector (values `1/2/3/4/8` observed). |
| `0x1c` | `u8[...]` | `0` | Per-player mode flag (value `4` triggers alternate HUD draw). |
| `0x44` | `u32` | `0` | Unknown. |
| `0x48` | `u32` | `0` | Unknown. |
| `0x6c` | `u32` | `0` | Unknown. |
| `0x70` | `f32` | `1.0` | Texture/terrain scale factor (clamped `0.5..4.0`). |
| `0x74` | `char[12]` | empty | Copied out by `config_sync_from_grim`; no consumers yet. |
| `0x80` | `u32` | `0` | Selected name slot (0..7). |
| `0x84` | `u32` | `1` | Saved-name count / insert index. |
| `0x88` | `u32[8]` | `0..7` | Saved-name order table (seeded; no xrefs). |
| `0xa8` | `char[0xd8]` | `"default" x8` | 8 saved names, 0x1b bytes each. |
| `0x180` | `char[0x20]` | default name | Player name (copied to runtime on load). |
| `0x1a0` | `u32` | `0` | Player name length (overwritten on load; 1.9.93 file stores 0). |
| `0x1a4` | `u32` | `100` | Unknown. |
| `0x1a8` | `u32` | `0` | Unknown. |
| `0x1ac` | `u32` | `0` | Unknown. |
| `0x1b0` | `u32` | `9000` | Compared to Grim vtable +0xa4 (likely dead). |
| `0x1b4` | `u32` | `27000` | Compared to Grim vtable +0xa4 (likely dead). |
| `0x1b8` | `u32` | `32` | Display color depth (bits-per-pixel). |
| `0x1bc` | `u32` | `800/1024` | Screen width (file in game_bins is 1024). |
| `0x1c0` | `u32` | `600/768` | Screen height (file in game_bins is 768). |
| `0x1c4` | `u8` | `0/1` | Windowed flag (`0` = fullscreen, `1` = windowed). |
| `0x1c8` | `u32[0x20]` | table | Keybind blocks (2 x 16 dwords; indices `0..12` copied). |
| `0x1f8` | `u32*` | alias | Points at `&keybinds[12]` (copy loop). |
| `0x440` | `u32` | `0` | Unknown. |
| `0x444` | `u32` | `0` | Unknown. |
| `0x448` | `u8` | `0` | Hardcore flag. |
| `0x449` | `u8` | `1` | Full-version/unlimited flag (gates quest logic). |
| `0x44c` | `u32` | `0` | Perk prompt counter. |
| `0x450` | `u32` | `1` | Unknown. |
| `0x460` | `u32` | `1` | Unknown. |
| `0x464` | `f32` | `?` | SFX volume multiplier. |
| `0x468` | `f32` | `?` | Music volume multiplier. |
| `0x46c` | `u8` | `0` | FX toggle (gore/particle path; forced to 1 if cfg missing). |
| `0x46d` | `u8` | `0` | Score load gate (paired with date mode). |
| `0x46e` | `u8` | `?` | Config bool applied via Grim id `0x54`. |
| `0x470` | `u32` | `?` | Detail preset (drives `0x0e/0x10/0x11`). |
| `0x478` | `u32` | `?` | Keybind: pick perk (level-up prompt). |
| `0x47c` | `u32` | `?` | Keybind: reload. |

## Keybind block layout (partial)

Block is `u32[0x20]` at `0x1c8` (2 x 16 dwords). Indices `0..12` are copied
into runtime key tables.

| Index | P1 default | P2 default | Notes |
| --- | --- | --- | --- |
| `0` | `0x11` (W) | `0xc8` (Up) | Move up |
| `1` | `0x1f` (S) | `0xd0` (Down) | Move down |
| `2` | `0x1e` (A) | `0xcb` (Left) | Move left |
| `3` | `0x20` (D) | `0xcd` (Right) | Move right |
| `4` | `0x100` | `0x9d` (RControl) | Primary fire |
| `5` | `0x17e` | `0x17e` | Unused/reserved |
| `6` | `0x17e` | `0x17e` | Unused/reserved |
| `7` | `0x10` (Q) | `0xd3` (Delete) | Rotate/aux |
| `8` | `0x12` (E) | `0xd1` (PageDown) | Rotate/aux |

## Notes

- The blob is always written at full size; unknown fields should be preserved
  when round-tripping.
- `game.cfg` is a different file (save/status) and does **not** share this layout.
