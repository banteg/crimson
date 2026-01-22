---
tags:
  - status-analysis
---

# Crimson config blob (crimson.cfg)

`crimson.cfg` is the fixed-size configuration blob used by the classic
Crimsonland executable. It is **not** the save/status file (that is `game.cfg`).

## Location and size

- Path: `game_base_path\\crimson.cfg` (built via `game_build_path`).
- Size: **0x480 bytes** (1152 bytes).
- Endianness: little-endian for integer/float fields.

## Struct view (crimson_cfg_t)

`config_blob` (`DAT_00480348`) is typed as `crimson_cfg_t`:

```c
typedef struct crimson_cfg_t {
    unsigned char reserved0[0x0a8];
    char saved_names[8][27];
    char player_name[32];
    int player_name_length;
    unsigned char reserved1[0x14];
    int display_bpp;
    int screen_width;
    int screen_height;
    int windowed;
    int keybinds_p1[13];
    unsigned char reserved2[0x0c];
    int keybinds_p2[13];
    unsigned char reserved3[0x0c];
    unsigned char reserved4[0x200];
    unsigned char hardcore;
    unsigned char full_version;
    unsigned char reserved5[2];
    int perk_prompt_counter;
    unsigned char reserved6[0x14];
    float sfx_volume;
    float music_volume;
    unsigned char fx_toggle;
    unsigned char score_load_gate;
    unsigned char reserved7[2];
    int detail_preset;
    unsigned char reserved8[4];
    int key_pick_perk;
    int key_reload;
} crimson_cfg_t;
```

Observed file:

- `game_bins/crimsonland/1.9.93-gog/crimson.cfg`
  - size 0x480
  - width 1024, height 768
  - windowed flag = 1
  - texture scale = 1.0

Hardcoded defaults (from `config_sync_from_grim` when `grim_config_invoked` is set):

- width 800, height 600
- windowed flag = 0 (fullscreen)
- bpp = 32
- sfx/music volume = 1.0
- player name defaults to `10tons`
- saved names default to `"default"` x8

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

## Field layout

Base address in the decompile is `DAT_00480348`. Offsets below are relative to
the blob start.

| Offset | Size | Default | Name | Description |
| --- | --- | --- | --- | --- |
| `0x000` | 0xA8 | - | Unused/Reserved? | Initial area, seems mostly zeroed/unused. |
| `0x0A8` | 216 | `"default"` x8 | `config_saved_names` | 8 saved names (player name cache), 27 bytes each. |
| `0x180` | 32 | `10tons` | `config_player_name` | Current player name (char[32] or similar?). |
| `0x1A0` | 4 | `0` | `config_player_name_length` | Length of player name. |
| `0x1A4` | 28 | - | Unused/Padding? | Gap. |
| `0x1B8` | 4 | `32` | `config_display_bpp` | Bits per pixel (16/32). |
| `0x1BC` | 4 | `800` | `config_screen_width` | Screen width. |
| `0x1C0` | 4 | `600` | `config_screen_height` | Screen height. |
| `0x1C4` | 4 | `0` | `config_windowed` | Windowed mode flag (0=fullscreen). |
| `0x1C8` | 52 | - | P1 Keybinds | Player 1 control bindings (13 dwords). |
| `0x1FC` | 12 | - | P1 Padding | Padding (3 dwords). |
| `0x208` | 52 | - | P2 Keybinds | Player 2 control bindings (13 dwords). |
| `0x23C` | 12 | - | P2 Padding | Padding (3 dwords). |
| `0x248` | 512 | - | Unused/Reserved | Large gap (possibly for P3/P4 + padding). |
| `0x448` | 1 | `0` | `config_hardcore` | Hardcore mode flag. |
| `0x449` | 1 | `1` | `config_full_version` | Full version flag. |
| `0x44A` | 2 | - | Unused? | Alignment. |
| `0x44C` | 4 | `0` | `config_perk_prompt_counter` | Counter for perk prompts. |
| `0x450` | 28 | - | Unused? | Gap. |
| `0x464` | 4 | `1.0` | `config_sfx_volume` | SFX Volume (float). |
| `0x468` | 4 | `1.0` | `config_music_volume` | Music Volume (float). |
| `0x46C` | 1 | `0` | `config_fx_toggle` | FX Detail toggle. |
| `0x46D` | 1 | `0` | `config_score_load_gate` | Score loading flag. |
| `0x46E` | 2 | - | Unused? | Alignment. |
| `0x470` | 4 | - | `config_detail_preset` | Detail preset index. |
| `0x474` | 4 | - | Unused? | Gap. |
| `0x478` | 4 | - | `config_key_pick_perk` | Keybind: Pick Perk. |
| `0x47C` | 4 | - | `config_key_reload` | Keybind: Reload. |
| `0x480` | - | - | End | End of file. |

## Keybind Block Structure

Each player block is 52 bytes (13 dwords), followed by 12 bytes padding.
The values map to DirectInput key codes (scancodes).

**Offset** refers to index within the block (0-12).

| Index | Name | P1 Default | P2 Default | Notes |
| --- | --- | --- | --- | --- |
| `0` | Move Forward | `0x11` (W) | `0xc8` (Up) | |
| `1` | Move Backward | `0x1f` (S) | `0xd0` (Down) | |
| `2` | Turn Left | `0x1e` (A) | `0xcb` (Left) | |
| `3` | Turn Right | `0x20` (D) | `0xcd` (Right) | |
| `4` | Fire | `0x100` (LMouse) | `0x9d` (RControl) | P1 uses mouse button 0 by default. |
| `5` | Reserved 0 | `0x17e` | `0x17e` | |
| `6` | Reserved 1 | `0x17e` | `0x17e` | |
| `7` | Aim Left | `0x10` (Q) | `0xd3` (Delete) | |
| `8` | Aim Right | `0x12` (E) | `0xd1` (PageDown) | |
| `9` | Axis Aim Y | `0x140` | `0x17e` | Analog axis (P1 Mouse Y). |
| `10` | Axis Aim X | `0x13f` | `0x17e` | Analog axis (P1 Mouse X). |
| `11` | Axis Move Y | `0x153` | `0x17e` | Analog axis. |
| `12` | Axis Move X | `0x17e` | `0x17e` | Analog axis. |

**P3/P4 Note:** The game loop in `config_load_presets` iterates only twice (for P1 and P2). The large gap after P2 suggests P3/P4 slots might have been planned but are not loaded by this version of the executable.

## Notes

- The blob is always written at full size; unknown fields should be preserved
  when round-tripping.

- `game.cfg` is a different file (save/status) and does **not** share this layout.
