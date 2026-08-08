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

`config_blob` at `0x00480348` is typed as `crimson_cfg_t`. The recovered
`crimsonShared.h::config_t` supplies the source identities for the direction
flags, render toggles, control arrays, `config_for`, logging flag, and two
installation IDs:

```c
typedef struct player_input_config_t {
    int move_key_forward;
    int move_key_backward;
    int turn_key_left;
    int turn_key_right;
    int fire_key;
    int key_reserved_0;
    int key_reserved_1;
    int aim_key_left;
    int aim_key_right;
    int axis_aim_y;
    int axis_aim_x;
    int axis_move_y;
    int axis_move_x;
    int reserved[3];
} player_input_config_t;

typedef struct crimson_cfg_t {
    unsigned char sound_disabled;
    unsigned char music_disabled;
    unsigned char highscore_date_mode;
    unsigned char highscore_duplicate_mode;
    unsigned char direction_arrow_flags[10];
    unsigned char shadows_enabled;
    unsigned char sharp_ground_enabled;
    unsigned char flame_glow_enabled;
    unsigned char smoke_enabled;
    unsigned char padding_12[2];
    int player_count;
    game_mode_id_t game_mode;
    int movement_schemes[10];
    int aim_schemes[10];
    int config_for;
    float texture_scale;
    char player_name_buf[12];
    int selected_saved_name_slot;
    int saved_name_count;
    int saved_name_order[8];
    char saved_names[8][27];
    char player_name[32];
    int player_name_length;
    unsigned char startup_defaults_only[0x0c];
    int aim_pov_right;
    int aim_pov_left;
    int display_bpp;
    int screen_width;
    int screen_height;
    unsigned char windowed;
    unsigned char windowed_padding[3];
    player_input_config_t input_config[10];
    unsigned char hardcore;
    unsigned char ui_info_texts;
    unsigned char hardcore_info_padding[2];
    int level_up_count;
    int ten_tons_logging_completed;
    int unique_id_1;
    int unique_id_2;
    int reserved_identity_word;
    unsigned char sound_frequency_adjustment;
    unsigned char sound_frequency_padding[3];
    float sfx_volume;
    float music_volume;
    unsigned char violence_disabled;
    unsigned char show_online_scores;
    unsigned char safe_mode_backend_enabled;
    unsigned char detail_padding;
    int detail_preset;
    float mouse_sensitivity;
    int key_pick_perk;
    int key_reload;
} crimson_cfg_t;
```

## Control scheme notes

For player controls, movement and aiming are stored separately in the blob:

- `config_movement_schemes[player]` controls movement mode.
- `config_aim_schemes[player]` controls aiming mode.

On the original EXE, these can be mixed in practice (for example
`move_mode = 2` static movement with `aim_scheme = 5` computer aiming).

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

From the decompile (see `docs/re/static/detangling.md`):

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
| `0x000` | 0xA8 | - | Header / mixed fields | Not all unused; contains multiple small config fields (see below for known offsets). |
| `0x0A8` | 216 | `"default"` x8 | `config_saved_names` | 8 saved names (player name cache), 27 bytes each. |
| `0x180` | 32 | `10tons` | `config_player_name` | Current player name (char[32] or similar?). |
| `0x1A0` | 4 | `0` | `config_player_name_length` | Length of player name. |
| `0x1A4` | 12 | `100,0,0` | Startup defaults only | Three words written only by `config_init_defaults`; their semantics remain unresolved. |
| `0x1B0` | 4 | `9000` | `aim_pov_right` | Joystick POV value for right. |
| `0x1B4` | 4 | `27000` | `aim_pov_left` | Joystick POV value for left. |
| `0x1B8` | 4 | `32` | `config_display_bpp` | Bits per pixel (16/32). |
| `0x1BC` | 4 | `800` | `config_screen_width` | Screen width. |
| `0x1C0` | 4 | `600` | `config_screen_height` | Screen height. |
| `0x1C4` | 1 | `0` | `config_windowed` | Byte-sized windowed mode flag (0=fullscreen). |
| `0x1C5` | 3 | - | Padding | Alignment before the P1 keybind table. |
| `0x1C8` | 640 | - | `input_config[10]` | Ten source-identified 16-dword binding blocks; this build actively copies the first two, while the ports use the next two for P3/P4. |
| `0x448` | 1 | `0` | `config_hardcore` | Hardcore mode flag. |
| `0x449` | 1 | `1` | `config_ui_info_texts` | UI info-text toggle. |
| `0x44A` | 2 | - | Padding | Alignment. |
| `0x44C` | 4 | `0` | `config_level_up_count` | Source `numLevelUps`; increments when a perk selection becomes pending. |
| `0x450` | 4 | `1` | `config_ten_tons_logging_completed` | Source-identified 10tons logging completion flag. |
| `0x454` | 4 | `0` | `config_unique_id_1` | Source-identified persisted installation ID. |
| `0x458` | 4 | `0` | `config_unique_id_2` | Source-identified persisted installation ID. |
| `0x45C` | 4 | `0` | Reserved identity word | Added after the recovered source layout; no native reads. |
| `0x460` | 1 | `1` | `config_sound_frequency_adjustment` | Sound frequency-adjustment toggle. |
| `0x461` | 3 | - | Padding | Alignment before volume floats. |
| `0x464` | 4 | `1.0` | `config_sfx_volume` | SFX Volume (float). |
| `0x468` | 4 | `1.0` | `config_music_volume` | Music Volume (float). |
| `0x46C` | 1 | `0` | `config_violence_disabled` | Gates blood/particle paths and alternate perk text. |
| `0x46D` | 1 | `0` | `config_show_online_scores` | Source `showOnlineScores`; controls the UI checkbox and remote-score loading. |
| `0x46E` | 1 | `0` | `config_safe_mode_backend_enabled` | Safe-mode backend flag mirrored to Grim. |
| `0x46F` | 1 | - | Padding | Alignment. |
| `0x470` | 4 | `5` | `config_detail_preset` | Graphics detail preset (1..5). Drives the source-identified render toggles via `config_apply_detail_preset` (`0x00447580`). |
| `0x474` | 4 | - | `config_mouse_sensitivity` | Mouse sensitivity (float; options slider clamps 0.1..1.0). |
| `0x478` | 4 | - | `config_key_pick_perk` | Keybind: Pick Perk. |
| `0x47C` | 4 | - | `config_key_reload` | Keybind: Reload. |
| `0x480` | - | - | End | End of file. |

## Source-identified render toggles (0x0E..0x11)

These three bytes live inside the `0x000..0x0A7` “header/mixed” region of the blob:

| Offset | Size | Name | Meaning (observed in decompile) |
| --- | --- | --- | --- |
| `0x0E` | 1 | `config_shadows_enabled` | Enables UI and creature shadow passes. |
| `0x0F` | 1 | `config_sharp_ground_enabled` | Legacy sharp-ground toggle; initialized but otherwise unused in this build. |
| `0x10` | 1 | `config_flame_glow_enabled` | Enables heavier projectile and bonus glow passes. |
| `0x11` | 1 | `config_smoke_enabled` | Gates an extra sprite-effect rendering pass. |

### How `config_detail_preset` maps to the flags

`config_apply_detail_preset` (`0x00447580`) applies the “Graphics detail” preset to these flags:

| `config_detail_preset` | `flag0` (`0x0E`) | `flag1` (`0x10`) | `flag2` (`0x11`) |
| --- | --- | --- | --- |
| 1 | 0 | 0 | 0 |
| 2 | 0 | 0 | *unchanged* |
| 3 | 1 | 1 | 1 |
| 4 | 1 | 1 | 1 |
| 5 | 1 | 1 | 1 |

Notes:

- The options UI clamps `config_detail_preset` to 1..5, then calls `config_apply_detail_preset` (`options_menu_update` at `0x004475d0`).
- Default init (`config_init_defaults` at `0x004028f0`) sets `flag0/1/2` to 1 and `config_detail_preset` to 5.

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
