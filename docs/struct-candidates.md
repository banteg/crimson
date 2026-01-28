---
tags:
  - status-analysis
  - ghidra
---

# Struct Mapping Candidates

This document tracks struct types and global data that can be mapped in Ghidra's `data_map.json`. Evidence includes array indexing with constant strides, field access patterns, constructor calls, and cross-references with documented behavior.

## Current Mapping Status

### Fully Mapped Structs (in data_map.json + crimsonland_types.h)

| Struct | Size | Entries | Status |
|--------|------|---------|--------|
| `player_state_t` | 0x360 | 4 players | Complete |
| `creature_t` | 0x98 | 0x180 pool | Complete |
| `projectile_t` | 0x40 | 0x60 pool | Complete |
| `particle_t` | 0x38 | 0x80 pool | Complete |
| `secondary_projectile_t` | 0x2c | 0x40 pool | Complete |
| `sprite_effect_t` | 0x2c | 0x180 pool | Complete |
| `effect_entry_t` | 0xbc | linked list | Complete |
| `fx_queue_entry_t` | 0x28 | 0x80 queue | Complete |
| `weapon_stats_t` | 0x7c | 53 weapons | Complete |
| `creature_type_t` | 0x44 | ~8 types | Complete |
| `perk_meta_t` | 0x14 | 0x80 perks | Complete |
| `bonus_meta_t` | 0x14 | 0x0f bonuses | Complete |
| `bonus_entry_t` | 0x1c | pool | Complete |
| `bonus_hud_slot_t` | 0x20 | 0x10 slots | Complete |
| `quest_meta_t` | 0x2c | 0x32 quests | Complete |
| `quest_spawn_entry_t` | 0x18 | varies | Complete |
| `creature_spawn_slot_t` | 0x18 | 0x20 slots | Complete |
| `ui_element_t` | 0x318+ | varies | Complete |
| `ui_button_t` | 0x18 | varies | Complete |
| `highscore_record_t` | 0x48 | 0x10 records | Complete |
| `credits_line_t` | 0x08 | 0x100 lines | Complete |
| `crimson_cfg_t` | 0x480 | singleton | Complete |
| `game_status_t` | 0x268 | singleton | Complete |
| `audio_entry_t` | 0x84 | varies | Complete |
| `mod_api_t` | varies | singleton | Complete |
| `mod_api_vtbl_t` | varies | vtable | Complete |
| `mod_interface_t` | varies | singleton | Complete |
| `effect_id_entry_t` | 0x08 | 0x13 entries | Complete |
| `player_input_t` | 0x34 | embedded | Complete |

---

## Unmapped Global Data (Ready to Add)

These globals have clear usage patterns and should be added to `data_map.json`:

### 1. `weapon_usage_time` - Per-Weapon Usage Tracking

**Address:** `0x0048708c`

**Evidence:**
- Zeroed in game init: `for (iVar10 = 0x40; iVar10 != 0; ...)`
- Indexed by weapon_id: `(&DAT_0048708c)[player_state_table.weapon_id] += frame_dt_ms`
- Used to determine most-used weapon for highscore

**Type:** `int[64]` (0x100 bytes)

**Proposed Entry:**
```json
{
  "address": "0x0048708c",
  "name": "weapon_usage_time",
  "comment": "Per-weapon usage tracking in milliseconds. Indexed by weapon_id (0-63). Used to determine most_used_weapon_id for highscore records.",
  "program": "crimsonland.exe"
}
```

---

### 2. `perk_selection_index` - Current Perk Choice

**Address:** `0x0048089c`

**Evidence:**
- Set during perk menu: `DAT_0048089c = iVar2`
- Used to index perk_choice_ids: `(&perk_choice_ids)[DAT_0048089c]`
- Range check: `-1 < DAT_0048089c`

**Type:** `int`

**Proposed Entry:**
```json
{
  "address": "0x0048089c",
  "name": "perk_selection_index",
  "comment": "Currently highlighted perk in the perk selection menu. Index into perk_choice_ids array. -1 when no selection.",
  "program": "crimsonland.exe"
}
```

---

### 3. `player_aim_screen` - Per-Player Aim Coordinates

**Address:** `0x004871f4` (X), `0x004871f8` (Y)

**Evidence:**
- Set from mouse: `(&DAT_004871f4)[render_overlay_player_index * 2] = ui_mouse_x`
- Read for aiming: `(float)(&DAT_004871f4)[render_overlay_player_index * 2] - _camera_offset_x`
- Stride 8 bytes (2 floats per player)

**Type:** `float[8]` (4 players x 2 coords)

**Proposed Entries:**
```json
{
  "address": "0x004871f4",
  "name": "player_aim_screen_x",
  "comment": "Per-player aim screen X coordinates. Stride 8 bytes (index * 2). Set from ui_mouse_x or joystick input.",
  "program": "crimsonland.exe"
},
{
  "address": "0x004871f8",
  "name": "player_aim_screen_y",
  "comment": "Per-player aim screen Y coordinates (player_aim_screen_x + 0x04). Stride 8 bytes.",
  "program": "crimsonland.exe"
}
```

---

### 4. `player_aux_timer` - Per-Player Auxiliary Timer

**Address:** `0x004871d0`

**Evidence:**
- Indexed by player: `(&DAT_004871d0)[render_overlay_player_index]`
- Timer decay: `(&DAT_004871d0)[...] -= frame_dt * fVar15`
- Reset to 2.0: `(&DAT_004871d0)[player_index] = 0x40000000` (float 2.0)

**Type:** `float[4]`

**Proposed Entry:**
```json
{
  "address": "0x004871d0",
  "name": "player_aux_timer",
  "comment": "Per-player auxiliary timer (4 floats). Used for UI feedback timing. Decays over time.",
  "program": "crimsonland.exe"
}
```

---

### 5. `terrain_texture_handles` - Terrain Layer Textures

**Address:** `0x0048f548`

**Evidence:**
- Indexed by quest terrain_id: `(&DAT_0048f548)[*(int *)(desc + 0x10)]`
- Used for all 3 terrain layers (terrain_id, terrain_id_b, terrain_id_c)
- Passed to `grim_bind_texture`

**Type:** `int[]` (texture handle array)

**Proposed Entry:**
```json
{
  "address": "0x0048f548",
  "name": "terrain_texture_handles",
  "comment": "Array of terrain texture handles. Indexed by quest_meta terrain_id fields (0x10/0x14/0x18 offsets).",
  "program": "crimsonland.exe"
}
```

---

## Lower Priority / Partial Mappings

These items have some fields mapped but could use expansion:

### `creature_type_t` - Complete Field Documentation

**Status:** Struct defined, individual fields partially mapped.

**Known Fields:**
| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00 | int | texture_handle | Creature sprite atlas |
| 0x04 | int[4] | sfx_bank_a | Death sounds |
| 0x14 | int[2] | sfx_bank_b | Attack sounds |
| 0x1c | byte[4] | _pad0 | Padding |
| 0x20 | float | field_0x20 | Unknown (set to 1.0) |
| 0x24 | byte[0x10] | _pad1 | Padding |
| 0x34 | float | anim_rate | Animation speed |
| 0x38 | int | base_frame | Atlas base frame |
| 0x3c | int | corpse_frame | Corpse sprite frame |
| 0x40 | int | anim_flags | Bit 0: ping-pong anim |

**Recommendation:** Add missing fields at 0x20-0x33 if behavior analysis requires them.

---

### `mod_var_t` - Mod Variable Entry

**Status:** Not mapped.

**Evidence:**
- Used in `mod_api_core_get_var`
- Linked list structure for cvars

**Recommendation:** Add if mod variable system needs documentation.

---

### `console_state_t` - Console State

**Status:** Partially documented, not formally typed.

**Observed Fields:**
| Offset | Type | Field |
|--------|------|-------|
| 0x00 | void* | log_head |
| 0x04 | void* | cmd_list |
| 0x08 | void* | log_list |
| 0x0c | int | echo |
| 0x18 | int | height |
| 0x20 | int | cursor |
| 0x24 | char | open |

**Base Address:** `console_log_queue` (0x0047eea0)

**Recommendation:** Add if console system needs deeper analysis.

---

## Verification Commands

To verify struct mappings in Ghidra:

```bash
# Check creature type stride (0x44 bytes)
just ghidra-print 0x00482728 0x44 1

# Check weapon usage time array (64 ints)
just ghidra-print 0x0048708c 0x04 64

# Check player aim screen (8 floats)
just ghidra-print 0x004871f4 0x04 8

# Check terrain texture handles
just ghidra-print 0x0048f548 0x04 16
```

---

## See Also

- [Runtime structs index](structs/index.md) - Detailed struct documentation
- [Effects pools](structs/effects.md) - Effect system structs
- [Player struct](structs/player.md) - Player state documentation
- [Creature struct](creatures/struct.md) - Creature pool documentation
- [data_map.json](../analysis/ghidra/maps/data_map.json) - Source of truth for Ghidra mappings
