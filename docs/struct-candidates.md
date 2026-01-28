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
