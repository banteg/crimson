---
tags:
  - status-analysis
---

# Save/status file (game.cfg)

Crimsonland stores quest progress and several counters in `game.cfg` (the “status” file). The
format is small but obfuscated and checksummed. This page documents what we know so far and
links the editor script in `scripts/save_status.py`.

## File layout

- **Total size:** `0x26c` bytes.
- **Payload:** first `0x268` bytes (`game_status_blob`).
- **Checksum:** final 4 bytes, little‑endian `u32`.

## Struct view (game_status_t)

`game_status_blob` (`DAT_00485540`) is typed as `game_status_t`:

```c
typedef struct game_status_t {
    unsigned short quest_unlock_index;
    unsigned short quest_unlock_index_full;
    unsigned int weapon_usage_counts[53];
    unsigned int quest_play_counts[91];
    unsigned int mode_play_survival;
    unsigned int mode_play_rush;
    unsigned int mode_play_typo;
    unsigned int mode_play_other;
    unsigned int game_sequence_id;
    unsigned char reserved0[0x10];
} game_status_t;
```

## Obfuscation

Each payload byte is transformed on save using a byte index polynomial and a constant add.
Let `i` be the byte index and `i8` be `i` wrapped to a signed 8‑bit value.

```
poly(i) = ((i8 * 7 + 0x0f) * i8 + 0x03) * i8
enc[i]  = (dec[i] + poly(i) + 0x6f) & 0xff
```

The loader reverses it with:

```
dec[i] = (enc[i] - 0x6f - poly(i)) & 0xff
```

## Checksum

The checksum is computed over the **decoded** payload. It accumulates in a 32‑bit
integer (wrap on overflow).

```
acc = 0
u   = 0
for i, byte in enumerate(decoded):
    c = signed8(byte)
    acc = (acc + 0x0d + ((c * 7 + i) * c + u)) & 0xffffffff
    u += 0x6f
```

## Known fields

Offsets are relative to the decoded payload (`game_status_blob`).

| Offset | Size | Name | Notes |
| --- | --- | --- | --- |
| `0x00` | u16 | `quest_unlock_index` | Max quest unlock index (limited version). |
| `0x02` | u16 | `quest_unlock_index_full` | Max quest unlock index (full version). |
| `0x04` | u32[53] | `weapon_usage_counts` | Weapon usage counters indexed by weapon id (1-based; slot 0 unused). Note: id 53 would overlap `quest_play_counts[0]` if written. |
| `0xD8` | u32[91] | `quest_play_counts` | Quest play/attempt counters (`major * 10 + minor`). Length inferred from known tail fields. |
| `0x244` | u32 | `mode_play_survival` | Incremented when starting Survival (mode 1). |
| `0x248` | u32 | `mode_play_rush` | Incremented when starting Rush (mode 2). |
| `0x24C` | u32 | `mode_play_typo` | Incremented when starting Typ‑o‑Shooter (mode 4). |
| `0x250` | u32 | `mode_play_other` | Incremented for other modes (e.g. tutorial). |
| `0x254` | u32 | `game_sequence_id` | Also written to registry on save. |
| `0x258` | 0x10 | — | Unknown/reserved tail bytes. |

## Editor tool

Use the helper script to inspect and edit `game.cfg`:

```
uv run python scripts/save_status.py info game_bins/crimsonland/1.9.93-gog/game.cfg
uv run python scripts/save_status.py set game.cfg --set quest_unlock_index=30 --set weapon_usage.5=12
```

Supported edits:

- `quest_unlock_index`, `quest_unlock_index_full`, `game_sequence_id`
- `weapon_usage.<slot>` (0–52; slot = weapon_id, 0 unused)
- `quest_play.<index>` (0–90)
- `mode_play.<survival|rush|typo|other>`

The script validates the checksum, applies updates to the decoded blob, and rewrites the
obfuscated file with a fresh checksum.
