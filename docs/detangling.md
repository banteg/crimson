# Detangling notes

**Status:** In progress

This page tracks high-value functions to name and the evidence gathered so far.
Use the hotspot script to refresh the lists when the decompile is regenerated.

## Hotspot script

```
uv run python scripts/function_hotspots.py --top 12 --only-fun
```

## Name/data map workflow

We keep authoritative function renames/signatures in `analysis/ghidra/maps/name_map.json`
and data labels in `analysis/ghidra/maps/data_map.json`, applying both during headless
analysis:

```
./analysis/ghidra/tooling/ghidra-analyze.sh \
  --script-path analysis/ghidra/scripts \
  -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
  -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
  -s ExportAll.java -o analysis/ghidra/raw \
  game_bins/crimsonland/1.9.93-gog/crimsonland.exe
```

You can also set `CRIMSON_NAME_MAP` / `CRIMSON_DATA_MAP` to point at custom maps.

## High-call functions (current)

### `crimsonland.exe`

```
   8    7 00405960 FUN_00405960 undefined FUN_00405960(void)
   8    5 00430af0 FUN_00430af0 undefined1 * FUN_00430af0(int param_1, float * param_2, float param_3)
   8    0 0041df40 FUN_0041df40 undefined1 FUN_0041df40(void)
   6    3 00403550 FUN_00403550 undefined FUN_00403550(void)
   6    1 00402bd0 FUN_00402bd0 undefined * FUN_00402bd0(void)
   6    0 0043d7e0 FUN_0043d7e0 undefined FUN_0043d7e0(int param_1, char param_2)
   6    0 00452ef0 FUN_00452ef0 undefined4 FUN_00452ef0(float param_1, float param_2)
   5    1 00461140 FUN_00461140 undefined FUN_00461140(void)
   5    1 004614a5 FUN_004614a5 undefined4 FUN_004614a5(int * param_1)
   5    1 00465fa9 FUN_00465fa9 undefined FUN_00465fa9(void)
   5    0 00417ae0 FUN_00417ae0 undefined FUN_00417ae0(void)
   5    0 0046cda0 FUN_0046cda0 undefined FUN_0046cda0(void)
```

### `grim.dll`

```
  30    0 100170d6 FUN_100170d6 undefined FUN_100170d6(undefined4 param_1)
  20    0 1004b5b0 FUN_1004b5b0 undefined FUN_1004b5b0(void)
  10    0 10001160 FUN_10001160 undefined FUN_10001160(void)
   8    2 1001029e FUN_1001029e undefined FUN_1001029e(int param_1)
   6    1 1001692e FUN_1001692e undefined FUN_1001692e(undefined4 * param_1)
   6    0 1000cbff FUN_1000cbff undefined4 FUN_1000cbff(float param_1, float param_2)
   6    0 100161b6 FUN_100161b6 undefined4 FUN_100161b6(byte * param_1)
   6    0 10020708 FUN_10020708 undefined FUN_10020708(undefined4 param_1)
   6    0 1002faab FUN_1002faab undefined4 FUN_1002faab(undefined4 * param_1, uint param_2, int param_3, int param_4)
   5    2 100161bb FUN_100161bb int FUN_100161bb(void * this, undefined4 * param_1, int * param_2, undefined4 param_3, uint * param_4, undefined4 param_5, uint param_6)
   5    1 1001ac4a FUN_1001ac4a undefined4 * FUN_1001ac4a(void * this, undefined4 * param_1)
   4    3 100101f5 FUN_100101f5 undefined FUN_100101f5(undefined4 param_1)
```

## Identified candidates

### Logging / console queue (high confidence)

- `FUN_0046e8f4` -> `strdup_malloc`
  - Evidence: `strlen` + `malloc` + copy (`FUN_00465c30`) pattern.
- `FUN_004017a0` -> `console_push_line`
  - Evidence: pushes strdup’d strings into a list, caps at 0x1000 entries.
- `FUN_00401870` -> `console_printf`
  - Evidence: formats strings (uses `FUN_00461089`) then pushes into the console queue; callsites include `Unknown command`/CMOD logs.


### UI element timeline + transitions (high confidence)

- `FUN_0041a530` -> `ui_elements_update_and_render`
  - Evidence: advances a global timeline (`ui_elements_timeline` (`DAT_00487248`)) based on `DAT_00480844`, clamps to
    `ui_elements_max_timeline`, triggers screen transitions via `FUN_004461c0`, and iterates
    `DAT_0048f208`..`DAT_0048f168` calling `FUN_00446900` + `ui_element_render`.
- `FUN_00446170` -> `ui_elements_reset_state`
  - Evidence: clears the element active flag (`*(char *)element`) and zeroes the per-element
    hover timer at `+0x2f8` across the UI element table.
- `FUN_00446190` -> `ui_elements_max_timeline`
  - Evidence: returns the max `element+0x10` value among active elements (used to clamp the
    UI transition timeline).


### Input primary action (high confidence)

- `FUN_00446030` -> `input_primary_just_pressed`
  - Evidence: edge-detects a primary action by latching `DAT_00478e50`, checks mouse button
    `(*DAT_0048083c + 0x58)(0)`, and scans per-player fire bindings at `player_fire_key` (stride
    `0xd8`). Used across UI click/confirm paths and player fire/selection logic.
- `FUN_004460f0` -> `input_primary_is_down`
  - Evidence: returns true while the primary action is held (mouse button 0, `player_fire_key`,
    or `player_alt_fire_key`), used by UI scroll/drag handling.
- `FUN_00446000` -> `input_any_key_pressed`
  - Evidence: scans keycodes `2..0x17e` via the input callback at `(*DAT_0048083c + 0x80)`.

### Data labels (high confidence)

- `DAT_00480348` -> `config_blob`
  - Evidence: 0x480‑byte `crimson.cfg` blob; see config layout below.
- `DAT_00480510` -> `config_keybind_table`
  - Evidence: 2×16 dword keybind table inside config blob; copied into runtime binds.
- `DAT_00482948` -> `bonus_pool`
  - Evidence: bonus/pickup pool base with 16 entries (stride `0x1c`).
- `DAT_004908d4` -> `player_health`
  - Evidence: per-player health (table base) with stride `0xd8`; see player struct.
- `DAT_004912b8` -> `fx_queue`
  - Evidence: FX queue base with 0x80 entries (stride `0x28`).
- `DAT_004926b8` -> `projectile_pool`
  - Evidence: base of 0x60-entry projectile pool with stride 0x40.
- `DAT_00493eb8` -> `particle_pool`
  - Evidence: particle pool base with 0x80 entries (stride `0x38`).
- `DAT_00495ad8` -> `secondary_projectile_pool`
  - Evidence: secondary projectile pool base with 0x40 entries (stride `0x2c`).
- `DAT_00496820` -> `sprite_effect_pool`
  - Evidence: sprite effect pool base with stride `0x2c`.
- `DAT_0049bf38` -> `creature_pool`
  - Evidence: base of 0x180‑entry creature pool with stride 0x98.
- `DAT_004aaf3c` -> `fx_queue_rotated`
  - Evidence: rotated FX queue base with 0x40 entries.
- `DAT_004d7a2c` -> `weapon_table`
  - Evidence: base of weapon table with stride 0x7c (see weapon table doc).

### Creature spawn + damage (high confidence)

- `FUN_00430af0` -> `creature_spawn_template`
  - Evidence: calls `creature_alloc_slot`, writes the `DAT_0049bf38` pool fields, maps
    `template_id` to type/flags, and spawns linked satellites; heading `-100` uses
    a randomized heading.
- `FUN_004207c0` -> `creature_apply_damage`
  - Evidence: applies perk multipliers, reduces HP and knockback, calls
    `creature_handle_death`, spawns effects, and returns `1` when the creature dies.

### Gameplay render pass (high confidence)

- `FUN_00405960` -> `gameplay_render_world`
  - Evidence: updates `ui_transition_alpha` (`DAT_00487278`) (fade), renders the FX queue, creatures,
    player overlays (dead/alive ordering), projectiles, and bonuses.

### Key binding block (`DAT_00490bdc`..`DAT_00490f5c`) (medium confidence)

These live inside the per-player input struct (stride `0x360` bytes / `0xd8` dwords) and are
queried through `grim_is_key_active` (`+0x80`) or `grim_is_key_down` (`+0x44`).
Defaults are set in `config_load_presets`.

| Address | Default (DIK) | Guess | Evidence |
| --- | --- | --- | --- |
| `DAT_00490bdc` | `0x11` (W) | move forward (`player_move_key_forward`) | queried via `is_key_active` in player movement |
| `DAT_00490be0` | `0x1f` (S) | move backward (`player_move_key_backward`) | queried via `is_key_active` in player movement |
| `DAT_00490be4` | `0x1e` (A) | turn left (`player_turn_key_left`) | rotates heading in movement scheme 1/2 |
| `DAT_00490be8` | `0x20` (D) | turn right (`player_turn_key_right`) | rotates heading in movement scheme 1/2 |
| `DAT_00490bec` | `0x0f` (Tab) | primary fire (`player_fire_key`) | used by `input_primary_*` with stride `0xd8` |
| `DAT_00490bf8` | `0x10` (Q) | aim rotate left (`player_aim_key_left`) | rotates `player_aim_heading` in aim scheme 1 |
| `DAT_00490bfc` | `0x12` (E) | aim rotate right (`player_aim_key_right`) | rotates `player_aim_heading` in aim scheme 1 |
| `DAT_00490bf0` | `0x11` (W) | unused/reserved | copied from config, but no `is_key_*` callsites found |
| `DAT_00490bf4` | `0x1f` (S) | unused/reserved | copied from config, but no `is_key_*` callsites found |
| `DAT_00490f3c` | `0xc8` (Up) | alt move forward (`player_alt_move_key_forward`) | used via `is_key_down` when `_DAT_0048035c == 1` |
| `DAT_00490f40` | `0xd0` (Down) | alt move backward (`player_alt_move_key_backward`) | used via `is_key_down` when `_DAT_0048035c == 1` |
| `DAT_00490f44` | `0xcb` (Left) | alt turn left (`player_alt_turn_key_left`) | used via `is_key_down` when `_DAT_0048035c == 1` |
| `DAT_00490f48` | `0xcd` (Right) | alt turn right (`player_alt_turn_key_right`) | used via `is_key_down` when `_DAT_0048035c == 1` |
| `DAT_00490f4c` | `0x9d` (RControl) | alt primary fire (`player_alt_fire_key`) | checked in `input_primary_is_down` |
| `DAT_00490f50` | `0x11` (W) | unused/reserved | defaults set; no callsites yet |
| `DAT_00490f54` | `0x1f` (S) | unused/reserved | defaults set; no callsites yet |
| `DAT_00490f58` | `0xd3` (Delete) | unused/reserved | defaults set; no callsites yet |
| `DAT_00490f5c` | `0xc9` (PageUp) | unused/reserved | defaults set; no callsites yet |

Key info overlay (`FUN_00405160`) shows the first five entries per player from the config
blob at `DAT_00480510` (stride 5: Forward/Back/TurnLeft/TurnRight/Fire), which matches the active runtime
binds copied from `DAT_00480540` into `DAT_00490bdc..DAT_00490bec`.

### Analog axis bindings (per-player, stride `0x360` bytes / `0xd8` dwords)

These bindings are read via `grim_get_config_float` (`+0x84`) and map to the
analog control schemes selected in the per-player mode flags:

| Address | Symbol | Scheme | Notes |
| --- | --- | --- | --- |
| `DAT_00490c08` | `player_axis_move_x` | movement scheme `DAT_00480364 == 3` | Used with `player_axis_move_y` to drive movement vectors. |
| `DAT_00490c0c` | `player_axis_move_y` | movement scheme `DAT_00480364 == 3` | Paired with `player_axis_move_x`. |
| `DAT_00490c00` | `player_axis_aim_x` | aim scheme `DAT_0048038c == 4` | Used to derive aim vectors for stick/axis aiming. |
| `DAT_00490c04` | `player_axis_aim_y` | aim scheme `DAT_0048038c == 4` | Paired with `player_axis_aim_x`. |

Config edit path status:
- No in-game rebind writes to `DAT_00480540` found in the decompile.
- `config_load_presets` reads the 0x480‑byte config blob from disk into `DAT_00480348`
  and then copies the keybind table (`DAT_00480540`) into the per-player runtime slots.
- `FUN_0041ec60` seeds defaults in a local 0x480 blob, optionally reads a 0x480‑byte
  config from `DAT_00472998`, copies the string field at offset `0x74` and the flag
  at offset `0x46c` into globals (`DAT_004803bc`, `DAT_004807b4`), then writes the
  global blob (`DAT_00480348`, size `0x480`) using mode `DAT_00473668` (`"wb"`).
- `FUN_0041f130` is a fallback path that writes the same `DAT_00480348` blob using
  mode `DAT_00473668` (`"wb"`) when the `DAT_00472998` config file is missing.
- File evidence: `game_bins/crimsonland/1.9.93-gog/crimson.cfg` is exactly `0x480` bytes; `game_bins/crimsonland/1.9.93-gog/game.cfg` is not
  (likely a save/progress file). `DAT_00472998` is `"rb"`; the filename is supplied
  by `FUN_00402bd0` (`"%s\\%s"`).

Config blob layout (partial, 0x480 bytes, base `DAT_00480348`):

| Offset | Address | Size | Default | Notes |
| --- | --- | --- | --- | --- |
| `0x00` | `DAT_00480348` | `u8` | `0` | Sound disable flag (nonzero skips SFX and music init; applied via config id `0x53`). |
| `0x01` | `DAT_00480349` | `u8` | `0` | Music disable flag (music init requires `DAT_00480348 == 0` and `DAT_00480349 == 0`). |
| `0x02` | `DAT_0048034a` | `u8` | `0` | High‑score date validation mode: `1` = year+month, `2` = computed date checksum + year, `3` = day+month+year. |
| `0x03` | `DAT_0048034b` | `u8` | `0` | High‑score duplicate handling: `1` = replace existing entry with same name (via `FUN_0043af30`). |
| `0x04` | `DAT_0048034c` | `u8[2]` | `1,1` | Per‑player HUD indicator toggle (gates the second indicator draw pass). |
| `0x08` | `DAT_00480350` | `u32` | `8` | Unknown; value comes from a stack temp in `FUN_0041ec60` (used to query Grim config), no global xrefs. |
| `0x0e` | `DAT_00480356` | `u8` | `0/1` | FX detail toggle (set by `DAT_004807b8`). |
| `0x10` | `DAT_00480358` | `u8` | `0/1` | FX detail toggle (set by `DAT_004807b8`). |
| `0x11` | `DAT_00480359` | `u8` | `0/1` | FX detail toggle (set by `DAT_004807b8`). |
| `0x14` | `DAT_0048035c` | `u32` | `1/2` | Player count (loop bound in most per‑player logic). |
| `0x18` | `DAT_00480360` | `u32` | `1..8` | Game mode/state selector (values `1/2/3/4/8` observed). |
| `0x1c` | `DAT_00480364` | `u8[?]` | `0` | Per‑player mode flag (value `4` triggers alternate HUD draw). |
| `0x44` | `DAT_0048038c` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x48` | `DAT_00480390` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x6c` | `DAT_004803b4` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x70` | `DAT_004803b8` | `float` | `1.0` (clamped `0.5..4.0`) | Texture/terrain scale factor (used when creating ground texture). |
| `0x74` | `DAT_004803bc` | `char[12]` | empty string | Copied from config in `FUN_0041ec60`; only explicit consumer so far. |
| `0x80` | `DAT_004803c8` | `u32` | `0` | Selected name slot (0..7) for the saved‑name list. |
| `0x84` | `DAT_004803cc` | `u32` | `1` | Saved‑name count / insert index. |
| `0x88` | `DAT_004803d0` | `u32[8]` | `0..7` | Saved‑name order table (seeded in `FUN_0041ec60`); no xrefs in the decompile, likely unused. |
| `0xa8` | `DAT_004803f0` | `char[0xd8]` | `"default"` x8 | 8 saved names, 0x1b bytes each (`DAT_0048040b` is entry 2). |
| `0x180` | `DAT_004804c8` | `char[36]` | `DAT_00471314` | Player name (copied to runtime `DAT_00487040` on load). |
| `0x1a0` | `DAT_004804e8` | `u32` | `DAT_004871e8` | Player name length (mirrored to runtime on load; config value is overwritten). |
| `0x1a4` | `DAT_004804ec` | `u32` | `100` | Seeded in `FUN_0041ec60`; no xrefs yet. |
| `0x1a8` | `DAT_004804f0` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x1ac` | `DAT_004804f4` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x1b0` | `DAT_004804f8` | `u32` | `9000` | Compared to Grim vtable `+0xa4` (`FUN_100075b0`) in `FUN_0041e8f0`; returns `DAT_1005d850[index]` (index 0 here), no callsites, likely dead. |
| `0x1b4` | `DAT_004804fc` | `u32` | `27000` | Compared to Grim vtable `+0xa4` (`FUN_100075b0`) in `FUN_0041e8d0`; returns `DAT_1005d850[index]` (index 0 here), no callsites, likely dead. |
| `0x1b8` | `DAT_00480500` | `u32` | `32` | Likely display color depth (bits‑per‑pixel); set alongside width/height via config id `0x2b` (inference from defaults and file). |
| `0x1bc` | `DAT_00480504` | `u32` | `800` | Screen width. |
| `0x1c0` | `DAT_00480508` | `u32` | `600` | Screen height. |
| `0x1c4` | `DAT_0048050c` | `u8` | `0` | Windowed flag (`0` = fullscreen). |
| `0x1c8` | `DAT_00480510` | `u32[0x20]` | see below | Keybind blocks (2 × 16 dwords; indices `0..12` copied). |
| `0x1f8` | `DAT_00480540` | `u32*` | alias | Points at `&DAT_00480510[12]` (used for the copy loop). |
| `0x440` | `DAT_00480788` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x444` | `DAT_0048078c` | `u32` | `0` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x448` | `DAT_00480790` | `u8` | `0` | Full‑version/unlimited flag (gates quest logic and UI strings). |
| `0x449` | `DAT_00480791` | `u8` | `1` | Perk prompt state (reset when `DAT_00480794` rolls over). |
| `0x44c` | `DAT_00480794` | `u8` | `0` | Perk prompt counter (`0..0x32`). |
| `0x450` | `DAT_00480798` | `u32` | `1` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x460` | `DAT_004807a8` | `u32` | `1` | Unknown (defaulted in `FUN_0041ec60`, no xrefs). |
| `0x464` | `DAT_004807ac` | `float` | `?` | SFX volume multiplier. |
| `0x468` | `DAT_004807b0` | `float` | `?` | Music volume multiplier. |
| `0x46c` | `DAT_004807b4` | `u8` | `0` | FX toggle (gore/particle path; copied from config; `FUN_0041f130` forces `1` when cfg missing). |
| `0x46d` | `DAT_004807b5` | `u8` | `0` | Score load gating flag (used with `DAT_0048034a`). |
| `0x46e` | `DAT_004807b6` | `u8` | `?` | Config bool applied via Grim id `0x54` (unknown). |
| `0x470` | `DAT_004807b8` | `u32` | `?` | Detail preset (drives `DAT_00480356/58/59`). |
| `0x478` | `DAT_004807c0` | `u32` | `?` | Keybind: pick perk (Level‑up prompt). |
| `0x47c` | `DAT_004807c4` | `u32` | `?` | Keybind: reload. |

Keybind block layout (`DAT_00480510`, 2 × 16 dwords, indices `0..12` copied into runtime;
`DAT_00480540` is `&DAT_00480510[12]`):

| Index | P1 default | P2 default | Notes |
| --- | --- | --- | --- |
| `0` | `0x11` (W) | `0xc8` (Up) | Move up (overlay uses indices `0..4`). |
| `1` | `0x1f` (S) | `0xd0` (Down) | Move down. |
| `2` | `0x1e` (A) | `0xcb` (Left) | Move left. |
| `3` | `0x20` (D) | `0xcd` (Right) | Move right. |
| `4` | `0x100` | `0x9d` (RControl) | Primary fire (P1 default uses a non‑DIK sentinel). |
| `5` | `0x17e` | `0x17e` | Unused/reserved. |
| `6` | `0x17e` | `0x17e` | Unused/reserved. |
| `7` | `0x10` (Q) | `0xd3` (Delete) | Rotate/aux? (mapped to runtime slots). |
| `8` | `0x12` (E) | `0xd1` (PageDown) | Rotate/aux? (mapped to runtime slots). |
| `9` | `0x13f` | `0x13f` | Unknown (mapped). |
| `10` | `0x140` | `0x140` | Unknown (mapped). |
| `11` | `0x141` | `0x141` | Unknown (mapped). |
| `12` | `0x153` | `0x153` | Unknown (mapped). |
| `13` | `0x17e` | `0x17e` | Unused/reserved. |
| `14` | `0x17e` | `0x17e` | Unused/reserved. |
| `15` | `0x17e` | `0x17e` | Unused/reserved. |

Grim input query (partial, vtable `+0x80` → `FUN_10006fe0` in `grim.dll`):
- `code < 0x100`: DirectInput keyboard state (raw DIK).
- `0x100..0x104`: mouse buttons `0..4` (via Grim `+0x58`).
- `0x11f..0x12b`: joystick buttons `0..12` (via Grim `+0xa8`).
- `0x13f..0x155`: analog axes (reads `DAT_1005d830/834/838/83c/840/844`, thresholded).
- `0x16d..0x17b`: joystick POV/axis queries via `DAT_1005d3b4` (if device present).

Grim key‑click helper (vtable `+0x48` → `FUN_10007390`):
- Uses `FUN_1000a370` (keyboard state byte) plus per‑key timers; returns 1 on a new press edge.

Grim misc getter (vtable `+0xa4` → `FUN_100075b0`):
- Returns `*(DAT_1005d850 + index*4)`; only index 0 observed in `crimsonland.exe` (`FUN_0041e8d0/1e8f0`).


### High score record (0x48 bytes) — metadata 0x20..0x37

The high score record embeds run metadata used for duplicate detection and ranking. These
fields are compared in `FUN_0043abd0` before a score can replace an existing entry.

| Offset | Address | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x20` | `DAT_00487060` | Survival/time metric (ms) | `FUN_0043b520` compares `survival_elapsed_ms` to `DAT_00482b30` for mode 2/3 ranking; `FUN_0043abd0` compares this dword. |
| `0x24` | `DAT_00487064` | Score/XP snapshot | Copied from `player_experience` each frame; `FUN_0043b520` compares against `DAT_00482b34` for non‑survival modes; included in `FUN_0043abd0`. |
| `0x28` | `DAT_00487068` | Game mode id | Set from `config_game_mode` in high‑score screens; also used to pick which metric to rank in `FUN_0043afa0`. |
| `0x29` | `DAT_00487069` | Quest stage major | Set from `quest_stage_major` and used in quest high‑score path naming. |
| `0x2a` | `DAT_0048706a` | Quest stage minor | Set from `quest_stage_minor` and used in quest high‑score path naming. |
| `0x2b` | `DAT_0048706b` | Most‑used weapon id | Set to the max‑usage index in `DAT_0048708c` before save. |
| `0x2c` | `DAT_0048706c` | Shots fired | Incremented on projectile spawns; clamped against hits; compared in `FUN_0043abd0`. |
| `0x30` | `DAT_00487070` | Shots hit | Incremented on projectile hit paths (creature hitbox size 16.0); clamped to shots fired; compared in `FUN_0043abd0`. |
| `0x34` | `DAT_00487074` | Creature kill count | Incremented on creature death paths; compared in `FUN_0043abd0`. |


### High score record (0x48 bytes) — tail bytes 0x40..0x47

Score entries are 0x48 bytes (`DAT_00482b10` array, `DAT_00487040` active record). The
tail bytes are validated against the current date and the full‑version flag.

| Offset | Address | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x40` | `DAT_00487080` | Day‑of‑month | Written via `param_1 + 0x10` (word index → +0x40) in `FUN_0043ad70`; compared to `local_system_day` (`DAT_00495ace`) in `FUN_0043afa0` mode 3. |
| `0x41` | `DAT_00487081` | Date checksum (week‑of‑year) | `FUN_0043a950` result stored at `param_1 + 0x41`; compared in mode 2. |
| `0x42` | `DAT_00487082` | Month (1–12) | Stored from `local_system_time._2_1_` (`DAT_00495ac8`); compared to `local_system_time._2_2_`. |
| `0x43` | `DAT_00487083` | Year‑2000 | Stored as `(char)local_system_time + '0'` (`DAT_00495ac8`, low byte wraps); compared to `year - 2000`. |
| `0x44` | `DAT_00487084` | Score flags | Bit 0 gates update vs append (and load gating in `FUN_0043afa0`); bit 1 is set to `2` when replacing an existing record and bypasses the load gate; bit 2 marks the entry selected for display after duplicate reduction. |
| `0x45` | `DAT_00487085` | Full‑version marker | Set to `0x75` (`'u'`) when `DAT_00480790 != 0`; checked in quest‑mode load to accept full/limited records. |
| `0x46` | `DAT_00487040 + 0x46` | Sentinel `0x7c` (`'|'`) | Initialized in `FUN_0043afa0` default‑record loop. |
| `0x47` | `DAT_00487040 + 0x47` | Sentinel `0xff` | Initialized in `FUN_0043afa0` default‑record loop. |

Checksum helper (`FUN_0043a950`):
- Inputs: year, month, day (from `local_system_time` + `local_system_day`).
- Returns a week‑of‑year style checksum (1..53) used when `config_highscore_date_mode == 2`.
- Used during both record write (`FUN_0043ad70`) and validation (`FUN_0043afa0`).

High score validation (`FUN_0043afa0`):
- Records only proceed to date checks if `config_score_load_gate` is set, or the record flags
  have bit 0 clear, or bit 1 set.
- Mode 3: day + month + year must match (`local_system_day`, `local_system_time`).
- Mode 2: checksum from `FUN_0043a950(year, month, day)` must match `highscore_date_checksum`,
  and year must match.
- Mode 1: month + year must match; other mode values skip the date check.

### Quest progression counters (high confidence)

- `quest_stage_major` (`DAT_00487004`) tracks the current quest episode/tier.
  - Evidence: increments after every 10 minor stages (`if 10 < quest_stage_minor` then
    `quest_stage_major++`, `quest_stage_minor -= 10`) during quest summary flow.
- Initialized to `1` in `FUN_004120b0` alongside high‑score state reset.
- `quest_stage_minor` (`DAT_00487008`) tracks the quest mission within the episode.
  - Evidence: used in quest string lookups and final‑mission checks (`major == 5 && minor == 10`).
- Incremented on quest results screen when the player chooses “Play Next”.
- Persistence: `quest_stage_major/minor` are runtime-only (reset on startup) and only used to
  select metadata and to build per‑quest high‑score filenames (`scores5\\quest*.hi`). Quest
  unlock progress is saved separately in `game_status_blob` via `quest_unlock_index` and
  `quest_unlock_index_full` (see below).
- `quest_play_counts` (`DAT_00485618`) increments on quest start (`game_state_id == 9`,
  `_config_game_mode == 3`) using the `[major * 10 + minor]` index.
- `quest_unlock_index` (`DAT_00487034`) stores the max quest unlock index (computed as
  `quest_stage_major * 10 + quest_stage_minor - 10`). It is updated on quest completion and
  persisted via `game_save_status`/`game_load_status`.
- `quest_unlock_index_full` (`DAT_00487038`) stores the full‑version unlock index (same
  calculation) and is only updated when `config_full_version` is set.
- `quest_meta_cursor` (`DAT_004c3650`) tracks the quest metadata entry last written by
  `FUN_00430a20` during `quest_database_init`.
- `quest_monster_vision_meta` (`DAT_004c3658`) points to a specific quest metadata entry
  used to force the Monster Vision perk in `perks_generate_choices`.

### Quest unlock table (perk/weapon rewards)

Quest metadata includes two reward fields:
- `quest_unlock_perk_id` (`DAT_00484750`, offset `+0x20`) — perk unlock for a quest (stride `0x2c`).
- `quest_unlock_weapon_id` (`DAT_00484754`, offset `+0x24`) — weapon unlock for a quest (stride `0x2c`).

Indexing: `quest_index = (quest_stage_major - 1) * 10 + (quest_stage_minor - 1)`.
Values below are initialized in `quest_database_init` (`FUN_00439230`).

Tier 1
- Quest 1: weapon Assault Rifle (id 0x02)
- Quest 2: weapon Shotgun (id 0x03)
- Quest 3: perk Uranium Filled Bullets (perk_id_uranium_filled_bullets, id 0x1c)
- Quest 4: weapon Flamethrower (id 0x08)
- Quest 5: perk Doctor (perk_id_doctor, id 0x1d)
- Quest 6: weapon Submachine Gun (id 0x05)
- Quest 7: perk Monster Vision (perk_id_monster_vision, id 0x1e)
- Quest 8: weapon Gauss Gun (id 0x06)
- Quest 9: perk Hot Tempered (perk_id_hot_tempered, id 0x1f)
- Quest 10: weapon Rocket Launcher (id 0x0c)

Tier 2
- Quest 1: perk Bonus Economist (perk_id_bonus_economist, id 0x20)
- Quest 2: weapon Plasma Rifle (id 0x09)
- Quest 3: perk Thick Skinned (perk_id_thick_skinned, id 0x21)
- Quest 4: weapon Ion Rifle (id 0x15)
- Quest 5: perk Barrel Greaser (perk_id_barrel_greaser, id 0x22)
- Quest 6: weapon Mean Minigun (id 0x07)
- Quest 7: perk Ammunition Within (perk_id_ammunition_within, id 0x23)
- Quest 8: weapon Sawed-off Shotgun (id 0x04)
- Quest 9: perk Veins Of Poison (perk_id_veins_of_poison, id 0x24)
- Quest 10: weapon Plasma Minigun (id 0x0b)

Tier 3
- Quest 1: perk Toxic Avenger (perk_id_toxic_avenger, id 0x25)
- Quest 2: weapon Multi-Plasma (id 0x0a)
- Quest 3: perk Regeneration (perk_id_regeneration, id 0x26)
- Quest 4: weapon Seeker Rockets (id 0x0d)
- Quest 5: perk Pyromaniac (perk_id_pyromaniac, id 0x27)
- Quest 6: weapon Blow Torch (id 0x0f)
- Quest 7: perk Ninja (perk_id_ninja, id 0x28)
- Quest 8: weapon Rocket Minigun (id 0x12)
- Quest 9: perk Highlander (perk_id_highlander, id 0x29)
- Quest 10: weapon Jackhammer (id 0x14)

Tier 4
- Quest 1: perk Jinxed (perk_id_jinxed, id 0x2a)
- Quest 2: weapon Pulse Gun (id 0x13)
- Quest 3: perk Perk Master (perk_id_perk_master, id 0x2b)
- Quest 4: weapon Plasma Shotgun (id 0x0e)
- Quest 5: perk Reflex Boosted (perk_id_reflex_boosted, id 0x2c)
- Quest 6: weapon Mini-Rocket Swarmers (id 0x11)
- Quest 7: perk Greater Regeneration (perk_id_greater_regeneration, id 0x2d)
- Quest 8: weapon Ion Minigun (id 0x16)
- Quest 9: perk Breathing Room (perk_id_breathing_room, id 0x2e)
- Quest 10: weapon Ion Cannon (id 0x17)

Tier 5
- Quest 1: weapon Ion Shotgun (id 0x1f)
- Quest 2: perk Death Clock (perk_id_death_clock, id 0x2f)
- Quest 3: perk My Favourite Weapon (perk_id_my_favourite_weapon, id 0x30)
- Quest 4: weapon Gauss Shotgun (id 0x1e)
- Quest 5: perk Bandage (perk_id_bandage, id 0x31)
- Quest 6: perk Angry Reloader (perk_id_angry_reloader, id 0x32)
- Quest 7: no unlock
- Quest 8: perk Ion Gun Master (perk_id_ion_gun_master, id 0x33)
- Quest 9: perk Stationary Reloader (perk_id_stationary_reloader, id 0x34)
- Quest 10: weapon Plasma Cannon (id 0x1c)

Record match + display selection:
- `FUN_0043abd0` is the equality predicate used during save‑file replacement; it compares the
  player name plus metadata fields at offsets `0x20..0x34` (ints + a byte) and does not look
  at the flags byte.
- After loading/sorting, `FUN_0043afa0` sets flag bit 2 on the single best record per name
  (or all records when a name slot is selected), so the UI can filter displayed entries.

Init timing note:
- `qpc_timestamp_scratch` (`DAT_00495ad6`) is only used as a temporary QPC storage during
  early init (`QueryPerformanceCounter` in `FUN_0042b090`); it sits near the date scratch
  globals but is not part of the high‑score checksum path.

### Renderer backend selection (medium confidence)

- `FUN_004566d3` -> `renderer_select_backend`
  - Evidence: copies a function table, reads config `DisableD3DXPSGP`,
    and switches between multiple vtable variants (`FUN_004567b0`, `FUN_004568c0`, `FUN_00456aa5`).


### Texture loading helpers (high confidence)

- `FUN_0042a670` -> `texture_get_or_load`
  - Evidence: calls Grim `get_texture_handle` (0xc0); if missing, calls `load_texture` (0xb4),
    logs success/failure, and re-queries handle.
- `FUN_0042a700` -> `texture_get_or_load_alt`
  - Evidence: identical body to `texture_get_or_load`; primary callers pass `.jaz` assets.


### CRT errno accessors (high confidence)

- `FUN_00465d93` -> `crt_errno_ptr` (`_errno`-style accessor)
- `FUN_00465d9c` -> `crt_doserrno_ptr` (`__doserrno`-style accessor)
- `FUN_00465d20` -> `crt_dosmaperr` (Win32 error -> errno mapper)
- Evidence:
  - Both call `crt_get_thread_data()` and return pointer offsets (`+2`, `+3`).
  - `crt_dosmaperr` stores Win32 errors into `*crt_doserrno_ptr` and maps to `*crt_errno_ptr`
    via the error table at `DAT_0047b7c0`.
  - File I/O wrappers set these directly on failure:
    - `FUN_004655bf` (FlushFileBuffers) stores `GetLastError()` in `*FUN_00465d9c` and sets
      `*FUN_00465d93 = 9` (EBADF).
    - `FUN_004656b7` (WriteFile) and `FUN_00466064` (ReadFile) call `crt_dosmaperr` after
      `GetLastError()` for non-trivial errors.
    - `FUN_0046645e` (SetFilePointer) maps `GetLastError()` through `crt_dosmaperr`.


### CRT lock/unlock helpers (high confidence)

- `FUN_0046586b` -> `crt_lock`
  - Evidence: calls `InitializeCriticalSection`, `EnterCriticalSection`, and `__amsg_exit` in the
    lock path; invoked by `crt_exit_lock` and many CRT wrappers.
- `FUN_004658cc` -> `crt_unlock`
  - Evidence: calls `LeaveCriticalSection`; invoked by `crt_exit_unlock` and many CRT wrappers.
- `FUN_00463da5` -> `crt_lock_file`
  - Evidence: uses `crt_lock` for small-stream table entries or a `FILE`-embedded critical section.
- `FUN_00463df7` -> `crt_unlock_file`
  - Evidence: inverse of `crt_lock_file`, calls `crt_unlock` or `LeaveCriticalSection`.
- `FUN_0046acf8` -> `crt_lock_fh`
  - Evidence: initializes per-file handle critical sections and enters the lock.
- `FUN_0046ad57` -> `crt_unlock_fh`
  - Evidence: leaves the per-file handle critical section.


### CRT ctype helpers (high confidence)

- `FUN_00463c74` -> `crt_isctype`
  - Evidence: uses `PTR_DAT_0047b1c0` table for single-byte and falls back to
    `GetStringTypeA/W` for multi-byte characters.
- `FUN_00462fd0` -> `crt_isalpha`
  - Evidence: calls `crt_isctype` with mask `0x103` (alpha/upper/lower).
- `FUN_00462ffe` -> `crt_isspace`
  - Evidence: calls `crt_isctype` with mask `0x8` (space).


### CRT exit/stdio helpers (high confidence)

- `FUN_00460d08` -> `crt_onexit`
  - Evidence: takes exit callback, grows onexit table (`DAT_004db4f4`/`DAT_004db4f0`) via
    `FUN_004626aa`, stores pointer, and wraps with `crt_exit_lock`/`crt_exit_unlock`.
- `FUN_00460d86` -> `crt_atexit`
  - Evidence: calls `crt_onexit` and returns `0` on success, `-1` on failure.
- `FUN_00460dc7` -> `crt_free`
  - Evidence: thin wrapper around `FUN_004625c1` (CRT heap free).
- `FUN_004625c1` -> `crt_free_base`
  - Evidence: checks heap mode (`DAT_004da3a8`), locks heap, frees via small-block helpers, and
    falls back to `HeapFree`.
- `FUN_00460e5d` -> `crt_fclose`
  - Evidence: if `_flag & 0x40` not set, locks stream, calls `__fclose_lk`, unlocks; otherwise
    clears `_flag`.
- `FUN_0046100e` -> `crt_fsopen`
  - Evidence: parses mode string, passes share flag to `FUN_0046adbd`, populates `FILE` fields.
- `FUN_0046103f` -> `crt_fopen`
  - Evidence: forwards to `crt_fsopen` with share mode `0x40` (`_SH_DENYNO`).
- `FUN_004615ae` -> `crt_fwrite`
  - Evidence: wraps `crt_fwrite_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `FUN_004615dd` -> `crt_fwrite_nolock`
  - Evidence: writes buffers directly to file handle, uses `crt_flsbuf` for single-byte writes.
- `FUN_00461af7` -> `crt_fread`
  - Evidence: wraps `crt_fread_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `FUN_00461b26` -> `crt_fread_nolock`
  - Evidence: reads buffers directly from file handle and sets EOF/error flags.
- `FUN_00461d91` -> `crt_fseek`
  - Evidence: wraps `crt_fseek_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `FUN_00461dbd` -> `crt_fseek_nolock`
  - Evidence: validates stream flags, flushes, and seeks via `crt_lseek`.
- `FUN_004616e7` -> `crt_sprintf`
  - Evidence: uses CRT output core `FUN_00464380` with an unbounded count (`0x7fffffff`) and
    terminates with `\0` on success.
- `FUN_00464268` -> `crt_flsbuf`
  - Evidence: flushes/allocates stream buffers, handles append seeks, and writes a single char;
    used by `crt_fwrite`/`crt_sprintf` when buffers underflow.
- `FUN_00464b1e` -> `crt_putc_nolock`
  - Evidence: decrements buffer count, calls `crt_flsbuf` on underflow, otherwise writes byte and
    updates the output counter (printf output helper).
- `FUN_00464b53` -> `crt_putc_repeat_nolock`
  - Evidence: loops count times calling `crt_putc_nolock`, used for space/zero padding in printf.
- `FUN_00464b84` -> `crt_putc_buffer_nolock`
  - Evidence: emits a string buffer via `crt_putc_nolock`, stops on error.
- `FUN_004663f9` -> `crt_lseek`
  - Evidence: validates handle, locks via `crt_lock_fh`, then calls `crt_lseek_nolock`.
- `FUN_0046645e` -> `crt_lseek_nolock`
  - Evidence: calls `SetFilePointer`, clears EOF flag on success, uses `crt_dosmaperr` on error.
- `FUN_0046dd16` -> `crt_chsize`
  - Evidence: uses `crt_lseek_nolock` to get size, truncates via `SetEndOfFile` or extends by
    writing zero-filled blocks, then restores the file offset.


### Grim/libpng helpers (high confidence)

- `FUN_1001e114` -> `png_error`
  - Evidence: calls `png_ptr->error_fn` when set and then `longjmp(png_ptr, 1)`.
- `FUN_1001e132` -> `png_warning`
  - Evidence: calls `png_ptr->warning_fn` when set.
- `FUN_1002047c` -> `png_read_data`
  - Evidence: dispatches to `read_data_fn` or raises `png_error` on NULL.
- `FUN_10020583` -> `png_reset_crc`
  - Evidence: seeds `png_ptr->crc` via `crc32(0, NULL, 0)`.
- `FUN_1002059b` -> `png_calculate_crc`
  - Evidence: updates CRC unless skip flags indicate the chunk is ignored.
- `FUN_10024741` -> `png_malloc`
  - Evidence: malloc wrapper that calls `png_error` on OOM.
- `FUN_10024777` -> `png_free`
  - Evidence: free wrapper with `(png_ptr, ptr)` signature.
- `FUN_10024734` -> `png_free_ptr`
  - Evidence: simple free wrapper used for png buffers and the main png_ptr.
- `FUN_10024807` -> `png_crc_read`
  - Evidence: calls `png_read_data` then `png_calculate_crc` on the same buffer.
- `FUN_10024821` -> `png_crc_error`
  - Evidence: reads the stored CRC and compares it against `png_ptr->crc`.
- `FUN_1002487f` -> `png_check_chunk_name`
  - Evidence: validates 4-letter chunk type and errors on invalid characters.
- `FUN_100250d7` -> `png_crc_finish`
  - Evidence: consumes remaining chunk bytes, checks CRC, and raises error/warning.


### Grim pixel/format helpers (high confidence)

- `FUN_1000aaa6` -> `grim_format_info_lookup`
  - Evidence: walks the D3D format descriptor table (`DAT_1004c3b0`) and returns the entry for the
    requested format id, falling back to a default descriptor.
- `FUN_100174a8` -> `grim_apply_color_key`
  - Evidence: iterates RGBA float pixels and zeroes those that match the current color key
    (`this+0x1c..0x28`), used after converting pixel buffers.


### Audio SFX helpers (medium confidence)

- `FUN_0043d120` -> `sfx_play`
  - Evidence: validates entry in `DAT_004c84e4`, checks cooldown `DAT_004c3c80`, sets sample rate
    via `bonus_reflex_boost_timer` into `DAT_00477d28`, chooses a voice (`FUN_0043be60`), calls vtable +0x40
    with pan 0, then sets volume with `FUN_0043bfa0`.
- `FUN_0043d260` -> `sfx_play_panned`
  - Evidence: same as `sfx_play`, but converts an FPU value to pan (`__ftol`), clamps to
    `[-10000, 10000]`, and passes pan to vtable +0x40.
- `FUN_0043d550` -> `sfx_mute_all`
  - Evidence: sets `DAT_004c8450[sfx]=1` and recursively mutes all other unmuted ids using
    `sfx_is_unmuted`.
- `FUN_0043d7c0` -> `sfx_is_unmuted`
  - Evidence: returns true when `DAT_004cc8d6` is set and the per-id mute flag is clear.
- `FUN_0043d460` -> `sfx_play_exclusive`
  - Evidence: mutes other ids, optionally selects a random variant, and ensures the chosen id is
    unmuted with its volume set in `DAT_004c404c`.
- `FUN_0043d5b0` -> `sfx_update_mute_fades`
  - Evidence: ramps per-id volume toward `DAT_004807b0` when unmuted and fades to zero when muted,
    stopping voices via `FUN_0043bf60`.
- `FUN_0043c9c0` -> `audio_init_music`
  - Evidence: loads `music.paq`, logs status, and registers track ids:
    - `DAT_004c4030` = `music_intro.ogg`
    - `DAT_004c4034` = `music_shortie_monk.ogg`
    - `DAT_004c4038` = `music_crimson_theme.ogg`
    - `DAT_004c4044` = `music_crimsonquest.ogg`
    - `DAT_004c403c`/`_DAT_004c4040` = subsequent track ids (+1/+2).
- `FUN_0043caa0` -> `audio_init_sfx`
  - Evidence: loads `sfx.paq` and registers the sound effect ids.
  - See [SFX ID map](sfx-id-map.md) for the extracted id-to-file mapping.
  - See [SFX usage](sfx-usage.md) for the most referenced SFX ids in the decompiled code.
  - See [SFX label suggestions](sfx-labels.md) for suggested data labels (ApplyDataMap applies data labels).
- `FUN_0043c740` -> `sfx_load_sample`
  - Evidence: allocates a free slot in `DAT_004c84e4`, loads `.ogg`/`.wav` data, and returns the
    sample id.
- `FUN_0043c700` -> `sfx_release_sample`
  - Evidence: releases an sfx entry by id via `sfx_release_entry`.
- `FUN_0043c090` -> `sfx_release_entry`
  - Evidence: frees sample buffers/voices and clears entry state.
- `FUN_0043c8d0` -> `music_load_track`
  - Evidence: allocates a free track in `DAT_004c4250`, loads the tune, and returns the id.
- `FUN_0043c960` -> `music_queue_track`
  - Evidence: appends a track id into `DAT_004cc6d0` playlist array.
- `FUN_0043c980` -> `music_release_track`
  - Evidence: releases a music entry by id via `sfx_release_entry`.
- `FUN_0043cf90` -> `sfx_system_init`
  - Evidence: initializes the Grim SFX system and clears `DAT_004c3c80`/`DAT_004c3e80` tables.
- `FUN_0043d070` -> `sfx_release_all`
  - Evidence: iterates `DAT_004c84d0` entries and calls `sfx_release_entry`.
- `FUN_0043d0d0` -> `music_release_all`
  - Evidence: iterates `DAT_004c4250` entries and calls `sfx_release_entry`.
- `FUN_0043d110` -> `audio_shutdown_all`
  - Evidence: calls `sfx_release_all`, `music_release_all`, and the audio backend shutdown helper.


### Global var access (medium confidence)

- `FUN_0042fcf0` -> `perk_count_get`
  - Evidence: returns `(&player_perk_counts)[perk_id]` (`DAT_00490968`) directly; used to track perk picks and gating.


### Save/load helpers (medium confidence)

- `FUN_0042a980` -> `reg_read_dword_default`
  - Evidence: wraps `RegQueryValueExA` for `REG_DWORD` and writes fallback on failure.
- `FUN_0042a9c0` -> `reg_write_dword`
  - Evidence: wraps `RegSetValueExA` with `REG_DWORD`.
- `FUN_00412a10` -> `game_sequence_load`
  - Evidence: reads the `sequence` registry value and updates `DAT_00485794`.
- `FUN_00412a80` -> `game_save_status`
  - Evidence: writes registry values (`sequence`, `dataPathId`, `transferFailed`) and saves a
    `game.cfg`-style status file; logs `GAME_SaveStatus OK/FAILED`.
- `FUN_00412c10` -> `game_load_status`
  - Evidence: loads the status file, validates checksum/size, and regenerates it on failure;
    logs `GAME_LoadStatus ...`.


### Effect spawn helper (medium confidence)

- `FUN_0042de80` -> `effect_init_entry`
  - Evidence: zeros/sets default fields on a single entry and initializes per-quad color slots.
- `FUN_0042df10` -> `effect_defaults_reset`
  - Evidence: resets global template values (`DAT_004ab1*`) used by effect spawners.
- `FUN_0042e080` -> `effect_free`
  - Evidence: pushes the entry back onto `effect_free_list_head` free list and clears live flag.
- `FUN_0042e0a0` -> `effect_select_texture`
  - Evidence: maps effect id through `effect_id_size_code` / `effect_id_frame` and calls Grim vtable +0x104 with
    texture page bitmasks.
- `FUN_0042e120` -> `effect_spawn`
  - Evidence: pops an entry from the pool `effect_free_list_head`, copies template `effect_template_vel_x`,
    writes position from `param_2`, tags the effect id, and assigns quad UVs from atlas tables
    `effect_id_size_code` / `effect_id_frame` plus arrays `effect_uv16_u`, `effect_uv8_u`, `effect_uv4_u`, `effect_uv2_u`.
- `FUN_0042e710` -> `effects_update`
  - Evidence: iterates pool entries, advances timers/positions with `DAT_00480840`, and calls
    `effect_free` when expired.
- `FUN_0042e820` -> `effects_render`
  - Evidence: sets render state, iterates effects, computes rotated quad vertices, and submits
    via Grim vtable +0x134.


### Perk database + selection (medium confidence)

- `FUN_0042fd90` -> `perks_init_database`
  - Evidence: assigns perk id constants (`DAT_004c2b**`/`DAT_004c2c**`) and fills the perk
    name/description tables via `FUN_0042fd00`.
  - See [Perk ID map](perk-id-map.md) for the extracted id-to-name mapping.
- `FUN_0042fb10` -> `perk_can_offer`
  - Evidence: checks mode gates and perk flags, then returns a nonzero byte if the perk is eligible.
- `FUN_0042fbd0` -> `perk_select_random`
  - Evidence: randomizes an id from the perk table, calls `perk_can_offer`, and logs a failure when
    selection runs too long.
- `FUN_0042fc30` -> `perks_rebuild_available`
  - Evidence: resets `DAT_004c2c4c` flags and re-enables base/unlocked perks.
  - Table layout (stride `0x14`): `name` @ `DAT_004c2c40`, `desc` @ `DAT_004c2c44`,
    `flags` @ `DAT_004c2c48`, `available` @ `DAT_004c2c4c`, `prereq` @ `DAT_004c2c50`.
  - Flag bits (inferred):
    - `0x1` allows perks when `_DAT_00480360 == 3`.
    - `0x2` allows perks when `_DAT_0048035c == 2` (two-player mode).
    - `0x4` marks stackable perks (random selection accepts them even if already taken).
  - Prereq field is checked via `perk_count_get` and gates perks like Toxic Avenger (requires
    Veins of Poison), Ninja (requires Dodger), Perk Master (requires Perk Expert), and
    Greater Regeneration (requires Regeneration).
- `FUN_004055e0` -> `perk_apply`
  - Evidence: called after selecting a perk in the UI, increments `perk_count_get` table, and
    executes the perk-specific effects (exp, health, weapon changes, perk spawns).
- `FUN_004045a0` -> `perks_generate_choices`
  - Evidence: fills `DAT_004807e8` with randomly selected perks using `perk_select_random`,
    enforces uniqueness, and applies special-case handling for mode `8` (fixed perk list).
- Perk prompt UI gates (high confidence):
  - `perk_prompt_timer` (`DAT_0048f524`) ramps 0..200 while perks are pending and feeds the
    prompt alpha plus the transform matrix (`perk_prompt_transform_*` at `DAT_0048f510..DAT_0048f51c`).
  - `perk_prompt_origin_x/y` (`DAT_0048f224`/`DAT_0048f228`) anchor the prompt bounds for hover/click
    tests; `perk_prompt_bounds_min_*` (`DAT_0048f248`/`DAT_0048f24c`) and
    `perk_prompt_bounds_max_*` (`DAT_0048f280`/`DAT_0048f284`) define the relative rectangle.
  - `perk_prompt_hover_active` (`DAT_0048f500`) flips when the cursor enters/leaves the perk prompt
    bounds and gates whether the click target is active.
  - `perk_prompt_pulse` (`DAT_0048f504`) ramps `0..1000` (decays when not hovered, accelerates when
    hovered) and is forced to `1000` when the perk pick key is pressed.
  - `perk_choices_dirty` (`DAT_00486fb0`) is set after perk selection and on reset, then cleared the
    first time `perks_generate_choices` runs before switching to state `6`.


### Tutorial prompt (medium confidence)

- `FUN_00408530` -> `tutorial_prompt_dialog`
  - Evidence: renders the tutorial message panel and uses button UI for "Repeat tutorial",
    "Play a game", and "Skip tutorial"; click handlers restart the tutorial (clears perk count
    table `player_perk_counts` (`DAT_00490968`) and resets timers) or exit to game (sets `game_state_pending` (`DAT_00487274`), flushes input,
    and resets `DAT_00486fe0`).
  - Signature (inferred): `void tutorial_prompt_dialog(char *text, float alpha)`
  - `alpha` comes from `tutorial_timeline_update` (0..1), controls the prompt fade, and is used
    to scale the button visuals; the decompiler currently shows it as a `char` because the call
    site passes `SUB41` of a float.


### Tutorial timeline (medium confidence)

- `FUN_00408990` -> `tutorial_timeline_update`
  - Evidence: loads the tutorial string table, advances `DAT_00486fd8` stage index when
    `DAT_00486fe0` counts up from `-1000`, and renders each stage via `tutorial_prompt_dialog`.
  - Timers:
    - `DAT_00486fdc` accumulates per-frame time (`DAT_00480844`), gates stage 0 auto-advance
      and is used to fade stage 5 after 5 seconds.
    - `DAT_00486fe0` is a stage transition/fade timer: it counts up from `-1000` toward `-1`
      to advance the stage, then counts up from `0` to `1000` before snapping back to `-1`.
      The absolute value is scaled by `0.001` to derive the prompt alpha.
  - Stage transitions observed:
    - Stage 0: after `DAT_00486fdc > 6000` and `DAT_00486fe0 == -1`, clears `DAT_004808a8`,
      resets `DAT_004712fc`, and sets `DAT_00486fe0 = -1000`.
    - Stage 1: waits for any movement key active (`grim_is_key_active` via vtable +0x80),
      then spawns bonus pickups (`FUN_0042ef60`) and sets `DAT_00486fe0 = -1000`.
    - Stage 2: waits until all 16 bonus slots in `bonus_pool` (`DAT_00482948`) clear, then sets
      `DAT_00486fe0 = -1000`.
    - Stage 3: waits for input in `player_fire_key` (`DAT_00490bec`) key slots, spawns arrow markers
      (`FUN_00430af0`), then sets `DAT_00486fe0 = -1000`.
    - Stage 4: waits for `creatures_none_active()`, spawns arrow markers, sets `DAT_00486fdc = 1000`,
      then sets `DAT_00486fe0 = -1000`.
    - Stage 5: increments `DAT_004808a8` on repeated `creatures_none_active()` events, spawns markers/bonuses,
      and after 8 iterations sets `player_experience` (`DAT_0049095c`) to 3000 and `DAT_00486fe0 = -1000`.
    - Stage 6: waits for `perk_pending_count` (`DAT_00486fac`) < 1, spawns markers, then sets `DAT_00486fe0 = -1000`.
  - Stage 7: waits for `creatures_none_active()` with no active bonus slots, then sets `DAT_00486fe0 = -1000`.
  - Stage text table (array indexed by `DAT_00486fd8`, base is `local_38`):

    | Stage | Text |
    | --- | --- |
    | 0 | This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby! |
    | 1 | Reflex Boost powerup slows down time giving you a chance to react better |
    | 2 | (empty string, `DAT_00472718`) |
    | 3 | (empty string, `DAT_00472718`) |
    | 4 | In this tutorial you'll learn how to play Crimsonland |
    | 5 | First learn to move by pushing the arrow keys. |
    | 6 | Now pick up the bonuses by walking over them |
    | 7 | Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot. |
    | 8 | Now, move the mouse to aim at the monsters |

  - Secondary hint overlay:
    - `DAT_004712fc` increments when the current bonus object (`DAT_004808ac`) flips inactive with flag `0x400`,
      and `DAT_004808b4` ramps the hint alpha (up/down at 3x delta, clamped 0..1000).
    - The hint text is fetched from the same stack string block (`afStack_5c[DAT_004712fc + 2]`);
      entries that point to `DAT_00472718` are skipped because the string starts with `0xa7`
      (`-0x59`), matching the guard byte check.
  - Additional strings in the same stack block include perk tutorial lines
    ("It will help you to move and shoot...", Perks intro, Perks description, "Great! Now you are ready to start"),
    plus speed/weapon/x2 powerup blurbs (`local_44/local_40/local_3c`).
  - Helper: `FUN_00428210` -> `creatures_none_active`
    - Evidence: scans the creature table at `DAT_0049bf38` for any active entries, sets `DAT_0048700c`,
      and returns low byte `1` only when the table is empty.
  - Stage index wraps to 0 when `DAT_00486fd8` reaches 9; counters are initialized in `FUN_00412dc0`
    (`DAT_00486fd8 = -1`, `DAT_00486fe0 = -1000`) and reset by `tutorial_prompt_dialog`.

### UI button helpers (medium confidence)

- `FUN_004034a0` -> `ui_mouse_inside_rect`
  - Evidence: checks mouse coordinates (`DAT_004871ec`/`DAT_004871f0`) against `xy + (w, h)` and
    returns 1 when inside and `DAT_004871cc` is clear.
- `FUN_0043d830` -> `ui_focus_update`
  - Evidence: tracks a rolling list of focus candidates in `DAT_004ccbd0`, responds to key input
    to move focus, and returns nonzero when the provided id matches the focused entry.
- `FUN_0043d940` -> `ui_focus_draw`
  - Evidence: draws a small highlight quad near the focused item location using the UI renderer.
- `FUN_0043e830` -> `ui_button_update`
  - Evidence: draws the small/medium button textures, updates hover/press timers using
    `ui_mouse_inside_rect`, and returns nonzero when the button is activated.

Button struct (size `0x18`, used by `DAT_0047f5f8` / `DAT_00480250` / `DAT_004807d0`):

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | `label` | `char *` text pointer passed to `grim_measure_text_width`. |
| 0x04 | `hovered` | low byte set from `ui_mouse_inside_rect`. |
| 0x05 | `activated` | set to 1 when `ui_button_update` triggers; cleared otherwise. |
| 0x06 | `enabled` | when 0, disables hover/press and decays the hover timer. |
| 0x08 | `hover_t` | 0..1000 hover animation timer (ramps ±4/±6 per frame). |
| 0x0c | `press_t` | 0..1000 press flash timer (decays by 6 per frame). |
| 0x10 | `alpha` | base alpha scale (1.0 default). |
| 0x14 | `flags` | byte flags; `0x15` is checked to force a wide button. |
| 0x15 | `force_wide` | overrides width selection for short labels. |

### Quest timeline (medium confidence)

- `FUN_0043a790` -> `quest_start_selected`
  - Evidence: resets quest state, selects quest metadata at `DAT_00484730`, queues perk state, and
    runs the quest builder at `DAT_0048474c` (or `quest_build_fallback` when null).
- `FUN_00434250` -> `quest_spawn_timeline_update`
  - Evidence: walks the quest spawn table (`DAT_004857a8`, count `DAT_00482b08`), checks trigger
    time vs `DAT_00486fd0`, and spawns each entry with `FUN_00430af0` using a 0x28 spacing offset.
- `FUN_00434220` -> `quest_spawn_table_empty`
  - Evidence: returns 1 when all spawn entries have been cleared (no pending spawns).
- `FUN_004343e0` -> `quest_build_fallback`
  - Evidence: logs a fallback warning and writes two default entries (spawn id `0x40`, counts 10/0x14,
    trigger times 500/5000).
- `FUN_004343c0` -> `quest_database_advance_slot`
  - Evidence: increments quest index, wraps every 10, and advances the tier.
- `FUN_00439230` -> `quest_database_init`
  - Evidence: populates the quest metadata table (`DAT_00484730`) with names, durations, and builder
    function pointers.


### Creature table (partial)

- `FUN_00428140` -> `creature_alloc_slot`
  - Evidence: scans `DAT_0049bf38` in `0x98`-byte strides for `active == 0`, clears flags/seed fields,
    increments `DAT_00486fb4`, and returns the slot index (or `0x180` on failure).
- Layout (entry size `0x98`, base `DAT_0049bf38`, pool size `0x180`):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | active (byte) | checked for zero in most creature loops; set to `1` on spawn, cleared on death. |
  | 0x14 | pos_x | set in `FUN_00428240`, used in distance checks and targeting. |
  | 0x18 | pos_y | set in `FUN_00428240`, used in distance checks and targeting. |
  | 0x1c | vel_x | computed from heading/speed and passed to `FUN_0041e400` for movement. |
  | 0x20 | vel_y | computed from heading/speed and passed to `FUN_0041e400` for movement. |
  | 0x24 | health | checked as `> 0` for valid targets and in perk kill logic (`<= 500`). |
  | 0x28 | max_health | set from `health` on spawn; used when splitting (clone health is `max_health * 0.25`). |
  | 0x2c | heading (radians) | set from `rand % 0x13a * 0.01` on spawn; eased toward desired heading via `FUN_0041f430`. |
  | 0x30 | desired heading | computed from target position and stored each frame. |
  | 0x34 | collision radius (?) | used in collision tests in `FUN_00420600`. |
  | 0x38 | hit flash timer | decremented each frame; set by `FUN_004207c0` on damage. |
  | 0x50 | target_x | target position derived from player/formation/linked enemy. |
  | 0x54 | target_y | target position derived from player/formation/linked enemy. |
  | 0x60 | attack cooldown | decremented each frame; gates projectile spawns for some flags. |
  | 0x6c | type id (spawn param) | written from `param_3` in `FUN_00428240`. |
  | 0x70 | target player index | toggled between players based on distance; indexes player pos arrays. |
  | 0x78 | link index / state timer | used as linked creature index in several AI modes; also incremented as a timer when `0x80` flag is set. |
  | 0x8c | flags | bit tests `0x4/0x8/0x400` guard behaviors in update/split logic. |
  | 0x90 | AI mode | selects movement pattern (cases 0/1/3/4/5/6/7/8 in update loop). |
  | 0x94 | anim phase | accumulates and wraps (31/15) to drive sprite animation timing. |

See [Creature struct](creature-struct.md) for the expanded field map and cross-links.


### Projectile pool (partial)

- `FUN_00420440` -> `projectile_spawn`
  - Evidence: allocates a slot in `projectile_pool` (`DAT_004926b8`), initializes angle/pos/type/owner,
    and callers store the return index.
- `FUN_00420b90` -> `projectile_update`
  - Evidence: iterates `0x60` projectile entries, advances movement, checks collisions against
    creatures/players, spawns hit effects, and clears expired entries.
- `FUN_004205d0` -> `projectile_reset_pools`
  - Evidence: clears `projectile_pool` (`DAT_004926b8`, `0x40` stride) and
    `particle_pool` (`DAT_00493eb8`, `0x38` stride).
- `FUN_00420600` -> `creatures_apply_radius_damage`
  - Evidence: loops active creatures, checks distance vs radius + size, and calls `FUN_004207c0`.
- `FUN_004206a0` -> `creature_find_in_radius`
  - Evidence: returns the first creature index within `radius` starting at `start_index` (or `-1`).
- `FUN_00420730` -> `player_find_in_radius`
  - Evidence: scans the player health table (`player_health`, `DAT_004908d4`), skipping the owner id,
    and returns the first player within range.
- Layout (entry size `0x40`, base `projectile_pool` (`DAT_004926b8`), pool size `0x60`):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | active (byte) | Set on spawn; cleared when lifetime expires. |
  | 0x08 | pos_x | Spawn position and update movement use. |
  | 0x0c | pos_y | Spawn position and update movement use. |
  | 0x20 | type id | Spawn parameter, drives branch logic. |
  | 0x24 | life timer | Decrements by `DAT_00480840`, clearing when <= 0. |
  | 0x34 | hit radius | Used for creature collision checks. |
  | 0x3c | owner id | Used to skip the shooter in hit tests. |

See [Projectile struct](projectile-struct.md) for the expanded field map and notes.


### Effects pools (medium confidence)

- `FUN_00420130` -> `fx_spawn_particle`
  - Evidence: allocates a `0x38`-byte entry in `particle_pool` (`DAT_00493eb8`), sets position, angle,
    and velocity (speed ~90), and returns the slot index.
- `FUN_00420240` -> `fx_spawn_particle_slow`
  - Evidence: same pool as `fx_spawn_particle`, but speed ~30 and sets style id `8`.
- `FUN_00420360` -> `fx_spawn_secondary_projectile`
  - Evidence: allocates a `0x2c`-byte entry in `secondary_projectile_pool` (`DAT_00495ad8`) with type
    id, velocity, and optional nearest-creature target when `type_id == 2`.
- `FUN_0041fbb0` -> `fx_spawn_sprite`
  - Evidence: allocates a `0x2c`-byte entry in `sprite_effect_pool` (`DAT_00496820`) with position,
    velocity, tint, and a scalar parameter used by the renderer.
- Layouts and fields are tracked in [Effects pools](effects-struct.md).


### Bonus / pickup pool (medium confidence)

- `FUN_0041f580` -> `bonus_alloc_slot`
  - Evidence: scans `bonus_pool` (`DAT_00482948`) in `0x1c`-byte strides and returns the first entry
    with type `0` (or the sentinel `bonus_pool_sentinel` / `DAT_00490630` when full).
- `FUN_0041f5b0` -> `bonus_spawn_at`
  - Evidence: clamps position to arena bounds, writes entry fields (type, lifetime, size, position,
    duration override), and spawns a pickup effect via `FUN_0042e120`.
- `FUN_0040a320` -> `bonus_update`
  - Evidence: decrements bonus lifetimes, checks player proximity, calls `bonus_apply` on pickup,
    and clears entries when `time_left` expires.
- `FUN_004295f0` -> `bonus_render`
  - Evidence: renders bonus icons from `DAT_0048f7f0`, scales/fades by timer, and draws label text
    via `bonus_label_for_entry` when players are nearby.
- `FUN_00429580` -> `bonus_label_for_entry`
  - Evidence: returns a formatted label string for bonus entries (weapon/score cases use a formatter).
- `FUN_00409890` -> `bonus_apply`
  - Evidence: applies bonus effects based on entry type (`param_2[0]`), spawns effects via
    `FUN_0042e120`, and plays bonus SFX (`FUN_0043d260`).
- See [Bonus ID map](bonus-id-map.md) for the id-to-name table and default amounts.
- Layout (entry size `0x1c`, base `bonus_pool` (`DAT_00482948`), 16 entries):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | type id (0 = free) | `bonus_alloc_slot` scans for `0`; render/update skip `0`. |
  | 0x04 | state flag (`bonus_state`) | `bonus_update` sets to `1` after pickup and accelerates lifetime decay. |
  | 0x08 | time_left (`bonus_time_left`) | decremented each frame in `bonus_update`; set to `0.5` on pickup; expiry clears type to `0`. |
  | 0x0c | time_max (`bonus_time_max`) | set to `10.0` on spawn; used for fade/flash in `bonus_render`. |
  | 0x10 | pos_x (`bonus_pos_x`) | set on spawn; used for distance checks. |
  | 0x14 | pos_y (`bonus_pos_y`) | set on spawn; used for distance checks. |
  | 0x18 | amount/duration (`bonus_amount`) | used by `bonus_apply` when applying certain bonus types. |


### Game mode selector (partial)

- `_DAT_00480360` holds the current game mode. See [Game mode map](game-mode-map.md) for the observed
  values and evidence.
- `FUN_00412960` -> `game_mode_label`
  - Evidence: returns a label string based on `_DAT_00480360` (Survival, Quests, Typ-o-Shooter, etc.).


### Survival mode (partial)

- `FUN_00407cd0` -> `survival_update`
  - Evidence: runs only when `_DAT_00480360 == 1`, advances scripted spawn stages, and calls
    `survival_spawn_creature` when the spawn timer elapses.
- `FUN_00407510` -> `survival_spawn_creature`
  - Evidence: allocates a creature slot, assigns spawn position, and selects a type based on
    `DAT_0049095c` thresholds before seeding speed/health and flags.
- Key state:
  - `DAT_00486fc4` acts as the spawn cooldown accumulator; it is decremented by
    `player_count * frame_dt`, and when it drops below zero a burst of spawns is scheduled.
  - `DAT_00487060` is the survival elapsed timer (ms). It is incremented each frame and is used
    to scale spawn cadence and HUD timers.
  - `DAT_00487190` is the scripted spawn stage index (0..10) that gates bonus/marker spawns by
    `DAT_00490964` milestones.
  - `player_experience` (`DAT_0049095c`) is the survival XP/progression score (HUD label `Xp`, displayed via the
    smoothed `DAT_00490300`) and is used for creature type/health scaling in `survival_spawn_creature`.
  - `player_level` (`DAT_00490964`) is the survival level/milestone counter (drawn as `%d` in the HUD) that gates
    scripted spawns in `survival_update`; it increments when `player_experience` surpasses a periodic
    threshold.
  - The HUD shows `Xp`, the smoothed XP value, and a `Progress` label with a bar fed by
    `player_experience`/`player_level` (`DAT_0049095c`/`DAT_00490964`) and a 1-second timer derived from `FUN_00461140()`.
