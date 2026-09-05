# Historical symbol-recovery notebook

Archived from `docs/re/static/detangling.md` on 2026-09-05. This is an immutable
record of early naming hypotheses and evidence, not current architecture or a
work queue. Paths, labels and uncertainty below describe that historical work.
Current references are routed through the documentation's source-recovery page.

---
tags:
  - status-analysis
---

# Detangling notes
This page tracks high-value functions to name and the evidence gathered so far.
Use the hotspot script to refresh the lists when structured function snapshots
are regenerated.

## Hotspot script

```
uv run scripts/function_hotspots.py --top 12 --only-fun
```

## Name/data map workflow

We keep authoritative function renames/signatures in `analysis/ghidra/maps/name_map.json`
and data labels in `analysis/ghidra/maps/data_map.json`, applying both during headless
analysis:

```
just ghidra-exe
```

You can also set `CRIMSON_NAME_MAP` / `CRIMSON_DATA_MAP` to point at custom maps.

## High-call functions (current)

### `crimsonland.exe`

```
crimsonland.exe_functions.json
   3    2 0046a39e crt_fp_round_digits undefined crt_fp_round_digits(char * param_1, int param_2, int param_3)
   3    1 00461981 crt_ehvec_ctor undefined crt_ehvec_ctor(undefined4 param_1, undefined4 param_2, int param_3, undefined * param_4)
   3    1 0046ad79 crt_file_buffer_init undefined crt_file_buffer_init(undefined4 * param_1)
   3    1 0046d5c7 crt_mbcs_init undefined crt_mbcs_init(void)
   3    0 00420040 creature_find_nearest int creature_find_nearest(float * param_1, int param_2, float param_3)
   3    0 0045eac0 x3d_vec3_transform_coord_inline undefined8 * x3d_vec3_transform_coord_inline(undefined8 * param_1, undefined8 * param_2, undefined8 * param_3)
   3    0 0045eb4b mat4_mul undefined8 * mat4_mul(undefined8 * param_1, undefined8 * param_2, undefined8 * param_3)
   3    0 004601c0 math_acos_packed ulonglong math_acos_packed(void)
   3    0 004608c0 math_sin_packed undefined math_sin_packed(void)
   3    0 004654a5 crt_init_thread_data undefined crt_init_thread_data(int param_1)
   3    0 00466c7b crt_sbh_find_region uint crt_sbh_find_region(int param_1)
   3    0 004679d6 crt_sbh_find_block int crt_sbh_find_block(undefined * param_1, undefined4 * param_2, uint * param_3)
```

### `grim.dll`

```
grim.dll_functions.json
  30    0 100170d6 fpu_set_round_trunc undefined fpu_set_round_trunc(undefined4 param_1)
  20    0 1004b5b0 seh_prolog undefined seh_prolog(void)
  10    0 10001160 grim_noop undefined grim_noop(void)
   8    2 1001029e d3dx_image_destroy undefined d3dx_image_destroy(int param_1)
   6    1 1001692e grim_vertex_space_converter_destroy undefined grim_vertex_space_converter_destroy(undefined4 * param_1)
   6    0 1000cbff float_near_equal undefined4 float_near_equal(float param_1, float param_2)
   6    0 100161b6 d3dx_lock_surface_dtor undefined4 d3dx_lock_surface_dtor(byte * param_1)
   6    0 10020708 fpu_save_control_word undefined fpu_save_control_word(undefined4 param_1)
   6    0 1002faab d3dx_jpeg_fill_bit_buffer undefined4 d3dx_jpeg_fill_bit_buffer(undefined4 * param_1, uint param_2, int param_3, int param_4)
   5    2 100161bb d3dx_lock_surface_lock int d3dx_lock_surface_lock(void * this, undefined4 * param_1, int * param_2, undefined4 param_3, uint * param_4, undefined4 param_5, uint param_6)
   5    1 1001ac4a grim_pixel_format_init_dxt undefined4 * grim_pixel_format_init_dxt(void * this, undefined4 * param_1)
   4    3 100101f5 grim_d3d_debug_set_mute undefined grim_d3d_debug_set_mute(undefined4 param_1)
```

## Identified candidates

### Logging / console queue (high confidence)

- `0x0046e8f4` -> `strdup_malloc`
  - Evidence: `strlen` + `malloc` + copy (crt_strcpy (`0x00465c30`)) pattern.
- `0x004017a0` -> `console_push_line`
  - Evidence: pushes strdup’d strings into a list, caps at 0x1000 entries.
- `0x00401870` -> `console_printf`
  - Evidence: formats strings (uses crt_vsprintf (`0x00461089`)) then pushes into the console queue; callsites include `Unknown command`/CMOD logs.
- `0x00402350` -> `console_register_cvar`
  - Evidence: searches existing entry by name, allocates a 0x24 entry when missing, strdup’s name/value, parses float via `crt_atof_l`, and is used by `register_core_cvars` with `cv_*` strings.
- `0x00401940` -> `console_exec_line`
  - Evidence: parses a line into command/cvar targets, executes command callbacks, updates cvar values, and logs
    status/errors; called with `exec_autoexec.txt` and `exec_music_game_tunes.txt`.

### Status/config paths (high confidence)

- `0x00402bd0` -> `game_build_path`
  - Evidence: formats `"%s\\%s"` with `game_base_path` and a filename argument; used with
    `console.log`, `game.cfg` (save/status blob), and `crimson.cfg` (config blob).

- `0x0041ec60` -> `config_sync_from_grim`
  - Evidence: pulls Grim config values (`+0x24` accessor), seeds default config blob when the
    Grim config dialog was invoked, loads `crimson.cfg` overrides, and writes the 0x480‑byte
    blob back out.

- `0x0041f130` -> `config_ensure_file`
  - Evidence: ensures `crimson.cfg` exists by writing the current config blob when missing.

### Console command/cvar helpers (high confidence)

- `0x00402580` -> `console_tokenize_line`
  - Evidence: copies the input into `console_tokenize_buf`, splits with `crt_strtok`, stores the command in
    `console_cmd_name` and arguments in `console_cmd_arg1..`, and updates `console_cmd_argc` (token count).

- `0x00402480` -> `console_cvar_find`
  - Evidence: walks the cvar list at `*this` and string-compares entry names against the target.
- `0x004024e0` -> `console_cvar_unregister`
  - Evidence: calls `console_cvar_find`, unlinks the node from the list, and returns success.
- `0x00402750` -> `console_command_find`
  - Evidence: same search as `console_cvar_find`, but over the command list at `this+4`.
- `0x00402530` -> `console_command_unregister`
  - Evidence: calls `console_command_find` and unlinks the node from the command list.
- `0x00402630` -> `console_cvar_autocomplete`
  - Evidence: returns an exact match or `_strncmp` prefix match; used to fill the input buffer during tab
    completion.

- `0x004027b0` -> `console_command_autocomplete`
  - Evidence: same as `console_cvar_autocomplete`, but over the command list.
### UI element timeline + transitions (high confidence)

- `0x0041a530` -> `ui_elements_update_and_render`
  - Evidence: advances a global timeline (`ui_elements_timeline` (`0x00487248`)) based on `frame_dt_ms`, clamps to
    `ui_elements_max_timeline`, triggers screen transitions via game_state_set (`0x004461c0`), and iterates
    `ui_element_table_start`..`ui_element_table_end` calling ui_element_update (`0x00446900`) + `ui_element_render`.

- `0x00446170` -> `ui_elements_reset_state`
  - Evidence: clears the element active flag (`*(char *)element`) and zeroes the per-element
    hover timer at `+0x2f8` across the UI element table.

- `0x00446190` -> `ui_elements_max_timeline`
  - Evidence: returns the max `element+0x10` value among active elements (used to clamp the
    UI transition timeline).

### Game state transitions (high confidence)

- `0x004461c0` -> `game_state_set`
  - Evidence: clears UI element state (`ui_elements_reset_state`), updates `game_state_prev`/`game_state_id`,
    resets transition globals, and seeds UI elements; invoked on startup (`game_core_init`), when perk selection
    is requested (`FUN_0040af70`), and when UI transitions complete (`ui_elements_update_and_render`).

### Gameplay session reset (high confidence)

- `0x004120b0` -> `gameplay_run_state_init`
  - Evidence: initializes `highscore_active_record` to default/sentinel values and resets run-scoped
    globals (quest stage/counters, demo flag, spawn stage) before gameplay/session flows.

- `0x00412dc0` -> `gameplay_reset_state`
  - Evidence: clears HUD/bonus slots, resets spawn/timer globals, seeds creature type textures/SFX, refreshes
    weapon/perk availability, and zeroes run/high-score counters; invoked when demo mode starts and on state
    transitions that require a fresh session.

### Demo mode bootstrap (high confidence)

- `0x00403390` -> `demo_mode_start`
  - Evidence: forces the demo game state, sets `demo_mode_active`, calls `gameplay_reset_state`, selects one of
    several demo setups, and advances the demo cycle index.

### Demo trial timing (high confidence)

- `0x0041df50` -> `demo_trial_time_limit_ms`
  - Evidence: returns constant `2400000` (40 minutes) and is used by
    `demo_trial_overlay_render` for remaining-time math.

### Gameplay helpers (high confidence)

- `0x0040ff50` -> `time_format_mm_ss`
  - Evidence: formats `total_seconds` as `m:ss` into static buffer `time_format_mm_ss_buffer`;
    callsites feed Base/Life/Perk/Final time rows in quest/game-over result panels.

- `0x00413540` -> `player_heading_approach_target` (signature fix: `float` return)
  - Evidence: normalizes heading wrap, turns toward target by `frame_dt * shortest_delta * 5`,
    and callers use returned shortest angular distance to scale movement while turning.

- `0x0041a810` -> `bonus_hud_slot_activate`
  - Evidence: allocates a free entry in the 16-slot `bonus_hud_slot_table`, wiring label/icon
    and timer pointers; called from timed-bonus branches in `bonus_apply`.

- `0x00425d80` -> `plaguebearer_spread_infection`
  - Evidence: only called in the Plaguebearer path of `creature_update_all`; checks nearby
    creatures (`<45` units) and propagates `collision_flag` for targets under `150` HP.

- `0x004281e0` -> `creature_reset_all` (signature fix: `void`)
  - Evidence: called at quest start before spawn setup; clears active creature slots and
    detaches any occupied `creature_spawn_slot_table[].owner` links.

### Menu/plugin/highscore helpers (high confidence)

- `0x0040b630` -> `plugin_runtime_update_and_render`
  - Evidence: dispatch uses it for `game_state_id == 0x16`; runs plugin `Init/Frame/Shutdown`,
    manages fallback to state `0x14`, and controls cursor/UI transition behavior.

- `0x0040b5d0` -> `plugin_runtime_clear_pools`
  - Evidence: called from plugin init path; clears bonus/creature/projectile/player active slots
    before entering plugin runtime.

- `0x00403430` -> `ui_mouse_inside_rect_with_padding`
  - Evidence: list/dropdown widgets use it for hit-tests with relaxed left/top bounds (`x-10`, `y-2`).

- `0x0043aa90` -> `highscore_record_pack_for_submit`
  - Evidence: online submit path copies `highscore_record_t` metadata into 0x40-byte upload records and
    clears bytes `0x3c..0x3f`.

- `0x0043aa60` -> `highscore_submit_full_version_guard`
  - Evidence: online submit selection path uses it as an illegal-score/full-version guard; emits the
    "potential illegal score" log when blocked.

- `0x00441270` -> `highscore_format_date_label`
  - Evidence: text input render uses it to format day/month label text in `highscore_date_label_buffer`
    via `s_fmt_highscore_date_label`.

- `0x004411c0` / `highscore_card_draw_vertical_divider` -> `highscore_card_draw_horizontal_divider` /
  `highscore_card_draw_vertical_divider`
  - Evidence: both are small scorecard-only render helpers used by `ui_text_input_render`; they draw
    1px divider lines with the shared card tint (`highscore_card_divider_color_r..0xb4`) and update the local layout cursor.

- `0x00448b50` -> `input_detect_active_analog_axis`
  - Evidence: polls `grim_get_config_float` on analog axis keycodes (`0x13f`, `0x140`, `0x141`,
    `0x153`, `0x154`, `0x155`) and returns the first moved axis id; used by control-config assignment flow.

- `0x00447420` -> `ui_menu_click_back_contextual`
  - Evidence: callback always starts a UI transition and routes `game_state_pending` to state `0`
    (main menu) unless in the in-game menu context (`render_pass_mode`/`plugin_runtime_active_latch`), where it routes to state `5`.

- `0x0043d9b0` -> `ui_segmented_slider_update`
  - Evidence: widget updates focus/hover/drag and arrow-key input, clamps current value against
    `[min,max]`, and renders 8x16 on/off segment strips using cached `ui_rectOn/ui_rectOff` handles.

- `0x00447c90` -> `input_configure_for_label`
  - Evidence: returns the configure-for label set (`Mouse/Keyboard/Joystick/Mouse relative/Dual Action Pad/Computer`).

- `0x0044faa0` -> `ui_element_init_defaults`
  - Evidence: menu layout init applies it across `ui_element_table_end` entries and a standalone prompt
    element to seed default UI element runtime state.

- `0x004123d0` / `0x0042faa0` -> `bonus_meta_table_init` / `perk_meta_table_init`
  - Evidence: both are `crt_ehvec_ctor` table constructors with matching `crt_atexit` registration helpers.

- `0x0041e8d0` / `0x0041e8f0` -> `input_aim_pov_left_active` / `input_aim_pov_right_active`
  - Evidence: `player_update` uses them in POV-aim mode to decrement/increment `aim_heading`.

- `0x00446140` -> `ui_callback_noop`
  - Evidence: function body is empty; credits/high-score/menu paths call/install it as a placeholder callback.

### Typ-o gameplay loop (high confidence)

- `0x004457c0` -> `typo_gameplay_update_and_render`
  - Evidence: dispatch runs it for `game_state_id == 0x12`; routine handles typed-name input
    (`typo_input_buffer`), matches against Typ-o target names, then renders world/HUD.

### UI text input (high confidence)

- `0x0043ecf0` -> `ui_text_input_update`
  - Evidence: handles focus/hover, polls text input via `console_input_poll`, plays typing SFX, and renders
    the input box plus caret.

- `0x004413a0` -> `ui_text_input_render`
  - Evidence: renders the text input field with caret blink and state‑dependent colors; used by high‑score
    entry paths and other text input flows.

### Typ-o name generation (high confidence)

- `0x00444f70` -> `typo_word_pick_fragment`
  - Evidence: returns a random word fragment from a static table; `typo_target_name_assign_random`
    composes one to four fragments into a Typ-o target name.

- `0x004451b0` -> `typo_word_pick_highscore_name`
  - Evidence: lazily builds a cache of unique alphabetic names from `highscore_table` and
    returns a random cached entry for Typ-o target naming variants.

- `typo_target_name_is_unique` / `typo_target_name_assign_random` / `typo_target_find_by_name` / `typo_target_name_draw_labels` ->
  `typo_target_name_is_unique` / `typo_target_name_assign_random` / `typo_target_find_by_name` /
  `typo_target_name_draw_labels`
  - Evidence: all four helpers are only used by Typ-o gameplay and read/write
    `typo_target_name_table`; they implement target-name generation, lookup, and in-world label rendering.

### Audio resource packs + loaders (high confidence)

- `0x0043b980` -> `resource_pack_set`
  - Evidence: opens the pack file to validate it, caches the path, and flips the pack-enabled flag.
- `0x0043b940` -> `resource_pack_read_cstring`
  - Evidence: reads NUL-terminated entry names from the pack file into `resource_pack_entry_name_buf`.
- `0x0043b9e0` -> `resource_open_read`
  - Evidence: when a resource pack is active, opens the pack and searches entries; otherwise opens the file
    directly, returns the file size, and leaves the file handle in a global used by sample/track loaders.

- `0x0043bad0` -> `resource_close`
  - Evidence: closes the global resource file handle (`resource_fp`) after a read.
- `0x0043bca0` -> `resource_read_alloc`
  - Evidence: opens a resource, allocates a buffer of the reported size, reads it fully, and returns the pointer.
- `0x0043c020` -> `sfx_entry_load_wav`
  - Evidence: reads a WAV resource into memory then parses headers/data into an sfx entry.
- `0x0043c110` -> `wav_parse_into_entry`
  - Evidence: parses RIFF/WAV headers from a memory buffer and copies PCM into the entry.
- `0x0043bcf0` -> `sfx_entry_load_ogg`
  - Evidence: initializes an Ogg/Vorbis decoder from a resource buffer and fills an sfx entry.
- `0x0043c3a0` -> `music_entry_load_ogg`
  - Evidence: initializes an Ogg/Vorbis decoder for music streaming and allocates the stream buffer.
- `0x0043b850` -> `buffer_reader_init`
  - Evidence: sets the buffer pointer/size used by the WAV parser.
- `0x0043b870` -> `buffer_reader_seek`
  - Evidence: sets the current read cursor for the WAV parser.
- `0x0043b880` -> `buffer_reader_read_u16`
  - Evidence: reads a little-endian 16-bit value and advances the cursor.
- `0x0043b8a0` -> `buffer_reader_read_u32`
  - Evidence: reads a little-endian 32-bit value and advances the cursor.
- `0x0043b8c0` -> `buffer_reader_skip`
  - Evidence: advances the read cursor by N bytes.
- `0x0043b8e0` -> `buffer_reader_find_tag`
  - Evidence: scans the buffer for a tag (e.g., RIFF/data) and advances the cursor to it.
- `0x0043baf0` -> `dsound_init`
  - Evidence: creates the DirectSound device and primary buffer (used by `sfx_system_init`).
- `0x0043bc20` -> `dsound_shutdown`
  - Evidence: releases the DirectSound device.
- `0x0043bc40` -> `dsound_restore_buffer`
  - Evidence: handles `DSERR_BUFFERLOST` by restoring the buffer.
- `0x0043c230` -> `sfx_entry_upload_buffer`
  - Evidence: locks a DirectSound buffer, copies PCM data, and unlocks it.
- `0x0043c2b0` -> `sfx_entry_create_buffers`
  - Evidence: creates and duplicates DirectSound buffers for an sfx entry.
- `0x0043c520` -> `music_stream_update`
  - Evidence: advances stream cursors and triggers refills when the play cursor wraps.
- `0x0043c590` -> `music_stream_fill`
  - Evidence: decodes Ogg data and writes the next streaming chunk.

Audio entries are 0x84-byte `audio_entry_t` records; see [Audio](../../re/static/reference/audio.md)
for the field layout used by `sfx_entry_table` and `music_entry_table`.

### Audio playback + streaming (high confidence)

- `0x0043d3f0` -> `audio_update`
  - Evidence: ticks sfx cooldowns, updates music stream buffers, and applies mute fades.
- `0x0043be60` -> `sfx_entry_start_playback`
  - Evidence: selects a free voice/buffer (or streaming buffer) and starts playback.
- `0x0043be20` -> `sfx_entry_seek`
  - Evidence: resets the DirectSound cursor and seeks the Ogg decoder to a sample offset.
- `0x0043bf40` -> `sfx_entry_resume`
  - Evidence: restarts streaming playback (used on resume/unmute).
- `0x0043bf60` -> `sfx_entry_stop`
  - Evidence: stops playback for all voices in the entry (used on suspend/mute).
- `0x0043bfa0` -> `sfx_entry_set_volume`
  - Evidence: applies volume changes across active voices.
### Input primary action (high confidence)

- `0x00446030` -> `input_primary_just_pressed`
  - Evidence: exact source gates on `console_open_flag`, then edge-detects mouse button 0 and
    the `fire_key` field in both fixed 0x360-byte player records with `input_primary_latch`.
    A held edge is returned only once and the latch clears after every source is released.
    Used across UI click/confirm paths and player fire/selection logic.

- `0x004460f0` -> `input_primary_is_down`
  - Evidence: exact source returns true while mouse button 0 or the `fire_key` field in either
    fixed player record is held, with no player-count read or edge-latch mutation. The second
    record doubles as `player_alt_fire_key` in one-player configuration. Used by UI scroll/drag
    handling.

- `0x00446000` -> `input_any_key_pressed`
  - Evidence: scans keycodes `2..0x17e` via the input callback at `(*grim_interface_ptr + 0x80)`.

### Data labels (high confidence)

- `0x00480348` -> `config_blob`
  - Evidence: 0x480‑byte `crimson.cfg` blob; see config layout below.
- `config_p1_move_forward` -> `config_keybind_table`
  - Evidence: 2×16 dword keybind table inside config blob; copied into runtime binds.
- `0x00482948` -> `bonus_pool`
  - Evidence: bonus/pickup pool base with 16 entries (stride `0x1c`).
- `0x004908d4` -> `player_health`
  - Evidence: per-player health (table base) with stride `0xd8`; see player struct.
- `0x004912b8` -> `fx_queue`
  - Evidence: FX queue base with 0x80 entries (stride `0x28`).
- `0x004926b8` -> `projectile_pool`
  - Evidence: base of 0x60-entry projectile pool with stride 0x40.
- `0x00493eb8` -> `particle_pool`
  - Evidence: particle pool base with 0x80 entries (stride `0x38`).
- `0x00495ad8` -> `secondary_projectile_pool`
  - Evidence: secondary projectile pool base with 0x40 entries (stride `0x2c`).
- `0x00496820` -> `sprite_effect_pool`
  - Evidence: sprite effect pool base with stride `0x2c`.
- `0x0049bf38` -> `creature_pool`
  - Evidence: base of 0x180‑entry creature pool with stride 0x98.
- `0x004aaf3c` -> `fx_queue_rotated`
  - Evidence: rotated FX queue base with 0x40 entries.
- `0x004d7a2c` -> `weapon_table`
  - Evidence: base of weapon table with stride 0x7c (see weapon table doc).

### Creature spawn + damage (high confidence)

- `0x00430af0` -> `creature_spawn_template`
  - Evidence: calls `creature_alloc_slot`, writes the `creature_pool` pool fields, maps
    `template_id` to type/flags, and spawns linked satellites; heading `-100` uses
    a randomized heading.

- `0x004207c0` -> `creature_apply_damage`
  - Evidence: applies perk multipliers, reduces HP and knockback, calls
    `creature_handle_death`, spawns effects, and returns `1` when the creature dies.

### Gameplay render pass (high confidence)

- `0x00405960` -> `gameplay_render_world`
  - Evidence: updates `ui_transition_alpha` (`0x00487278`) (fade), renders the FX queue, creatures,
    player overlays (dead/alive ordering), projectiles, and bonuses.

### Key binding block (`player_move_key_forward`..`player_alt_key_reserved_3`) (medium confidence)

These live inside the per-player input struct (stride `0x360` bytes / `0xd8` dwords) and are
queried through `grim_is_key_active` (`+0x80`) or `grim_is_key_down` (`+0x44`).
Defaults are set in `config_load_presets`.

| Address | Default (DIK) | Guess | Evidence |
| --- | --- | --- | --- |
| `0x00490bdc` | `0x11` (W) | move forward (`player_move_key_forward`) | queried via `is_key_active` in player movement |
| `0x00490be0` | `0x1f` (S) | move backward (`player_move_key_backward`) | queried via `is_key_active` in player movement |
| `0x00490be4` | `0x1e` (A) | turn left (`player_turn_key_left`) | rotates heading in movement scheme 1/2 |
| `0x00490be8` | `0x20` (D) | turn right (`player_turn_key_right`) | rotates heading in movement scheme 1/2 |
| `0x00490bec` | `0x0f` (Tab) | primary fire (`player_fire_key`) | used by `input_primary_*` with stride `0xd8` |
| `0x00490bf8` | `0x10` (Q) | aim rotate left (`player_aim_key_left`) | rotates `player_aim_heading` in aim scheme 1 |
| `0x00490bfc` | `0x12` (E) | aim rotate right (`player_aim_key_right`) | rotates `player_aim_heading` in aim scheme 1 |
| `player_key_reserved_0` | `0x11` (W) | unused/reserved | copied from config, but no `is_key_*` callsites found |
| `player_key_reserved_1` | `0x1f` (S) | unused/reserved | copied from config, but no `is_key_*` callsites found |
| `0x00490f3c` | `0xc8` (Up) | alt move forward (`player_alt_move_key_forward`) | used via `is_key_down` when `config_player_count == 1` |
| `0x00490f40` | `0xd0` (Down) | alt move backward (`player_alt_move_key_backward`) | used via `is_key_down` when `config_player_count == 1` |
| `0x00490f44` | `0xcb` (Left) | alt turn left (`player_alt_turn_key_left`) | used via `is_key_down` when `config_player_count == 1` |
| `0x00490f48` | `0xcd` (Right) | alt turn right (`player_alt_turn_key_right`) | used via `is_key_down` when `config_player_count == 1` |
| `0x00490f4c` | `0x9d` (RControl) | player 2 / alt primary fire (`player_alt_fire_key`) | `player_state_table[1].input.fire_key`; always checked in `input_primary_is_down` |
| `player_alt_key_reserved_0` | `0x11` (W) | unused/reserved | defaults set; no callsites yet |
| `player_alt_key_reserved_1` | `0x1f` (S) | unused/reserved | defaults set; no callsites yet |
| `player_alt_key_reserved_2` | `0xd3` (Delete) | unused/reserved | defaults set; no callsites yet |
| `player_alt_key_reserved_3` | `0xc9` (PageUp) | unused/reserved | defaults set; no callsites yet |

Key info overlay (`ui_render_keybind_help`) indexes the block at `config_p1_move_forward`
with a five-dword player stride (Up/Down/Left/Right/Fire). The exact recovered
source confirms that both columns come from the flat `config_blob.player_keys` array: Player 1
uses slots 0..4 and Player 2 uses slots 5..9. It does not step to the separate
second key block at `config_blob.input_config[1]`; this appears to be stale native layout
behavior and should not be silently corrected in parity work.

### Analog axis bindings (per-player, stride `0x360` bytes / `0xd8` dwords)

These bindings are read via `grim_get_config_float` (`+0x84`) and map to the
analog control schemes selected in the per-player mode flags:

| Address | Symbol | Scheme | Notes |
| --- | --- | --- | --- |
| `0x00490c08` | `player_axis_move_x` | movement scheme `config_movement_schemes == 3` | Used with `player_axis_move_y` to drive movement vectors. |
| `0x00490c0c` | `player_axis_move_y` | movement scheme `config_movement_schemes == 3` | Paired with `player_axis_move_x`. |
| `0x00490c00` | `player_axis_aim_x` | aim scheme `config_aim_schemes == 4` | Used to derive aim vectors for stick/axis aiming. |
| `0x00490c04` | `player_axis_aim_y` | aim scheme `config_aim_schemes == 4` | Paired with `player_axis_aim_x`. |

Config edit path status:

- No in-game rebind writes to `config_p1_axis_move_x` found in the decompile.
- `config_load_presets` reads the 0x480‑byte config blob from disk into `config_blob`
  and then copies the keybind table (`config_p1_axis_move_x`) into the per-player runtime slots.

- config_sync_from_grim (`0x0041ec60`) seeds defaults in a local 0x480 blob, optionally reads a 0x480‑byte
  config from `file_mode_read_binary`, copies the string field at offset `0x74` and the flag
  at offset `0x46c` into globals (`config_player_name_buf`, `config_violence_disabled`), then writes the
  global blob (`config_blob`, size `0x480`) using mode `file_mode_write_binary` (`"wb"`).

- config_ensure_file (`0x0041f130`) is a fallback path that writes the same `config_blob` blob using
  mode `file_mode_write_binary` (`"wb"`) when the `file_mode_read_binary` config file is missing.

- File evidence: `game_bins/crimsonland/1.9.93-gog/crimson.cfg` is exactly `0x480` bytes; `game_bins/crimsonland/1.9.93-gog/game.cfg` is not
  (likely a save/progress file). `file_mode_read_binary` is `"rb"`; the filename is supplied
  by game_build_path (`0x00402bd0`) (`"%s\\%s"`).

Config blob layout (partial, 0x480 bytes, base `config_blob`):

| Offset | Address | Size | Default | Notes |
| --- | --- | --- | --- | --- |
| `0x00` | `config_blob` | `u8` | `0` | Sound disable flag (nonzero skips SFX and music init; applied via config id `0x53`). |
| `0x01` | `config_music_disabled` | `u8` | `0` | Music disable flag (music init requires `config_blob == 0` and `config_music_disabled == 0`). |
| `0x02` | `config_highscore_date_mode` | `u8` | `0` | High‑score date validation mode: `1` = year+month, `2` = computed date checksum + year, `3` = day+month+year. |
| `0x03` | `config_highscore_duplicate_mode` | `u8` | `0` | High‑score duplicate handling: `1` = replace existing entry with same name (via `highscore_find_name_entry`). |
| `0x04` | `config_direction_arrow_flags` | `u8[2]` | `1,1` | Per‑player HUD indicator toggle (gates the second indicator draw pass). |
| `0x08` | `DAT_00480350` | `u32` | `8` | Unknown; value comes from a stack temp in config_sync_from_grim (`0x0041ec60`) (used to query Grim config), no global xrefs. |
| `0x0e` | `config_shadows_enabled` | `u8` | `0/1` | FX detail toggle (set by `config_detail_preset`). |
| `0x10` | `config_flame_glow_enabled` | `u8` | `0/1` | FX detail toggle (set by `config_detail_preset`). |
| `0x11` | `config_smoke_enabled` | `u8` | `0/1` | FX detail toggle (set by `config_detail_preset`). |
| `0x14` | `config_player_count` | `u32` | `1/2` | Player count (loop bound in most per‑player logic). |
| `0x18` | `config_game_mode` | `u32` | `1..8` | Game mode/state selector (values `1/2/3/4/8` observed). |
| `0x1c` | `config_movement_schemes` | `u8[?]` | `0` | Per‑player mode flag (value `4` triggers alternate HUD draw). |
| `0x44` | `config_aim_schemes` | `u32` | `0` | Unknown (defaulted in config_sync_from_grim (`0x0041ec60`), no xrefs). |
| `0x48` | `DAT_00480390` | `u32` | `0` | Unknown (defaulted in config_sync_from_grim (`0x0041ec60`), no xrefs). |
| `0x6c` | `config_for` | `u32` | `0` | Unknown (defaulted in config_sync_from_grim (`0x0041ec60`), no xrefs). |
| `0x70` | `config_texture_scale` | `float` | `1.0` (clamped `0.5..4.0`) | Texture/terrain scale factor (used when creating ground texture). |
| `0x74` | `config_player_name_buf` | `char[12]` | empty string | Copied from config in config_sync_from_grim (`0x0041ec60`); only explicit consumer so far. |
| `0x80` | `config_selected_saved_name_slot` | `u32` | `0` | Selected name slot (0..7) for the saved‑name list. |
| `0x84` | `config_saved_name_count` | `u32` | `1` | Saved‑name count / insert index. |
| `0x88` | `config_saved_name_order` | `u32[8]` | `0..7` | Saved‑name order table (seeded in config_sync_from_grim (`0x0041ec60`)); no xrefs in the decompile, likely unused. |
| `0xa8` | `config_saved_name_0` | `char[0xd8]` | `"default"` x8 | 8 saved names, 0x1b bytes each (`config_saved_name_1` is entry 2). |
| `0x180` | `config_player_name` | `char[36]` | `default_player_name` | Player name (copied to runtime `highscore_active_record` on load). |
| `0x1a0` | `config_player_name_length` | `u32` | `player_name_length` | Player name length (mirrored to runtime on load; config value is overwritten). |
| `0x1a4` | `DAT_004804ec` | `u32` | `100` | Seeded in config_sync_from_grim (`0x0041ec60`); no xrefs yet. |
| `0x1a8` | `DAT_004804f0` | `u32` | `0` | Unknown (defaulted in config_sync_from_grim (`0x0041ec60`), no xrefs). |
| `0x1ac` | `DAT_004804f4` | `u32` | `0` | Unknown (defaulted in config_sync_from_grim (`0x0041ec60`), no xrefs). |
| `0x1b0` | `DAT_004804f8` | `u32` | `9000` | Compared to Grim vtable `+0xa4` (grim_get_joystick_pov (`0x100075b0`)) in `input_aim_pov_right_active`; used by `player_update` when control mode reads POV aim. |
| `0x1b4` | `DAT_004804fc` | `u32` | `27000` | Compared to Grim vtable `+0xa4` (grim_get_joystick_pov (`0x100075b0`)) in `input_aim_pov_left_active`; used by `player_update` when control mode reads POV aim. |
| `0x1b8` | `config_display_bpp` | `u32` | `32` | Likely display color depth (bits‑per‑pixel); set alongside width/height via config id `0x2b` (inference from defaults and file). |
| `0x1bc` | `config_screen_width` | `u32` | `800` | Screen width. |
| `0x1c0` | `config_screen_height` | `u32` | `600` | Screen height. |
| `0x1c4` | `config_windowed` | `u8` | `0` | Windowed flag (`0` = fullscreen). |
| `0x1c8` | `config_blob.input_config` | `player_input_config_t[10]` | see below | Ten source-defined 16-dword keybind blocks; this build actively copies the first two. |
| `0x1f8` | `config_blob.input_config[0].axis_move_x` | `u32*` | alias | Interior cursor used by the P1/P2 copy loop. |
| `0x440` | `config_blob.input_config[9].reserved[1]` | `u32` | `0` | Final source-defined keybind block, currently unused. |
| `0x444` | `config_blob.input_config[9].reserved[2]` | `u32` | `0` | Final source-defined keybind block, currently unused. |
| `0x448` | `config_hardcore` | `u8` | `0` | Hardcore flag (`0` normal, `1` hardcore). |
| `0x449` | `config_ui_info_texts` | `u8` | `1` | UI info-text toggle (options checkbox; gates perk-prompt info text). `game_is_full_version()` is hardcoded to return 1 in this build; there is no full-version config byte. |
| `0x44c` | `config_level_up_count` | `u32` | `0` | Source `numLevelUps`; increments when perk selection becomes pending. |
| `0x450` | `config_ten_tons_logging_completed` | `u32` | `1` | Source-identified 10tons logging completion flag. |
| `0x454` | `config_unique_id_1` | `u32` | `0` | Source-identified installation ID. |
| `0x458` | `config_unique_id_2` | `u32` | `0` | Source-identified installation ID. |
| `0x45c` | `config_blob.reserved_identity_word` | `u32` | `0` | Later-version word with no native reads; absent from the recovered source layout. |
| `0x460` | `config_sound_frequency_adjustment` | `u8` | `1` | Sound-frequency adjustment toggle. |
| `0x464` | `config_sfx_volume` | `float` | `?` | SFX volume multiplier. |
| `0x468` | `config_music_volume` | `float` | `?` | Music volume multiplier. |
| `0x46c` | `config_violence_disabled` | `u8` | `0` | Gates blood/particle paths and alternate perk text. |
| `0x46d` | `config_show_online_scores` | `u8` | `0` | Source `showOnlineScores`; controls remote-score loading and its checkbox. |
| `0x46e` | `config_safe_mode_backend_enabled` | `u8` | `?` | Safe-mode backend flag mirrored through Grim id `0x54`. |
| `0x470` | `config_detail_preset` | `u32` | `?` | Detail preset; drives `config_shadows_enabled`, `config_flame_glow_enabled`, and `config_smoke_enabled`. |

Runtime note (2026-01-19 quest-build capture, 1.1 runs):

- Bytes at `config_hardcore..93` were `[1, 1, 0, 0]` for hardcore and `[0, 1, 0, 0]`
  for normal (both 1P/2P). This confirms:

  - `config_hardcore` toggles with hardcore (`0` normal, `1` hardcore).
  - `config_ui_info_texts` stayed `1` in all runs; later source recovery identifies it as the info-text toggle, not a full-version flag.
- `config_level_up_count` increments on perk prompt opens (observed `0x1a..0x1d`).
- Forcing `config_ui_info_texts = 0` at runtime showed no immediate visible change in that capture; its gating behavior occurs in the perk-prompt flow.
| `0x478` | `config_key_pick_perk` | `u32` | `?` | Keybind: pick perk (Level‑up prompt). |
| `0x47c` | `config_key_reload` | `u32` | `?` | Keybind: reload. |

Keybind block layout (`config_p1_move_forward`, 2 × 16 dwords, indices `0..12` copied into runtime;
`config_p1_axis_move_x` is `&config_p1_move_forward[12]`):

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

Grim input query (partial, vtable `+0x80` → grim_is_key_active (`0x10006fe0`) in `grim.dll`):

- `code < 0x100`: DirectInput keyboard state (raw DIK).
- `0x100..0x104`: mouse buttons `0..4` (via Grim `+0x58`).
- `0x11f..0x12a`: joystick buttons `0..11` (via Grim `+0xa8`).
- `0x131..0x134`: joystick up/down/left/right deadzone helpers.
- `0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, `0x155`: six analog axes
  (reads `grim_joystick_state/834/838/83c/840/844`, scales by `0.001`, and tests
  `fabs(value) > 0.5`).
- `0x16d..0x17b`: three groups of five RIM actions dispatched through the
  optional provider at `grim_input_provider` as `(player, action)`.

Grim key‑click helper (vtable `+0x48` → grim_was_key_pressed (`0x10007390`)):

- Uses grim_keyboard_key_down (`0x1000a370`) plus per-key timers. It returns 1
  on the press edge, waits 0.5 seconds, then repeats every 0.1 seconds while
  held; releasing the key resets its first-press latch.

Grim misc getter (vtable `+0xa4` → grim_get_joystick_pov (`0x100075b0`)):

- Returns `*(DAT_1005d850 + index*4)`; only index 0 observed in `crimsonland.exe` (`input_aim_pov_left_active` / `input_aim_pov_right_active`).
### High score record (0x48 bytes) — name 0x00..0x1f

The record begins with the player name (copied from config on load and compared
by `highscore_record_equals`).

| Offset | Address | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x00` | `highscore_active_record` | Player name (NUL‑terminated, 0x20 bytes) | Copied from config `player_name` on load; compared in `highscore_record_equals`. |
### High score record (0x48 bytes) — metadata 0x20..0x37

The high score record embeds run metadata used for duplicate detection and ranking. These
fields are compared in `highscore_record_equals` before a score can replace an existing entry.

| Offset | Address | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x20` | `0x00487060` | Survival/time metric (ms) | `highscore_rank_index` compares `survival_elapsed_ms` to `DAT_00482b30` for mode 2/3 ranking; `highscore_record_equals` compares this dword. |
| `0x24` | `highscore_score_xp` | Score/XP snapshot | Copied from `player_experience` each frame; `highscore_rank_index` compares against `DAT_00482b34` for non‑survival modes; included in `highscore_record_equals`. |
| `0x28` | `highscore_record_game_mode` | Game mode id | Set from `config_game_mode` in high‑score screens; also used to pick which metric to rank in `highscore_load_table`. |
| `0x29` | `highscore_record_quest_major` | Quest stage major | Set from `quest_stage_major` and used in quest high‑score path naming. |
| `0x2a` | `highscore_record_quest_minor` | Quest stage minor | Set from `quest_stage_minor` and used in quest high‑score path naming. |
| `0x2b` | `highscore_record_weapon_id` | Most‑used weapon id | Set to the max‑usage index in `weapon_usage_time` before save. |
| `0x2c` | `highscore_record_shots_fired` | Shots fired | Incremented on projectile spawns; clamped against hits; compared in `highscore_record_equals`. |
| `0x30` | `highscore_record_shots_hit` | Shots hit | Incremented on projectile hit paths (`lifecycle_stage == 16.0`); clamped to shots fired; compared in `highscore_record_equals`. |
| `0x34` | `creature_kill_count` | Creature kill count | Incremented on creature death paths; compared in `highscore_record_equals`. |
| `0x38` | `highscore_record_random_tag` | `uniNum` | Original `score_t::Reset` / `ResetLight` initializes this to `rand() & (16348 * 16348 - 1)`. |
| `0x3c` | `DAT_0048707c` | Reserved | Original header names this dword `reserved`. The online submit path zeroes this dword in the 0x40-byte record copies (`highscore_record_pack_for_submit`), suggesting it is not required for leaderboard uploads. |
### High score record (0x48 bytes) — tail bytes 0x40..0x47

Score entries are 0x48 bytes (`highscore_table` array, `highscore_active_record` active record). The
tail bytes are validated against the current date and the full‑version flag.

| Offset | Address | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x40` | `highscore_day` | Day‑of‑month | Written via `param_1 + 0x10` (word index → +0x40) in `highscore_write_record`; compared to `local_system_day` (`0x00495ace`) in `highscore_load_table` mode 3. |
| `0x41` | `highscore_record_date_checksum` | `dateWeek` | Week-of-year value stored at `param_1 + 0x41`; compared in mode 2. |
| `0x42` | `highscore_month` | Month (1–12) | Stored from `local_system_time._2_1_` (`0x00495ac8`); compared to `local_system_time._2_2_`. |
| `0x43` | `highscore_year_offset` | Year‑2000 | Stored as `(char)local_system_time + '0'` (`0x00495ac8`, low byte wraps); compared to `year - 2000`. |
| `0x44` | `highscore_flags` | Score flags | Bit 0 gates update vs append (and load gating in `highscore_load_table`); bit 1 is set to `2` when replacing an existing record and bypasses the load gate; bit 2 marks the entry selected for display after duplicate reduction. |
| `0x45` | `highscore_hardcore_marker` | Hardcore marker | Set to `0x75` (`'u'`) when `config_hardcore != 0`; checked in quest‑mode load to accept hardcore/normal records. |
| `0x46` | `highscore_active_record + 0x46` | Sentinel `0x7c` (`'|'`) | Initialized in `highscore_load_table` default‑record loop. |
| `0x47` | `highscore_active_record + 0x47` | Sentinel `0xff` | Initialized in `highscore_load_table` default‑record loop. |

`dateWeek` helper:

- Inputs: year, month, day (from `local_system_time` + `local_system_day`).
- Returns a week‑of‑year style checksum (1..53) used when `config_highscore_date_mode == 2`.
- Used during both record write (`highscore_write_record`) and validation (`highscore_load_table`).

High score validation (`highscore_load_table`):

- Records only proceed to date checks if `config_show_online_scores` is set, or the record flags
  have bit 0 clear, or bit 1 set.

- Mode 3: day + month + year must match (`local_system_day`, `local_system_time`).
- Mode 2: computed `dateWeek` must match the stored `dateWeek` byte (`highscore_record_date_checksum`), and year must match.

- Mode 1: month + year must match; other mode values skip the date check.

### Quest progression counters (high confidence)

- `quest_stage_major` (`0x00487004`) tracks the current quest episode/tier.
  - Evidence: increments after every 10 minor stages (`if 10 < quest_stage_minor` then
    `quest_stage_major++`, `quest_stage_minor -= 10`) during quest summary flow.

- Initialized to `1` in `gameplay_run_state_init` (`0x004120b0`) alongside high‑score state reset.
- `quest_stage_minor` (`0x00487008`) tracks the quest mission within the episode.
  - Evidence: used in quest string lookups and final‑mission checks (`major == 5 && minor == 10`).
- Incremented on quest results screen when the player chooses “Play Next”.
- Persistence: `quest_stage_major/minor` are runtime-only (reset on startup) and only used to
  select metadata and to build per‑quest high‑score filenames (`scores5\\quest*.hi`). Quest
  unlock progress is saved separately in `game_status_blob` via `quest_unlock_index` and
  `quest_unlock_index_full` (see below).

- `quest_play_counts` (`0x00485618`) increments on quest start (`game_state_id == 9`,
  `_config_game_mode == 3`) using the `[major * 10 + minor]` index.

- `quest_unlock_index` (`0x00487034`) stores the max quest unlock index (computed as
  `quest_stage_major * 10 + quest_stage_minor - 10`). It is updated on quest completion and
  persisted via `game_save_status`/`game_load_status`.

- `quest_unlock_index_full` (`0x00487038`) stores the full‑version unlock index (same
  calculation) and is only updated when `config_full_version` is set.

- `quest_meta_cursor` (`0x004c3650`) tracks the quest metadata entry last written by
  `quest_meta_init_entry` during `quest_database_init`.

- `quest_monster_vision_meta` (`0x004c3658`) points to a specific quest metadata entry
  used to force the Monster Vision perk in `perks_generate_choices`.

### Quest unlock table (perk/weapon rewards)

Quest metadata includes two reward fields:

- `quest_unlock_perk_id` (`0x00484750`, offset `+0x20`) — perk unlock for a quest (stride `0x2c`).
- `quest_unlock_weapon_id` (`0x00484754`, offset `+0x24`) — weapon unlock for a quest (stride `0x2c`).

Indexing: `quest_index = (quest_stage_major - 1) * 10 + (quest_stage_minor - 1)`.
Values below are initialized in `quest_database_init` (`0x00439230`).

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

### Quest metadata struct (0x2c bytes)

Quest metadata entries live at `quest_selected_meta` (`0x00484730`) with a stride of `0x2c`.
Fields below are high‑confidence; unknown offsets are omitted.

| Offset | Field | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x00` | `quest_meta_tier` | Tier/episode number | Set to `param_2` in `quest_meta_init_entry` (called by `quest_database_init`). |
| `0x04` | `quest_meta_index` | Quest number within tier | Set to `param_3` in `quest_meta_init_entry`. |
| `0x08` | `quest_meta_time_limit_ms` | Quest time limit in ms | Written per quest in `quest_database_init` (values like 120000, 300000, 480000). |
| `0x0c` | `quest_meta_name` | Quest display name pointer | Set to `strdup` of the quest title in `quest_meta_init_entry`. |
| `0x10` | `quest_meta_terrain_id` | Terrain texture index (layer A) | Used by `terrain_generate(desc)` via `*(int *)(desc + 0x10)` to index `terrain_texture_handles`. Set in `quest_meta_init_entry` (tiers 1–4: `2 * (tier - 1)`, tier 5: `quest_index & 3`). |
| `0x14` | `quest_meta_terrain_id_b` | Terrain texture index (layer B) | Used by `terrain_generate(desc)` via `*(int *)(desc + 0x14)`. Set in `quest_meta_init_entry` (tiers 1–4: odd id for quests 1–5, even id for quests 6–10; tier 5: `1`). |
| `0x18` | `quest_meta_terrain_id_c` | Terrain texture index (layer C) | Used by `terrain_generate(desc)` via `*(int *)(desc + 0x18)`. Set in `quest_meta_init_entry` (tiers 1–4: even id for quests 1–5, odd id for quests 6–10; tier 5: `3`). |
| `0x1c` | `quest_selected_builder` | Quest builder function pointer | Assigned after each `quest_meta_init_entry` call in `quest_database_init`. |
| `0x20` | `quest_unlock_perk_id` | Perk unlock id | Used by `perks_rebuild_available`. |
| `0x24` | `quest_unlock_weapon_id` | Weapon unlock id | Used by `weapon_refresh_available`. |
| `0x28` | `quest_start_weapon_id` | Starting weapon id | Used by `quest_start_selected` to equip both players. |

Record match + display selection:

- `highscore_record_equals` is the equality predicate used during save‑file replacement; it compares the
  player name plus metadata fields at offsets `0x20..0x34` (ints + a byte) and does not look
  at the flags byte.

- After loading/sorting, `highscore_load_table` sets flag bit 2 on the single best record per name
  (or all records when a name slot is selected), so the UI can filter displayed entries.

Init timing note:

- `qpc_timestamp_scratch` (`local_system_milliseconds`) is only used as a temporary QPC storage during
  early init (`QueryPerformanceCounter` in `game_startup_init`); it sits near the date scratch
  globals but is not part of the high‑score checksum path.

### Renderer backend selection (medium confidence)

- `0x004566d3` -> `D3DXCpuOptimizations`
  - Evidence: copies a function table, reads config `DisableD3DXPSGP`,
    and switches between multiple vtable variants (`renderer_patch_sse`, `renderer_patch_sse2`, `renderer_patch_3dnow`).

### Math helpers (high confidence)

- `0x00452ef0` -> `float_near_equal`
  - Evidence: returns 1 when `|a-b| < 1.1920929e-07` (FLT_EPSILON) and guards against NaNs.
### Texture loading helpers (high confidence)

- `0x0042a670` -> `texture_get_or_load`
  - Evidence: calls Grim `get_texture_handle` (0xc0); if missing, calls `load_texture` (0xb4),
    logs success/failure, and re-queries handle.

- `0x0042a700` -> `texture_get_or_load_alt`
  - Evidence: identical body to `texture_get_or_load`; primary callers pass `.jaz` assets.
### CRT errno accessors (high confidence)

- `0x00465d93` -> `crt_errno_ptr` (`_errno`-style accessor)
- `0x00465d9c` -> `crt_doserrno_ptr` (`__doserrno`-style accessor)
- `0x00465d20` -> `crt_dosmaperr` (Win32 error -> errno mapper)
- Evidence:
  - Both call `crt_get_thread_data()` and return pointer offsets (`+2`, `+3`).
  - `crt_dosmaperr` stores Win32 errors into `*crt_doserrno_ptr` and maps to `*crt_errno_ptr`
    via the error table at `crt_dosmaperr_table`.

  - File I/O wrappers set these directly on failure:
    - crt_commit (`0x004655bf`) (FlushFileBuffers) stores `GetLastError()` in `*crt_doserrno_ptr (`0x00465d9c`) and sets
      `*crt_errno_ptr (`0x00465d93`) = 9` (EBADF).
    - crt_write_nolock (`0x004656b7`) (WriteFile) and crt_read_nolock (`0x00466064`) (ReadFile) call `crt_dosmaperr` after
      `GetLastError()` for non-trivial errors.
    - crt_lseek_nolock (`0x0046645e`) (SetFilePointer) maps `GetLastError()` through `crt_dosmaperr`.
### CRT lock/unlock helpers (high confidence)

- `0x0046586b` -> `crt_lock`
  - Evidence: calls `InitializeCriticalSection`, `EnterCriticalSection`, and `__amsg_exit` in the
    lock path; invoked by `crt_exit_lock` and many CRT wrappers.

- `0x004658cc` -> `crt_unlock`
  - Evidence: calls `LeaveCriticalSection`; invoked by `crt_exit_unlock` and many CRT wrappers.
- `0x00463da5` -> `crt_lock_file`
  - Evidence: uses `crt_lock` for small-stream table entries or a `FILE`-embedded critical section.
- `0x00463df7` -> `crt_unlock_file`
  - Evidence: inverse of `crt_lock_file`, calls `crt_unlock` or `LeaveCriticalSection`.
- `0x0046acf8` -> `crt_lock_fh`
  - Evidence: initializes per-file handle critical sections and enters the lock.
- `0x0046ad57` -> `crt_unlock_fh`
  - Evidence: leaves the per-file handle critical section.
### CRT ctype helpers (high confidence)

- `0x00463c74` -> `crt_isctype`
  - Evidence: uses `PTR_DAT_0047b1c0` table for single-byte and falls back to
    `GetStringTypeA/W` for multi-byte characters.

- `0x00462fd0` -> `crt_isalpha`
  - Evidence: calls `crt_isctype` with mask `0x103` (alpha/upper/lower).
- `0x00462ffe` -> `crt_isspace`
  - Evidence: calls `crt_isctype` with mask `0x8` (space).
### CRT exit/stdio helpers (high confidence)

- `0x00460d08` -> `crt_onexit`
  - Evidence: takes exit callback, grows onexit table (`crt_onexit_table_begin`/`crt_onexit_table_end`) via
    crt_realloc (`0x004626aa`), stores pointer, and wraps with `crt_exit_lock`/`crt_exit_unlock`.

- `0x00460d86` -> `crt_atexit`
  - Evidence: calls `crt_onexit` and returns `0` on success, `-1` on failure.
- `0x00460dc7` -> `crt_free`
  - Evidence: thin wrapper around crt_free_base (`0x004625c1`) (CRT heap free).
- `0x004625c1` -> `crt_free_base`
  - Evidence: checks heap mode (`crt_heap_mode`), locks heap, frees via small-block helpers, and
    falls back to `HeapFree`.

- `0x00460e5d` -> `crt_fclose`
  - Evidence: if `_flag & 0x40` not set, locks stream, calls `__fclose_lk`, unlocks; otherwise
    clears `_flag`.

- `0x0046100e` -> `crt_fsopen`
  - Evidence: parses mode string, passes share flag to crt_sopen (`0x0046adbd`), populates `FILE` fields.
- `0x0046103f` -> `crt_fopen`
  - Evidence: forwards to `crt_fsopen` with share mode `0x40` (`_SH_DENYNO`).
- `0x004615ae` -> `crt_fwrite`
  - Evidence: wraps `crt_fwrite_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `0x004615dd` -> `crt_fwrite_nolock`
  - Evidence: writes buffers directly to file handle, uses `crt_flsbuf` for single-byte writes.
- `0x00461af7` -> `crt_fread`
  - Evidence: wraps `crt_fread_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `0x00461b26` -> `crt_fread_nolock`
  - Evidence: reads buffers directly from file handle and sets EOF/error flags.
- `0x00461d91` -> `crt_fseek`
  - Evidence: wraps `crt_fseek_nolock` with `crt_lock_file`/`crt_unlock_file`.
- `0x00461dbd` -> `crt_fseek_nolock`
  - Evidence: validates stream flags, flushes, and seeks via `crt_lseek`.
- `0x004616e7` -> `crt_sprintf`
  - Evidence: uses CRT output core crt_output (`0x00464380`) with an unbounded count (`0x7fffffff`) and
    terminates with `\0` on success.

- `0x00464268` -> `crt_flsbuf`
  - Evidence: flushes/allocates stream buffers, handles append seeks, and writes a single char;
    used by `crt_fwrite`/`crt_sprintf` when buffers underflow.

- `0x00464b1e` -> `crt_putc_nolock`
  - Evidence: decrements buffer count, calls `crt_flsbuf` on underflow, otherwise writes byte and
    updates the output counter (printf output helper).

- `0x00464b53` -> `crt_putc_repeat_nolock`
  - Evidence: loops count times calling `crt_putc_nolock`, used for space/zero padding in printf.
- `0x00464b84` -> `crt_putc_buffer_nolock`
  - Evidence: emits a string buffer via `crt_putc_nolock`, stops on error.
- `0x004663f9` -> `crt_lseek`
  - Evidence: validates handle, locks via `crt_lock_fh`, then calls `crt_lseek_nolock`.
- `0x0046645e` -> `crt_lseek_nolock`
  - Evidence: calls `SetFilePointer`, clears EOF flag on success, uses `crt_dosmaperr` on error.
- `0x0046dd16` -> `crt_chsize`
  - Evidence: uses `crt_lseek_nolock` to get size, truncates via `SetEndOfFile` or extends by
    writing zero-filled blocks, then restores the file offset.
### Grim/libpng helpers (high confidence)

- `d3dx_png_error` -> `0x1001e114`
  - Evidence: calls `png_ptr->error_fn` when set and then `longjmp(png_ptr, 1)`.
- `0x1001e132` -> `png_warning`
  - Evidence: calls `png_ptr->warning_fn` when set.
- `0x1002047c` -> `png_read_data`
  - Evidence: dispatches to `read_data_fn` or raises `d3dx_png_error` on NULL.
- `0x10020583` -> `png_reset_crc`
  - Evidence: seeds `png_ptr->crc` via `crc32(0, NULL, 0)`.
- `0x1002059b` -> `png_calculate_crc`
  - Evidence: updates CRC unless skip flags indicate the chunk is ignored.
- `d3dx_png_malloc` -> `0x10024741`
  - Evidence: malloc wrapper that calls `d3dx_png_error` on OOM.
- `0x10024777` -> `png_free`
  - Evidence: free wrapper with `(png_ptr, ptr)` signature.
- `png_destroy_struct` -> `0x10024734`
  - Evidence: simple free wrapper used for png buffers and the main png_ptr.
- `0x10024807` -> `png_crc_read`
  - Evidence: calls `png_read_data` then `png_calculate_crc` on the same buffer.
- `0x10024821` -> `png_crc_error`
  - Evidence: reads the stored CRC and compares it against `png_ptr->crc`.
- `0x1002487f` -> `png_check_chunk_name`
  - Evidence: validates 4-letter chunk type and errors on invalid characters.
- `0x100250d7` -> `png_crc_finish`
  - Evidence: consumes remaining chunk bytes, checks CRC, and raises error/warning.
### Grim pixel/format helpers (high confidence)

- `0x1000aaa6` -> `grim_format_info_lookup`
  - Evidence: walks the D3D format descriptor table (`grim_format_info_entries`) and returns the entry for the
    requested format id, falling back to a default descriptor.

- `0x100174a8` -> `grim_apply_color_key`
  - Evidence: iterates RGBA float pixels and zeroes those that match the current color key
    (`this+0x1c..0x28`), used after converting pixel buffers.
### Audio SFX helpers (medium confidence)

- `0x0043d120` -> `sfx_play`
  - Evidence: validates entry in `sfx_entry_table_state`, checks cooldown `sfx_cooldown_table`, sets sample rate
    via `bonus_reflex_boost_timer` into `sfx_rate_scale`, chooses a voice (sfx_entry_start_playback (`0x0043be60`)), calls vtable +0x40
    with pan 0, then sets volume with sfx_entry_set_volume (`0x0043bfa0`).

- `0x0043d260` -> `sfx_play_panned`
  - Evidence: same as `sfx_play`, but converts an FPU value to pan (`__ftol`), clamps to
    `[-10000, 10000]`, and passes pan to vtable +0x40.

- `0x0043d550` -> `sfx_mute_all`
  - Evidence: sets `sfx_mute_flags[sfx]=1` and recursively mutes all other unmuted ids using
    `sfx_is_unmuted`.

- `0x0043d7c0` -> `sfx_is_unmuted`
  - Evidence: returns true when `sfx_unmuted_flag` is set and the per-id mute flag is clear.
- `0x0043d460` -> `sfx_play_exclusive`
  - Evidence: mutes other ids, optionally selects a random variant, and ensures the chosen id is
    unmuted with its volume set in `sfx_volume_table`.

- `0x0043d5b0` -> `sfx_update_mute_fades`
  - Evidence: ramps per-id volume toward `config_music_volume` when unmuted and fades to zero when muted,
    stopping voices via sfx_entry_stop (`0x0043bf60`).

- `0x0043c9c0` -> `audio_init_music`
  - Evidence: loads `music.paq`, logs status, and registers track ids:
    - `music_track_intro_id` = `music_intro.ogg`
    - `music_track_shortie_monk_id` = `music_shortie_monk.ogg`
    - `music_track_crimson_theme_id` = `music_crimson_theme.ogg`
    - `music_track_crimsonquest_id` = `music_crimsonquest.ogg`
    - `music_track_extra_0`/`music_track_extra_1` = subsequent track ids (+1/+2).

- `0x0043caa0` -> `audio_init_sfx`
  - Evidence: loads `sfx.paq` and registers the sound effect ids.
  - See [Audio](../../re/static/reference/audio.md) for SFX IDs, usage hotspots, and data labels.
- `0x0043c740` -> `sfx_load_sample`
  - Evidence: allocates a free slot in `sfx_entry_table_state`, loads `.ogg`/`.wav` data, and returns the
    sample id.

- `0x0043c700` -> `sfx_release_sample`
  - Evidence: releases an sfx entry by id via `sfx_release_entry`.
- `0x0043c090` -> `sfx_release_entry`
  - Evidence: frees sample buffers/voices and clears entry state.
- `0x0043c8d0` -> `music_load_track`
  - Evidence: allocates a free track in `music_entry_table`, loads the tune, and returns the id.
- `0x0043c960` -> `music_queue_track`
  - Evidence: appends a track id into `music_playlist` playlist array.
- `0x0043c980` -> `music_release_track`
  - Evidence: releases a music entry by id via `sfx_release_entry`.
- `0x0043cf90` -> `sfx_system_init`
  - Evidence: initializes the Grim SFX system and clears `sfx_cooldown_table`/`sfx_voice_table` tables.
- `0x0043d070` -> `sfx_release_all`
  - Evidence: iterates `sfx_entry_table` entries and calls `sfx_release_entry`.
- `0x0043d0d0` -> `music_release_all`
  - Evidence: iterates `music_entry_table` entries and calls `sfx_release_entry`.
- `0x0043d110` -> `audio_shutdown_all`
  - Evidence: calls `sfx_release_all`, `music_release_all`, and the audio backend shutdown helper.
### Global var access (medium confidence)

- `0x0042fcf0` -> `perk_count_get`
  - Evidence: returns `(&player_perk_counts)[perk_id]` (`0x00490968`) directly; used to track perk picks and gating.
### Save/load helpers (medium confidence)

- `0x0042a980` -> `reg_read_dword_default`
  - Evidence: wraps `RegQueryValueExA` for `REG_DWORD` and writes fallback on failure.
- `0x0042a9c0` -> `reg_write_dword`
  - Evidence: wraps `RegSetValueExA` with `REG_DWORD`.
- `0x00412a10` -> `play_time_load`
  - Evidence: reads the `sequence` registry value and updates `play_time_ms`.
- `0x00412a80` -> `game_save_status`
  - Evidence: writes registry values (`sequence`, `dataPathId`, `transferFailed`) and saves a
    `game.cfg`-style status file; logs `GAME_SaveStatus OK/FAILED`.

- `0x00412c10` -> `game_load_status`
  - Evidence: loads the status file, validates checksum/size, and regenerates it on failure;
    logs `GAME_LoadStatus ...`.
### Effect spawn helper (medium confidence)

- `0x0042de80` -> `effect_init_entry`
  - Evidence: zeros/sets default fields on a single entry and initializes per-quad color slots.
- `0x0042df10` -> `effect_defaults_reset`
  - Evidence: resets global template values (`DAT_004ab1*`) used by effect spawners.
- `0x0042e080` -> `effect_free`
  - Evidence: pushes the entry back onto `effect_free_list_head` free list and clears live flag.
- `0x0042e0a0` -> `effect_select_texture`
  - Evidence: maps effect id through `effect_id_table` (`size_code`, `frame`) and calls Grim vtable +0x104 with
    texture page bitmasks.

- `0x0042e120` -> `effect_spawn`
  - Evidence: pops an entry from the pool `effect_free_list_head`, copies template `effect_template_vel_x`,
    writes position from `param_2`, tags the effect id, and assigns quad UVs from atlas tables
    `effect_id_table` (`size_code`, `frame`) plus arrays `effect_uv16`, `effect_uv8`, `effect_uv4`, `effect_uv2`.

- `0x0042e710` -> `effects_update`
  - Evidence: iterates pool entries, advances timers/positions with `frame_dt`, and calls
    `effect_free` when expired.

- `0x0042e820` -> `effects_render`
  - Evidence: sets render state, iterates effects, computes rotated quad vertices, and submits
    via Grim vtable +0x134.

- `0x00427700` -> `fx_queue_add_random`
  - Evidence: chooses a random effect id `3..7`, random grayscale color/size, and pushes an entry
    via `fx_queue_add`; uses `fx_queue_random_color_*` scratch globals.

- `0x0042ec80` -> `effect_spawn_freeze_shard`
  - Evidence: configures the effect template and spawns a random `8..10` variant with velocity
    based on `(angle + pi)`; used by freeze/shatter logic.

- `0x0042ee00` -> `effect_spawn_freeze_shatter`
  - Evidence: spawns four `effect_id 0xe` bursts at 90° offsets plus extra `effect_spawn_freeze_shard`
    calls.

- `0x0042f080` -> `effect_spawn_shrinkifier_hit`
  - Evidence: called from `projectile_update` on `PROJECTILE_TYPE_SHRINKIFIER`; spawns one
    `effect_id 1` pulse plus detail-scaled `effect_id 0` debris.

- `0x0042f270` -> `effect_spawn_ion_hit_core`
  - Evidence: called on Ion projectile impacts (`PROJECTILE_TYPE_ION_MINIGUN/_RIFLE/_CANNON`);
    writes core pulse template fields and spawns `effect_id 1`.

- `0x0042f540` -> `effect_spawn_ion_hit_sparks`
  - Evidence: paired with `effect_spawn_ion_hit_core` on Ion impacts; emits detail-scaled
    `effect_id 0` spark particles around the hit point.

- `0x0042f330` -> `effect_spawn_plasma_hit_core`
  - Evidence: called on `PROJECTILE_TYPE_PLASMA_CANNON` impacts; emits two core pulses
    (`scale_step` 1.5 then 1.0) with explicit lifetime.

- `0x0042f3f0` -> `effect_spawn_splitter_hit_burst`
  - Evidence: called on `PROJECTILE_TYPE_SPLITTER_GUN` impacts before spawning split child
    projectiles; the exact-matched body emits radial burst particles in a configurable
    radius/count and preserves a double-precision distance across both x87 projections.
### Perk database + selection (medium confidence)

- `0x0042fd90` -> `perks_init_database`
  - Evidence: assigns perk id constants (`DAT_004c2b**`/`DAT_004c2c**`) and fills the perk
    name/description tables via `wrap_text_to_width_alloc`.

  - For extracted id/name metadata and runtime references, see
    `src/crimson/perks/ids.py` and [Perk runtime reference](perks-runtime-reference.md).
- `0x0042fb10` -> `perk_can_offer`
  - Evidence: checks mode gates and perk flags, then returns a nonzero byte if the perk is eligible.
- `0x0042fbd0` -> `perk_select_random`
  - Evidence: randomizes an id from the perk table, calls `perk_can_offer`, and logs a failure when
    selection runs too long.

- `0x0042fc30` -> `perks_rebuild_available`
  - Evidence: resets `perk_available_table` flags and re-enables base/unlocked perks.
  - Table layout (stride `0x14`): `name` @ `perk_meta_table`, `desc` @ `perk_desc_table`,
    `flags` @ `perk_flags_table`, `available` @ `perk_available_table`, `prereq` @ `perk_prereq_table`.

  - Flag bits (inferred):
    - `0x1` allows perks when `config_game_mode == GAME_MODE_QUEST`.
    - `0x2` allows perks when `config_player_count == 2` (two-player mode).
    - `0x4` marks stackable perks (random selection accepts them even if already taken).

  - Prereq field is checked via `perk_count_get` and gates perks like Toxic Avenger (requires
    Veins of Poison), Ninja (requires Dodger), Perk Master (requires Perk Expert), and
    Greater Regeneration (requires Regeneration).

- `0x004055e0` -> `perk_apply`
  - Evidence: called after selecting a perk in the UI, increments `perk_count_get` table, and
    executes the perk-specific effects (exp, health, weapon changes, perk spawns).

- `0x004045a0` -> `perks_generate_choices`
  - Evidence: fills `perk_choice_ids` with randomly selected perks using `perk_select_random`,
    enforces uniqueness, and applies special-case handling for mode `8` (fixed perk list).

- Perk prompt UI gates (high confidence):
  - `perk_prompt_timer` (`0x0048f524`) ramps 0..200 while perks are pending and feeds the
    prompt alpha plus the transform matrix (`perk_prompt_transform_*` at `perk_prompt_transform_cos..perk_prompt_transform_cos_2`).

  - `ui_perk_prompt_element` (`0x0048f20c`) is the prompt's root UI element; `perk_prompt_update_and_render`
    forces its active flag and renders it each frame while `ui_element_render` skips focus/click handling for it.
  - `ui_perk_prompt_on_activate` (`0x0048f240`) is the prompt callback slot seeded to `ui_callback_noop`
    during menu layout init.

  - `perk_prompt_origin_x/y` (`0x0048f224`/`perk_prompt_origin_y`) anchor the prompt bounds for hover/click
    tests; `perk_prompt_bounds_min_*` (`perk_prompt_bounds_min_x`/`perk_prompt_bounds_min_y`) and
    `perk_prompt_bounds_max_*` (`perk_prompt_bounds_max_x`/`perk_prompt_bounds_max_y`) define the relative rectangle.

  - `perk_prompt_hover_active` (`0x0048f500`) flips when the cursor enters/leaves the perk prompt
    bounds and gates whether the click target is active.

  - `perk_prompt_pulse` (`0x0048f504`) ramps `0..1000` (decays when not hovered, accelerates when
    hovered) and is forced to `1000` when the perk pick key is pressed.

  - `perk_choices_dirty` (`0x00486fb0`) is set after perk selection and on reset, then cleared the
    first time `perks_generate_choices` runs before switching to state `6`.
### Tutorial prompt (high confidence)

- `0x00408530` -> `tutorial_prompt_dialog`
  - Evidence: renders the tutorial message panel and uses button UI for "Repeat tutorial",
    "Play a game", and "Skip tutorial"; click handlers restart the tutorial (clears perk count
    table `player_perk_counts` (`0x00490968`) and resets timers) or exit to game (sets `game_state_pending` (`0x00487274`), flushes input,
    and resets `tutorial_stage_transition_timer`).

  - Signature (matched):
    `void tutorial_prompt_dialog(char *text, float alpha, char tutorial_complete)`
  - `alpha` comes from `tutorial_timeline_update` (0..1), controls the prompt fade, and scales
    the button visuals. The main prompt passes `tutorial_stage_index == 8` as the third argument;
    transient tutorial hints pass zero. The third byte selects Play/Repeat versus Skip.
### Tutorial timeline (medium confidence)

- `0x00408990` -> `tutorial_timeline_update`
  - Evidence: loads the tutorial string table, advances `tutorial_stage_index` stage index when
    `tutorial_stage_transition_timer` counts up from `-1000`, and renders each stage via `tutorial_prompt_dialog`.

  - Timers:
    - `tutorial_stage_timer` accumulates per-frame time (`frame_dt_ms`), gates stage 0 auto-advance
      and is used to fade stage 5 after 5 seconds.
    - `tutorial_stage_transition_timer` is a stage transition/fade timer: it counts up from `-1000` toward `-1`
      to advance the stage, then counts up from `0` to `1000` before snapping back to `-1`.
      The absolute value is scaled by `0.001` to derive the prompt alpha.

  - Stage transitions observed:
    - Stage 0: after `tutorial_stage_timer > 6000` and `tutorial_stage_transition_timer == -1`, clears `tutorial_repeat_spawn_count`,
      resets `tutorial_hint_index`, and sets `tutorial_stage_transition_timer = -1000`.
    - Stage 1: waits for any movement key active (`grim_is_key_active` via vtable +0x80),
      then spawns bonus pickups (effect_spawn_burst (`0x0042ef60`)) and sets `tutorial_stage_transition_timer = -1000`.
    - Stage 2: waits until all 16 bonus slots in `bonus_pool` (`0x00482948`) clear, then sets
      `tutorial_stage_transition_timer = -1000`.
    - Stage 3: waits for input in `player_fire_key` (`0x00490bec`) key slots, spawns arrow markers
      (creature_spawn_template (`0x00430af0`)), then sets `tutorial_stage_transition_timer = -1000`.
    - Stage 4: waits for `creatures_none_active()`, spawns arrow markers, sets `tutorial_stage_timer = 1000`,
      then sets `tutorial_stage_transition_timer = -1000`.
    - Stage 5: increments `tutorial_repeat_spawn_count` on repeated `creatures_none_active()` events, spawns markers/bonuses,
      and after 8 iterations sets `player_experience` (`0x0049095c`) to 3000 and `tutorial_stage_transition_timer = -1000`.
    - Stage 6: waits for `perk_pending_count` (`0x00486fac`) < 1, spawns markers, then sets `tutorial_stage_transition_timer = -1000`.

  - Stage 7: waits for `creatures_none_active()` with no active bonus slots, then sets `tutorial_stage_transition_timer = -1000`.
  - Stage text table (array indexed by `tutorial_stage_index`, base is `local_38`):

    | Stage | Text |
    | --- | --- |
    | 0 | This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby! |
    | 1 | Reflex Boost powerup slows down time giving you a chance to react better |
    | 2 | (empty string, `tutorial_empty_string`) |
    | 3 | (empty string, `tutorial_empty_string`) |
    | 4 | In this tutorial you'll learn how to play Crimsonland |
    | 5 | First learn to move by pushing the arrow keys. |
    | 6 | Now pick up the bonuses by walking over them |
    | 7 | Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot. |
    | 8 | Now, move the mouse to aim at the monsters |

  - Secondary hint overlay:
    - `tutorial_hint_index` increments when the current bonus object (`tutorial_hint_bonus_ptr`) flips inactive with flag `0x400`,
      and `tutorial_hint_alpha` ramps the hint alpha (up/down at 3x delta, clamped 0..1000).
    - The hint text is fetched from the same stack string block (`afStack_5c[tutorial_hint_index + 2]`);
      entries that point to `tutorial_empty_string` are skipped because the string starts with `0xa7`
      (`-0x59`), matching the guard byte check.

  - Additional strings in the same stack block include perk tutorial lines
    ("It will help you to move and shoot...", Perks intro, Perks description, "Great! Now you are ready to start"),
    plus speed/weapon/x2 powerup blurbs (`local_44/local_40/local_3c`).

  - Helper: `0x00428210` -> `creatures_none_active`
    - Evidence: scans the creature table at `creature_pool` for any active entries, sets `creatures_any_active_flag`,
      and returns low byte `1` only when the table is empty.

  - Stage index wraps to 0 when `tutorial_stage_index` reaches 9; counters are initialized in gameplay_reset_state (`0x00412dc0`)
    (`tutorial_stage_index = -1`, `tutorial_stage_transition_timer = -1000`) and reset by `tutorial_prompt_dialog`.

### UI button helpers (medium confidence)

- `0x004034a0` -> `ui_mouse_inside_rect`
  - Evidence: checks mouse coordinates (`ui_mouse_x`/`ui_mouse_y`) against `xy + (w, h)` and
    returns 1 when inside and `ui_mouse_blocked` is clear.

- `0x0043d830` -> `ui_focus_update`
  - Evidence: tracks a rolling list of focus candidates in `ui_focus_candidates`, responds to key input
    to move focus, and returns nonzero when the provided id matches the focused entry.

- `0x0043d940` -> `ui_focus_draw`
  - Evidence: draws a small highlight quad near the focused item location using the UI renderer.
- `0x0043e830` -> `ui_button_update`
  - Evidence: draws the small/medium button textures, updates hover/press timers using
    `ui_mouse_inside_rect`, and returns nonzero when the button is activated.

Button struct (size `0x18`, used by `demo_trial_purchase_button` / `tutorial_prompt_repeat_button` / `tutorial_prompt_primary_button`):

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

- `0x0043a790` -> `quest_start_selected`
  - Evidence: resets quest state, selects quest metadata at `quest_selected_meta`, queues perk state, and
    runs the quest builder at `quest_selected_builder` (or `quest_build_fallback` when null).

- `0x00434250` -> `quest_spawn_timeline_update`
  - Evidence: walks the quest spawn table (`quest_spawn_table`, count `quest_spawn_count`), checks trigger
    time vs `quest_spawn_timeline`, and spawns each entry with creature_spawn_template (`0x00430af0`) using a 0x28 spacing offset.

- `0x00434220` -> `quest_spawn_table_empty`
  - Evidence: returns 1 when all spawn entries have been cleared (no pending spawns).
- `0x004343e0` -> `quest_build_fallback`
  - Evidence: logs a fallback warning and writes two default entries (spawn id `0x40`, counts 10/0x14,
    trigger times 500/5000).

- `0x004343c0` -> `quest_database_advance_slot`
  - Evidence: increments quest index, wraps every 10, and advances the tier.
- `0x00439230` -> `quest_database_init`
  - Evidence: populates the quest metadata table (`quest_selected_meta`) with names, durations, and builder
    function pointers.
### Creature table (partial)

- `0x00428140` -> `creature_alloc_slot`
  - Evidence: scans `creature_pool` in `0x98`-byte strides for `active == 0`, clears flags/seed fields,
    increments `creature_spawned_count`, and returns the slot index (or `0x180` on failure).

- Layout (entry size `0x98`, base `creature_pool`, pool size `0x180`):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | active (byte) | checked for zero in most creature loops; set to `1` on spawn, cleared on death. |
  | 0x14 | pos_x | set in creature_spawn (`0x00428240`), used in distance checks and targeting. |
  | 0x18 | pos_y | set in creature_spawn (`0x00428240`), used in distance checks and targeting. |
  | 0x1c | vel_x | computed from heading/speed and passed to vec2_add_inplace (`0x0041e400`) for movement. |
  | 0x20 | vel_y | computed from heading/speed and passed to vec2_add_inplace (`0x0041e400`) for movement. |
  | 0x24 | health | checked as `> 0` for valid targets and in perk kill logic (`<= 500`). |
  | 0x28 | max_health | set from `health` on spawn; used when splitting (clone health is `max_health * 0.25`). |
  | 0x2c | heading (radians) | set from `rand % 0x13a * 0.01` on spawn; eased toward desired heading via angle_approach (`0x0041f430`). |
  | 0x30 | desired heading | computed from target position and stored each frame. |
  | 0x34 | collision radius (?) | used in collision tests in creatures_apply_radius_damage (`0x00420600`). |
  | 0x38 | hit flash timer | decremented each frame; set by creature_apply_damage (`0x004207c0`) on damage. |
  | 0x50 | target_x | target position derived from player/formation/linked enemy. |
  | 0x54 | target_y | target position derived from player/formation/linked enemy. |
  | 0x60 | attack cooldown | decremented each frame; gates projectile spawns for some flags. |
  | 0x6c | type id (spawn param) | written from `param_3` in creature_spawn (`0x00428240`). |
  | 0x70 | target player index | toggled between players based on distance; indexes player pos arrays. |
  | 0x78 | link index / state timer | used as linked creature index in several AI modes; also incremented as a timer when `0x80` flag is set. |
  | 0x8c | flags | bit tests `0x4/0x8/0x400` guard behaviors in update/split logic. |
  | 0x90 | AI mode | selects movement pattern (cases 0/1/3/4/5/6/7/8 in update loop). |
  | 0x94 | anim phase | accumulates and wraps (31/15) to drive sprite animation timing. |

See [Creature pool struct](../../creatures/struct.md) for the expanded field map and cross-links.

- Creature-type table carving updates:
  - `creature_type_table` is now typed as `creature_type_table_t` (6 entries, stride `0x44`).
  - Entry bases are labeled as `creature_type_lizard`, `creature_type_alien`,
    `creature_type_spider_sp1`, `creature_type_spider_sp2`, and `creature_type_trooper`.
  - Evidence: contiguous `gameplay_reset_state` writes at `+0x44` steps from `0x00482728`.

### Projectile pool (partial)

- `0x00420440` -> `projectile_spawn`
  - Evidence: allocates a slot in `projectile_pool` (`0x004926b8`), initializes angle/pos/type/owner,
    and callers store the return index.

- `0x00420b90` -> `projectile_update`
  - Evidence: iterates `0x60` projectile entries, advances movement, checks collisions against
    creatures/players, spawns hit effects, and clears expired entries.

- `0x004205d0` -> `projectile_reset_pools`
  - Evidence: clears `projectile_pool` (`0x004926b8`, `0x40` stride) and
    `particle_pool` (`0x00493eb8`, `0x38` stride).

- `0x00420600` -> `creatures_apply_radius_damage`
  - Evidence: loops active creatures with `lifecycle_stage > 5.0`, checks distance vs radius + size, and calls creature_apply_damage (`0x004207c0`) (no health gate).
- `0x004206a0` -> `creature_find_in_radius`
  - Evidence: returns the first creature index within `radius` starting at `start_index` (or `-1`).
- `0x00420730` -> `player_find_in_radius`
  - Evidence: scans the player health table (`player_health`, `0x004908d4`), skipping the owner id,
    and returns the first player within range.

- Layout (entry size `0x40`, base `projectile_pool` (`0x004926b8`), pool size `0x60`):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | active (byte) | Set on spawn; cleared when lifetime expires. |
  | 0x08 | pos_x | Spawn position and update movement use. |
  | 0x0c | pos_y | Spawn position and update movement use. |
  | 0x20 | type id | Spawn parameter, drives branch logic. |
  | 0x24 | life timer | Decrements by `frame_dt`, clearing when <= 0. |
  | 0x34 | hit radius | Used for creature collision checks. |
  | 0x3c | owner id | Used to skip the shooter in hit tests. |

See [Projectile struct](../../structs/projectile.md) for the expanded field map and notes.
### Effects pools (medium confidence)

- `0x00420130` -> `fx_spawn_particle`
  - Evidence: allocates a `0x38`-byte entry in `particle_pool` (`0x00493eb8`), sets position, angle,
    and velocity (speed ~90), and returns the slot index.

- `0x00420240` -> `fx_spawn_particle_slow`
  - Evidence: same pool as `fx_spawn_particle`, but speed ~30 and sets style id `8`.
- `0x00420360` -> `fx_spawn_secondary_projectile`
  - Evidence: allocates a `0x2c`-byte entry in `secondary_projectile_pool` (`0x00495ad8`) with type
    id, velocity, and optional nearest-creature target when `type_id == 2`.

- `0x0041fbb0` -> `fx_spawn_sprite`
  - Evidence: allocates a `0x2c`-byte entry in `sprite_effect_pool` (`0x00496820`) with position,
    velocity, tint, and a scalar parameter used by the renderer.

- Layouts and fields are tracked in [Effects pools](../../structs/effects.md).
### Bonus / pickup pool (medium confidence)

- `0x0041f580` -> `bonus_alloc_slot`
  - Evidence: scans `bonus_pool` (`0x00482948`) in `0x1c`-byte strides and returns the first entry
    with type `0` (or the sentinel `bonus_pool_sentinel` / `0x00490630` when full).

- `0x0041f5b0` -> `bonus_spawn_at`
  - Evidence: clamps position to arena bounds, writes entry fields (type, lifetime, size, position,
    duration override), and spawns a pickup effect via effect_spawn (`0x0042e120`).

- `0x0040a320` -> `bonus_update`
  - Evidence: decrements bonus lifetimes, checks player proximity, calls `bonus_apply` on pickup,
    and clears entries when `time_left` expires.

- `0x004295f0` -> `bonus_render`
  - Evidence: renders bonus icons from `bonus_texture`, scales/fades by timer, and draws label text
    via `bonus_label_for_entry` when players are nearby.

- `0x00429580` -> `bonus_label_for_entry`
  - Evidence: returns a formatted label string for bonus entries (weapon/score cases use a formatter).
- `0x00409890` -> `bonus_apply`
  - Evidence: applies bonus effects based on entry type (`param_2[0]`), spawns effects via
    effect_spawn (`0x0042e120`), and plays bonus SFX (sfx_play_panned (`0x0043d260`)).

- See [Bonus ID map](../../re/static/reference/bonus-id-map.md) for the id-to-name table and default amounts.
- Layout (entry size `0x1c`, base `bonus_pool` (`0x00482948`), 16 entries):

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

- `config_game_mode` (`0x00480360`) holds the current game mode (typed as `game_mode_id_t`). See [Game mode map](../../re/static/modes/game-mode-map.md) for the observed
  values and evidence.

- `0x00412960` -> `game_mode_label`
  - Evidence: returns a label string based on `config_game_mode` (Survival, Quests, Typ-o-Shooter, etc.).
### Survival mode (partial)

- `0x00407cd0` -> `survival_update`
  - Evidence: runs only when `config_game_mode == GAME_MODE_SURVIVAL`, advances scripted spawn stages, and calls
    `survival_spawn_creature` when the spawn timer elapses.

- `0x00407510` -> `survival_spawn_creature`
  - Evidence: allocates a creature slot, assigns spawn position, and selects a type based on
    `player_experience` thresholds before seeding speed/health and flags.

- Key state:
  - `survival_spawn_cooldown` acts as the spawn cooldown accumulator; it is decremented by
    `player_count * frame_dt`, and when it drops below zero a burst of spawns is scheduled.

  - `survival_elapsed_ms` is the survival elapsed timer (ms). It is incremented each frame and is used
    to scale spawn cadence and HUD timers.

  - `survival_spawn_stage` is the scripted spawn stage index (0..10) that gates bonus/marker spawns by
    `player_level` milestones.

  - `player_experience` (`0x0049095c`) is the survival XP/progression score (HUD label `Xp`, displayed via the
    smoothed `survival_xp_smoothed`) and is used for creature type/health scaling in `survival_spawn_creature`.

  - `player_level` (`0x00490964`) is the survival level/milestone counter (drawn as `%d` in the HUD) that gates
    scripted spawns in `survival_update`; it increments when `player_experience` surpasses a periodic
    threshold.

  - The HUD shows `Xp`, the smoothed XP value, and a `Progress` label with a bar fed by
    `player_experience`/`player_level` (`0x0049095c`/`0x00490964`) and a 1-second timer derived from `crt_ci_pow()`.

### Gameplay timer/guard globals (high confidence)

- Labeled `player_alt_weapon_swap_cooldown_ms` (`0x0048719c`):
  - Evidence: `player_update` decrements it by `frame_dt_ms`, sets it to `200` after a successful
    alternate-weapon swap, and clears it when reload key is released.

- Labeled `perk_jinxed_proc_timer_s` (`0x004aaf1c`):
  - Evidence: `perks_update_effects` decrements it each frame and, when elapsed, applies the
    Jinxed self-damage roll then reseeds it to `2.0 + rand(0..1.9)`.

- Labeled `survival_reward_weapon_guard_id` (`0x00486fb8`):
  - Evidence: `survival_update` writes `0x18`/`0x19` on Survival handouts, and
    `gameplay_render_world` uses it to revoke temporary reward weapons when the guard mismatches.

- Labeled `quest_spawn_stall_timer_ms` (`0x004c3654`):
  - Evidence: `quest_spawn_timeline_update` increments it while creatures are active and allows a
    fallback trigger after `3000ms` to avoid stalled spawn progression.

- Labeled `perk_lean_mean_exp_tick_timer_s` (`0x004808a4`):
  - Evidence: `perks_update_effects` decrements it by `frame_dt`, and on expiry it resets to `0.25`
    and applies Lean Mean Exp Machine XP ticks.

- Labeled `perk_doctor_target_creature_id` (`0x00487268`):
  - Evidence: set from `creature_find_in_radius` while Doctor is active; `ui_render_aim_indicators`
    reads it to draw the target-health HUD overlay (`-1` means inactive).

- Labeled `quest_stage_banner_timer_ms` (`0x00487244`):
  - Evidence: reset in `quest_start_selected`, incremented in `quest_mode_update`, and consumed by
    quest HUD render for staged title-card fade in/out windows (`0..2000ms`).

- Labeled demo/keybind overlay timers:
  - `demo_trial_overlay_active` (`0x00480850`) and
    `demo_trial_overlay_alpha_ms` (`0x00480898`)
  - `pause_keybind_help_alpha_ms` (`0x00487284`)
  - Evidence: gameplay render path toggles/ramps these values (all clamped to `0..1000`) before
    calling `demo_trial_overlay_render` / `ui_render_keybind_help`.

- Labeled `time_played_ms` (`0x0048718c`):
  - Evidence: loaded from registry key `timePlayed` at startup, incremented during active gameplay
    frames, and written back on shutdown.

- Labeled quest-results staged reveal globals:
  - `quest_results_unlock_weapon_id` / `quest_results_unlock_perk_id`
    (`quest_results_unlock_weapon_id` / `quest_results_unlock_perk_id`)
  - `quest_results_final_time_ms` (`0x0048270c`)
  - `quest_results_reveal_base_time_ms` (`0x00482710`)
  - `quest_results_reveal_health_bonus_ms` (`0x00482714`)
  - `quest_results_reveal_perk_bonus_s` (`0x00482718`)
  - `quest_results_reveal_total_time_ms` (`0x00482720`)
  - `quest_results_reveal_step_timer_ms` (`0x00482724`)
  - `quest_results_health_bonus_ms` (`0x00482600`)
  - Evidence: `quest_results_screen_update` seeds these from quest metadata/timers and animates the
    Base Time / Health Bonus / Unpicked Perk Bonus rows in discrete timed steps.

- Labeled `perk_id_max` (`0x004c2c38`):
  - Evidence: initialized to `0x39` in `perks_init_database` and used as the upper bound (+1) in
    `perk_select_random` / `perks_rebuild_available`.

- Labeled bonus metadata aliases used by `bonus_apply` HUD slot wiring:
  - Label/icon pairs: `bonus_label_reflex_boost`/`bonus_icon_reflex_boost`,
    `bonus_label_weapon_power_up`/`bonus_icon_weapon_power_up`,
    `bonus_label_speed`/`bonus_icon_speed`,
    `bonus_label_freeze`/`bonus_icon_freeze`,
    `bonus_label_shield`/`bonus_icon_shield`,
    `bonus_label_fire_bullets`/`bonus_icon_fire_bullets`,
    `bonus_label_energizer`/`bonus_icon_energizer`,
    `bonus_label_double_experience`/`bonus_icon_double_experience`.
  - `bonus_label_points` and `bonus_label_format_buffer` now cover the formatted
    `bonus_label_for_entry` text path.

- Labeled perk trigger interval globals:
  - `perk_man_bomb_trigger_interval_s` (`0x00473310`)
  - `perk_fire_cough_trigger_interval_s` (`0x00473314`)
  - `perk_hot_tempered_trigger_interval_s` (`0x00473318`)
  - Evidence: all three act as threshold/reseed intervals against their respective per-player perk timers.

### UI template/audio init helpers (high confidence)

- `0x00417690` -> `ui_menu_template_pool_init`
  - Evidence: pre-initializes contiguous UI template blocks (`0x0048f808..0x004902e4`) and
    seeds each block's mode sentinel (`= 4`) before `ui_menu_layout_init` copies from those templates.
  - Mapping updates: `ui_template_pool_block_00..02`, `ui_sign_crimson_template`,
    and `ui_menu_item_subtemplate_block_01..06` (+ corresponding `_mode` sentinels).
  - Field-level carve: `ui_menu_item_subtemplate_block_01..06` now use
    `ui_menu_item_subtemplate_block_t` (`8 * 0x1c` slots + `texture_handle` + `quad_mode`),
    with explicit `*_texture_handle` labels at `+0xe0` and a recovered
    `ui_menu_item_subtemplate_block_01_mode` label at `0x0048fe5c`.
  - Offset-loop evidence (`ui_menu_assets_init`):
    - `slot_i.x -= 84.0` over all 8 slots in block 01 (`0x0048fd78 + i*0x1c`).
    - `slot_02.y/slot_03.y -= 116.0`, `slot_04.y..slot_07.y += 124.0` in block 01.
    - block 02 (`0x0048fe60`) is cloned from block 01 and then `slot_04.y..slot_07.y -= 100.0`
      (`0x0048fed4`, `0x0048fef0`, `0x0048ff0c`, `0x0048ff28`).

- `0x00417a90` -> `ui_template_slot_ctor_noop`
  - Evidence: identity callback used repeatedly by `ui_menu_template_pool_init` while iterating slot arrays.

- `0x004010f0` -> `invoke_callback_n`
  - Evidence: helper repeatedly invokes a callback pointer `count` times; used by `ui_menu_template_pool_init`
    for late template-slot batches.

- `0x00417aa0` -> `ui_template_block_set_mode4`
  - Evidence: writes mode sentinel value `4` at `block+0xe4`.

- `0x00417ab0` -> `ui_template_triplet_reset_and_seed_modes`
  - Evidence: zeroes head flags and seeds three mode sentinel dwords at `+0x120`, `+0x208`, and `+0x2f0`.

- `console_register_global_destructor_atexit` -> `console_register_clear_log_atexit`
  - Evidence: single-purpose `crt_atexit` wrapper that registers the local cleanup thunk at `LAB_00401190`.

- `0x0043b810` -> `sfx_entry_reset_runtime_state`
  - Evidence: clears runtime fields in the `sfx_entry_*` layout (`+0x74/+0x78/+0x7c/+0x80` stream offsets,
    voice pointer slab at `+0x24..+0x60`, and default scalar at `+0x20`), matching the same fields used by
    `sfx_entry_seek`, `sfx_release_entry`, and `music_stream_update`.

### HUD/menu texture handle globals (high confidence)

- Labeled `ui_cursor_texture..ui_text_well_done_texture` as UI/HUD texture handles loaded by `load_textures_step` and reused by
  `ui_menu_layout_init`/HUD render paths.
  - Examples: `ui_cursor_texture`, `ui_aim_texture`, `ui_hud_panel_texture`, `ui_clock_pointer_texture`,
    `ui_item_texts_texture`, `ui_text_pick_perk_texture`.
  - Evidence: direct `texture_get_or_load(_alt)` assignments in `load_textures_step` plus `grim_bind_texture`
    callsites in overlay/menu rendering.

- Labeled terrain stage-5 texture slots `0x0048f54c..terrain_texture_layer_7` as `terrain_texture_layer_1..7`.
  - Evidence: fixed assignment order in `load_textures_step` (quest base/detail sheets, or fallback set when
    `terrain_texture_failed != 0`) and indexed consumption via `terrain_texture_handles[...]` in terrain render paths.

### UI element pointer-table slots (high confidence)

- Labeled `ui_element_table_slot_01_main_menu_aux..ui_element_table_slot_39` as typed `ui_element_t *` table slots
  (`ui_element_table_slot_*`) to remove raw pointer-soup globals around `ui_menu_layout_init`.
  - Evidence: the contiguous 41-entry pointer table seeded in `ui_menu_layout_init` and iterated in reverse by
    `ui_elements_update_and_render` (`0x0048f168 .. 0x0048f208`).
- Corrected `ui_menu_layout_a` / `ui_menu_layout_b` / `ui_menu_layout_c` type from `char *` to `ui_element_t *`
  (they are table slot anchors used for per-element quad/offset scaling).
- Labeled and typed backing storage blocks for those slots (`0x004875a8..0x0048ee50`) as `ui_element_slot_*`
  (`ui_element_t`), so table assignments no longer point to anonymous `DAT_*` elements.
- Labeled adjacent UI globals:
  - `ui_menu_layout_init_latch` (`0x0048f164`) set to `1` at the end of `ui_menu_layout_init`.
  - `ui_perk_prompt_element` (`0x0048f20c`) typed as `ui_element_t`.
  - `ui_perk_prompt_on_activate` (`0x0048f240`) typed as `_func_1 *` callback slot.
  - `ui_perk_prompt_levelup_element` (`0x0048f330`) typed as a nested `ui_element_t` block loaded from
    `ui\\ui_textLevelUp.jaz`.
