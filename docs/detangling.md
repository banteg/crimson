# Detangling notes

**Status:** In progress

This page tracks high-value functions to name and the evidence gathered so far.
Use the hotspot script to refresh the lists when the decompile is regenerated.

## Hotspot script

```
uv run python scripts/function_hotspots.py --top 12 --only-fun
```

## Name map workflow

We keep authoritative renames/signatures in `source/ghidra/name_map.json` and
apply them during headless analysis:

```
./.codex/skills/ghidra/scripts/ghidra-analyze.sh \
  --script-path scripts/ghidra_scripts \
  -s ApplyNameMap.java -a source/ghidra/name_map.json \
  -s ExportAll.java -o source/decompiled game/crimsonland.exe
```

You can also set `CRIMSON_NAME_MAP` to point at a custom map.

## High-call functions (current)

### `crimsonland.exe`

```
  25    1 00465d93 FUN_00465d93 DWORD * FUN_00465d93(void)
  20    1 00460d86 FUN_00460d86 int FUN_00460d86(undefined4 param_1)
  19    0 0042fcf0 FUN_0042fcf0 undefined4 FUN_0042fcf0(int param_1)
  15    2 004616e7 FUN_004616e7 int FUN_004616e7(undefined1 * param_1, byte * param_2)
  15    0 0042e120 FUN_0042e120 undefined4 * FUN_0042e120(int param_1, undefined4 * param_2)
  14    3 0043d120 FUN_0043d120 int FUN_0043d120(int param_1)
  14    1 00460dc7 FUN_00460dc7 undefined FUN_00460dc7(undefined * param_1)
  14    1 00465d9c FUN_00465d9c DWORD * FUN_00465d9c(void)
  12    8 004625c1 FUN_004625c1 undefined FUN_004625c1(undefined * param_1)
  12    3 00460e5d FUN_00460e5d undefined4 FUN_00460e5d(FILE * param_1)
  12    2 0043d550 FUN_0043d550 undefined FUN_0043d550(int param_1)
  11    3 0043d260 FUN_0043d260 float FUN_0043d260(float param_1)
```

### `grim.dll`

```
  33    0 10016944 FUN_10016944 undefined4 FUN_10016944(void * this, int param_1)
  32    6 1001c188 FUN_1001c188 int FUN_1001c188(int param_1)
  32    1 100170f9 FUN_100170f9 undefined4 * FUN_100170f9(void * this, undefined4 * param_1, uint param_2, undefined4 param_3)
  30    0 100170d6 FUN_100170d6 undefined FUN_100170d6(undefined4 param_1)
  28    0 100174a8 FUN_100174a8 undefined FUN_100174a8(void * this, uint param_1)
  21    0 1004b5b0 FUN_1004b5b0 undefined FUN_1004b5b0(void)
  14    1 1001e114 FUN_1001e114 undefined FUN_1001e114(int * param_1, undefined4 param_2)
  10    0 10001160 FUN_10001160 undefined FUN_10001160(void)
  10    0 1001e132 FUN_1001e132 undefined FUN_1001e132(int param_1, undefined4 param_2)
   9    4 100250d7 FUN_100250d7 undefined4 FUN_100250d7(int * param_1, uint param_2)
   9    2 10024807 FUN_10024807 undefined FUN_10024807(int * param_1, byte * param_2, uint param_3)
   8    2 1001029e FUN_1001029e undefined FUN_1001029e(int param_1)
```

## Identified candidates

### Logging / console queue (high confidence)

- `FUN_0046e8f4` -> `strdup_malloc`
  - Evidence: `strlen` + `malloc` + copy (`FUN_00465c30`) pattern.
- `FUN_004017a0` -> `console_push_line`
  - Evidence: pushes strdup’d strings into a list, caps at 0x1000 entries.
- `FUN_00401870` -> `console_printf`
  - Evidence: formats strings (uses `FUN_00461089`) then pushes into the console queue; callsites include `Unknown command`/CMOD logs.


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
- Evidence:
  - Both call `crt_get_thread_data()` and return pointer offsets (`+2`, `+3`).
  - `FUN_00465d20` stores Win32 errors into `*FUN_00465d9c` and maps to `*FUN_00465d93`
    via the error table at `DAT_0047b7c0`.
  - File I/O wrappers set these directly on failure:
    - `FUN_004655bf` (FlushFileBuffers) stores `GetLastError()` in `*FUN_00465d9c` and sets
      `*FUN_00465d93 = 9` (EBADF).
    - `FUN_004656b7` (WriteFile) and `FUN_00466064` (ReadFile) call `FUN_00465d20` after
      `GetLastError()` for non-trivial errors.
    - `FUN_0046645e` (SetFilePointer) maps `GetLastError()` through `FUN_00465d20`.


### CRT lock/unlock helpers (high confidence)

- `FUN_0046586b` -> `crt_lock`
  - Evidence: calls `InitializeCriticalSection`, `EnterCriticalSection`, and `__amsg_exit` in the
    lock path; invoked by `crt_exit_lock` and many CRT wrappers.
- `FUN_004658cc` -> `crt_unlock`
  - Evidence: calls `LeaveCriticalSection`; invoked by `crt_exit_unlock` and many CRT wrappers.


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
- `FUN_004616e7` -> `crt_sprintf`
  - Evidence: uses CRT output core `FUN_00464380` with an unbounded count (`0x7fffffff`) and
    terminates with `\0` on success.


### Audio SFX helpers (medium confidence)

- `FUN_0043d120` -> `sfx_play`
  - Evidence: validates entry in `DAT_004c84e4`, checks cooldown `DAT_004c3c80`, sets sample rate
    via `_DAT_00487014` into `DAT_00477d28`, chooses a voice (`FUN_0043be60`), calls vtable +0x40
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
  - See [SFX label suggestions](sfx-labels.md) for suggested data labels (ApplyNameMap only renames functions).
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
  - Evidence: returns `(&DAT_00490968)[perk_id]` directly; used to track perk picks and gating.


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
  - Evidence: pushes the entry back onto `DAT_004c2b30` free list and clears live flag.
- `FUN_0042e0a0` -> `effect_select_texture`
  - Evidence: maps effect id through `DAT_004755f0/4` and calls Grim vtable +0x104 with
    texture page bitmasks.
- `FUN_0042e120` -> `effect_spawn`
  - Evidence: pops an entry from the pool `DAT_004c2b30`, copies template `DAT_004ab1bc`,
    writes position from `param_2`, tags the effect id, and assigns quad UVs from atlas tables
    `DAT_004755f0/4` plus arrays `DAT_004aa4d8`, `DAT_00491010`, `DAT_00491210`, `DAT_00491290`.
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


### Tutorial prompt (medium confidence)

- `FUN_00408530` -> `tutorial_prompt_dialog`
  - Evidence: renders the tutorial message panel and uses button UI for "Repeat tutorial",
    "Play a game", and "Skip tutorial"; click handlers restart the tutorial (clears perk count
    table `DAT_00490968` and resets timers) or exit to game (sets `DAT_00487274`, flushes input,
    and resets `DAT_00486fe0`).


### Tutorial timeline (medium confidence)

- `FUN_00408990` -> `tutorial_timeline_update`
  - Evidence: loads the tutorial string table, advances `DAT_00486fd8` stage index when
    `DAT_00486fe0` counts up from `-1000`, and renders each stage via `tutorial_prompt_dialog`.
  - Stage transitions observed:
    - Stage 0: after `DAT_00486fdc > 6000` and `DAT_00486fe0 == -1`, clears `DAT_004808a8`,
      resets `DAT_004712fc`, and sets `DAT_00486fe0 = -1000`.
    - Stage 1: waits for any movement key active (`grim_is_key_active` via vtable +0x80),
      then spawns bonus pickups (`FUN_0042ef60`) and sets `DAT_00486fe0 = -1000`.
    - Stage 2: waits until all 16 bonus slots in `DAT_00482948` clear, then sets
      `DAT_00486fe0 = -1000`.
    - Stage 3: waits for input in `DAT_00490bec` key slots, spawns arrow markers
      (`FUN_00430af0`), then sets `DAT_00486fe0 = -1000`.
    - Stage 4: waits for `creatures_none_active()`, spawns arrow markers, sets `DAT_00486fdc = 1000`,
      then sets `DAT_00486fe0 = -1000`.
    - Stage 5: increments `DAT_004808a8` on repeated `creatures_none_active()` events, spawns markers/bonuses,
      and after 8 iterations sets `DAT_0049095c = 3000` and `DAT_00486fe0 = -1000`.
    - Stage 6: waits for `DAT_00486fac < 1`, spawns markers, then sets `DAT_00486fe0 = -1000`.
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

  - Unused strings in the same stack block: indices 9-12 map to perk/tutorial lines
    ("It will help you to move and shoot...", Perks intro, Perks description, "Great! Now you are ready to start"),
    and the speed/weapon/x2 powerup strings are assigned to `local_44/local_40/local_3c` but not indexed by `DAT_00486fd8`.
  - Helper: `FUN_00428210` -> `creatures_none_active`
    - Evidence: scans the creature table at `DAT_0049bf38` for any active entries, sets `DAT_0048700c`,
      and returns low byte `1` only when the table is empty.
  - Stage index wraps to 0 when `DAT_00486fd8` reaches 9; counters are initialized in `FUN_00412dc0`
    (`DAT_00486fd8 = -1`, `DAT_00486fe0 = -1000`) and reset by `tutorial_prompt_dialog`.


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


### Bonus / pickup pool (medium confidence)

- `FUN_0041f580` -> `bonus_alloc_slot`
  - Evidence: scans `DAT_00482948` in `0x1c`-byte strides and returns the first entry with type `0`
    (or the sentinel `DAT_00490630` when full).
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
- Layout (entry size `0x1c`, base `DAT_00482948`, 16 entries):

  | Offset | Field | Evidence |
  | --- | --- | --- |
  | 0x00 | type id (0 = free) | `bonus_alloc_slot` scans for `0`; render/update skip `0`. |
  | 0x04 | state flag (picked) | `bonus_update` sets to `1` after pickup and accelerates lifetime decay. |
  | 0x08 | time_left | decremented each frame in `bonus_update`; set to `0.5` on pickup; expiry clears type to `0`. |
  | 0x0c | time_max | set to `10.0` on spawn; used for fade/flash in `bonus_render`. |
  | 0x10 | pos_x | set on spawn; used for distance checks. |
  | 0x14 | pos_y | set on spawn; used for distance checks. |
  | 0x18 | amount/duration | used by `bonus_apply` when applying certain bonus types. |


### Game mode selector (partial)

- `_DAT_00480360` holds the current game mode. See [Game mode map](game-mode-map.md) for the observed
  values and evidence.
- `FUN_00412960` -> `game_mode_label`
  - Evidence: returns a label string based on `_DAT_00480360` (Survival, Quests, Typ-o-Shooter, etc.).


## Next naming targets

- For `grim.dll`, inspect `FUN_10016944` (coordinate conversions and vertex packing) to pin down the render pipeline stage.
