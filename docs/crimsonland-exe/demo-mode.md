---
tags:
  - status-analysis
---

# Demo / attract mode (shareware)

This page documents the classic shareware **demo/attract loop** implemented in
`crimsonland.exe`. The same code exists in the v1.9.93 codebase but is normally
gated by `game_is_full_version()` (the DRM-free builds don’t enter the loop on
their own).

The demo loop is useful for reimplementation because it exercises:

- Gameplay state `9` (creatures/projectiles/players) without needing menu work.
- A deterministic set of setup variants (`demo_setup_variant_*`).
- A self-contained “upsell” overlay + purchase screen (`demo_purchase_screen_update`)
  that drives its own timer and can transition back to menu state `0`.
  **Rewrite note:** we implement this screen for parity (the purchase URL is legacy).

## Entry points

### Boot handoff: logos → demo

In the logo sequence, once the logo timer passes the theme trigger (~14s), the
shareware build:

- mutes the intro track
- plays `music_track_crimsonquest_id`
- calls `demo_mode_start()` (`0x00403390`)

Full builds instead play `music_track_crimson_theme_id` and proceed to the menu.

See: `docs/re/static/boot-sequence.md` (handoff section).

### Runtime entry: trial/attract trigger

The main loop (`console_hotkey_update`) contains a shareware-only path that
starts `demo_mode_start()` and switches music to `shortie_monk` (exact trigger
still TBD; see decompile around `0x0040cf06`).

## Core loop model

At a high level:

- Demo mode runs in gameplay state `9`.
- `demo_mode_active` gates HUD and input behavior.
- `demo_mode_start()` resets the session and picks a setup variant.
- A per-frame overlay (`demo_purchase_screen_update`) is rendered on top and can
  transition to menu state `0`.

### Main loop integration (state `9`)

In the per-frame dispatcher:

- If `game_state_id == 9`:
  - If `demo_purchase_screen_active` is `0`: run `gameplay_update_and_render()`.
  - Else: **skip gameplay** and clear the screen.
  - If `demo_mode_active != 0`: always run `demo_purchase_screen_update()` on top.

This is why the demo cycle includes a “purchase interstitial” variant: it flips
`demo_purchase_screen_active` to suppress gameplay and show only the upsell
screen for a fixed time.

**Rewrite note:** the Python rewrite matches the modulo-6 sequencing, including
the automatic “variant 5” purchase interstitial. The purchase screen can also be
triggered on input (LMB / Esc / Space), matching the original shareware behavior.

### Timing: `quest_spawn_timeline` + `demo_time_limit_ms`

Two globals define the cycle timing:

- `quest_spawn_timeline` (`0x00486fd0`): a generic “mode timeline” counter (ms).
  Reset to `0` by `demo_mode_start()`.

- `demo_time_limit_ms` (`0x004712f0`): demo timer limit used as:
  - ~4–5s per gameplay variant (`4000`/`5000`)
  - ~10s for the interstitial (`10000`)
  - ~16s when the user triggers the purchase screen (`16000`)

Mode-specific update hooks use these:

- `survival_update()` and `rush_mode_update()`:
  - if `demo_mode_active` and `quest_spawn_timeline > demo_time_limit_ms`: call `demo_mode_start()`.
- `demo_purchase_screen_update()`:
  - when the purchase screen is active, it increments `quest_spawn_timeline` itself and restarts via
    `demo_mode_start()` when it exceeds `demo_time_limit_ms`.

## `demo_mode_start` (`0x00403390`)

High-confidence pseudocode (decompile + callsite xrefs):

```c
if (game_state_id != 9) game_state_set(9);

demo_purchase_screen_active = 0;
demo_mode_active = 1;

gameplay_reset_state();
config.game_mode = 1; // survival

switch (demo_variant_index) {
  case 0: demo_setup_variant_0(); break;
  case 1: demo_setup_variant_1(); break;
  case 2: demo_setup_variant_2(); break;
  case 3: demo_setup_variant_3(); break;
  case 4: demo_setup_variant_0(); break;
  case 5: demo_purchase_interstitial_begin(); break; // 0x00403370
}

quest_spawn_timeline = 0;
screen_fade_ramp_flag = 0; // DAT_0048702c
demo_variant_index = (demo_variant_index + 1) % 6;
```

## Setup variants (`demo_setup_variant_*`)

The variants are small, deterministic setup functions that:

- set `config.player_count`
- optionally call `terrain_generate(desc)`
- spawn a fixed set of creatures via `creature_spawn_template(spawn_id, pos_xy, heading)`
- position players and assign starting weapons
- set `demo_time_limit_ms`

### Variant 0 — `demo_setup_variant_0` (`0x00402ed0`)

- `player_count = 2`
- `demo_time_limit_ms = 4000`
- Spawns template `0x38` in two columns (x≈128/192 and x≈798/862), y=256..1632 step 80.
- Player positions: P1 `(448,384)`, P2 `(546,654)`.
- Weapon: `0x0b` (Rocket Launcher) for both.
- Uses `heading = -100.0` for spawns (likely a sentinel; exact semantics TBD).

### Variant 1 — `demo_setup_variant_1` (`0x004030f0`)

- `player_count = 2`
- `terrain_generate(&DAT_00484914)` (this points into the quest metadata table; see `docs/crimsonland-exe/terrain.md`).
- `demo_time_limit_ms = 5000`
- Spawns 20× template `0x34` plus ~13× template `0x35` at random positions:
  - `x = rand()%200 + 32` (or `%30 + 32` for template `0x35`)
  - `y = rand()%899 + 64`
  - `heading = -100.0`
- Player positions: P1 `(490,448)`, P2 `(480,576)`.
- Weapon: `0x05` (Gauss Gun) for both.
- Forces `bonus_weapon_power_up_timer = 15.0`.

### Variant 2 — `demo_setup_variant_2` (`0x00402fe0`)

- `player_count = 1`
- `demo_time_limit_ms = 5000`
- Spawns template `0x41` in columns at y=128..788 step 60, with x offsets:
  - `x = 32`, `128`, `-64`, `768` (alternating by row parity)
  - `heading = -100.0`
- Weapon: `0x15` (Ion Minigun).

### Variant 3 — `demo_setup_variant_3` (`0x00403250`)

- `player_count = 1`
- `terrain_generate(&quest_selected_meta)` (uses the currently selected quest descriptor).
- `demo_time_limit_ms = 4000`
- Spawns random templates `0x24` and `0x25` at positions similar to variant 1.
- Player position: `(512,512)`.
- Weapon: `0x12` (Pulse Gun).
- Uses `heading = 0.0` for spawns.

### Variant 5 — purchase interstitial — `demo_purchase_interstitial_begin` (`0x00403370`)

- `demo_time_limit_ms = 10000`
- `demo_purchase_screen_active = 1` (suppresses gameplay and renders the full-screen purchase UI)

**Rewrite note:** the Python rewrite implements the purchase UI and auto-enters
this interstitial variant.

## Upsell overlay (`demo_purchase_screen_update` / `0x0040b740`)

**Rewrite note:** implemented in `src/crimson/demo.py` for parity. The purchase
URL is legacy; we open it best-effort.

This runs whenever `demo_mode_active != 0`:

- **When `demo_purchase_screen_active == 0`**
  - Shows a rotating “Want more …” message (`demo_upsell_message_index`).
  - On user input, activates the full purchase screen:
    - `demo_purchase_screen_active = 1`
    - `demo_time_limit_ms = 16000`

- **When `demo_purchase_screen_active != 0`**
  - Renders the full-screen purchase UI (backplasma + mockup + logo, feature list).
  - Buttons:
    - `Purchase`: sets `shareware_offer_seen_latch` and opens the purchase URL (then requests quit).
    - `Maybe later`: starts a transition back to menu state `0` and resumes `crimson_theme`.

  - Increments `quest_spawn_timeline` itself and restarts the demo via `demo_mode_start()` once
    `quest_spawn_timeline > demo_time_limit_ms`.

## Exiting demo mode (returning to menu)

When the upsell overlay triggers a transition to state `0`, the UI transition
manager (`ui_elements_update_and_render @ 0x0041a530`) does two demo-specific
things:

- If `demo_mode_active` and `game_state_pending == 0`, it calls
  `terrain_generate_random()` right before `game_state_set(0)` (so the menu
  background changes).

- Once the menu transition finishes, it clears `demo_mode_active` and reloads
  presets (`config_load_presets()`).

## Player behavior in demo mode (autoplay)

`player_update @ 0x004136b0` treats `demo_mode_active` as a control-scheme
override and routes through the same logic as the “auto-aim” control mode:

- Maintains `player_auto_target` (`player+0x2fc`) as the nearest living creature
  with a 64-unit hysteresis.

- Aiming is biased by arena center:
  - if no valid target: aim away from `(512,512)`
  - if within 300 units of center: aim at the target; otherwise aim relative to center

The exact firing behavior in this mode still needs confirmation (movement/aim
are clearly autonomous; the fire gating should be verified with a runtime probe).
