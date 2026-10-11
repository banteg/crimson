---
tags:
  - status-validation
---

# Boot / Loading Sequence

This page documents the boot-up sequence from process entry to the main menu.
The sequence follows the recovered `crimsonland_main`
(`decomp/1.9/crimsonland/crimsonland/crimsonland_main.cpp`), `game_startup_init`
and the iterative asset loader `load_textures_step`.

## 1. System Initialization
(`crimsonland_main` start)

1. **Seed + DirectX check:** `crt_srand(crt_time(0))`; `dx_get_version` requires
   DX 8.1+ (a MessageBox offers the download page, then the game exits).
2. **Paths + log:** `crt_getcwd` stores `game_base_path`; `Direct3DCreate8` is a
   presence check; the console banner is flushed to `console.log`.
3. **Config file + commands:** `config_ensure_file`, then the
   [startup console commands](systems/console.md#startup-commands-registered-in-crimsonland_main).
4. **Grim2D load:** `grim_load_interface` tries the developer build
   `..\grim_grSystem_c\Release\grim.dll`, then `grim.dll`. The developer-hint
   print block after it never runs: its guard,
   `grim_interface_ptr == grim_interface_ptr + 1`, is always false. Then
   `register_core_cvars`.
5. **Config load:** `config_load_presets` reads `crimson.cfg`; `game_load_status`
   and `play_time_load`.
6. **Grim config:** `grim_apply_config` (resolution/window mode dialog; cancel
   exits), `config_sync_from_grim`, then `config_load_presets` again without the
   Grim settings. `grim_get_config_var` reads back texture scale, windowed flag,
   screen size and backend flags.
7. **Callbacks + Grim2D init:** `grim_set_config_var(0x2d, game_startup_init)`
   installs the frame callback (audio suspend/resume callbacks use `5`/`6`);
   keyboard, mouse and joystick are enabled; `grim_init_system` brings up D3D,
   input and `smallFnt.dat`, or shows `grim_get_error_text` and exits.
8. **Autoexec:** `exec autoexec.txt`, then `v_width`/`v_height` cvars from the
   screen size.
9. **Audio/Terrain Init:** `init_audio_and_terrain` (`0x0042a9f0`), then the
   resource paq is set to `crimson.paq`.

## 2. Splash Assets Loading
(`crimsonland_main` continued)

The game pre-loads specific textures needed for the splash screen and loading screen *before* the main asset load.

| Texture | Resource | Notes |
| --- | --- | --- |
| `backplasma` | `load\backplasma.jaz` | 64×64 RGBA plasma tile (extracted as `backplasma.png`). |
| `mockup` | `load\mockup.jaz` | 512×256 RGBA overlay (extracted as `mockup.png`). |
| `logo_esrb` | `load\esrb_mature.jaz` | 256×128 RGBA ESRB logo (extracted as `esrb_mature.png`). |
| `loading` | `load\loading.jaz` | 128×32 RGBA "LOADING..." (extracted as `loading.png`). |
| `cl_logo` | `load\logo_crimsonland.tga` | 512×64 RGBA logo (extracted as `logo_crimsonland.png`). |
| `splash10tons` | `load\splash10tons.jaz` | 512×128 RGBA company logo (extracted as `splash10tons.png`). |
| `splashReflexive` | `load\splashReflexive.jpg` | 512×256 RGB company logo (extracted as `splashReflexive.jpg`). |

> **Note:** `splash10tons` and `splashReflexive` are loaded in `game_startup_init`
> after the main texture steps complete, not directly inside `crimsonland_main`.

After loading the first five, `crimsonland_main` alternates `grim_clear_color`
with `grim_set_config_var(0x36, …)` (`IDirect3DDevice8::Present`; see the
[Grim config API](../../grim2d/api.md)) so the window starts black.

## 3. Loading Screen

`game_startup_init` (`0x0042b290`,
`decomp/1.9/crimsonland/crimsonland/game_startup_init.cpp`) draws the loading
screen on a black clear while `load_textures_step` runs. `backplasma` and
`mockup` are loaded but never drawn here.

### State / fade

- `startup_splash_timer` (`0x004aaf90`) grows by `frame_dt` each tick. Once
  loading finishes it shrinks by `frame_dt` instead; at `0` it sets
  `startup_loading_fade_complete` and frees `loading` and `logo_esrb`.
- `loading_alpha = clamp(2.0 * startup_splash_timer, 0.0, 1.0)` tints
  `logo_esrb`, `loading`, and `cl_logo`.

### Render setup (per frame)

- `grim_clear_color(0, 0, 0, 1)`.
- `grim_set_config_var(0x15, 1)` (texture filter state).
- `grim_set_color(1, 1, 1, loading_alpha)`.
- `grim_set_uv(0, 0, 1, 1)`, `grim_set_rotation(0)`.

### Draw order (per pass)

Each textured pass uses `grim_get_texture_handle` + `grim_bind_texture`, then
`grim_begin_batch` → `grim_draw_quad` → `grim_end_batch`:

1. **ESRB** (`logo_esrb`)
   - `x = screen_width - 257`
   - `y = screen_height - 129`
   - `w = 256`, `h = 128`
2. **Loading** (`loading`)
   - `x = (screen_width * 0.5) + 128`
   - `y = (screen_height * 0.5) + 16`
   - `w = 128`, `h = 32`
3. **Logo** (`cl_logo`)
   - `x = (screen_width * 0.5) - 256`
   - `y = (screen_height * 0.5) - 32`
   - `w = 512`, `h = 64`
4. **Band frame** (four 1px quads tinted)
   - Top: `x = -4`, `y = (screen_height * 0.5) - 68`, `w = screen_width + 8`, `h = 1`
   - Bottom: `x = -4`, `y = (screen_height * 0.5) + 60`, `w = screen_width + 9`, `h = 1`
   - Left: `x = -4`, `y = (screen_height * 0.5) - 68`, `w = 1`, `h = 128`
   - Right: `x = screen_width + 4`, `y = (screen_height * 0.5) - 68`, `w = 1`, `h = 128`

Unless `cv_silentloads` is set, `Grim GFX n/m` and `Grim SFX: n/81` progress
lines are drawn under the logo at `loading_alpha * 0.7` before the band frame.

The band frame is `startup_render_loading_outline`: one
`grim_draw_rect_outline(-4, h/2 - 68, w + 8, 128)` call, which
`decomp/1.9/grim/render/draw_rect_outline.cpp` expands into the four quads
above. Its tint is `render_tint_color` (`#95AFC6`, set in
`render_tint_color_global_init.cpp`) with alpha `loading_alpha * 0.7`.

## 4. Company Logo Sequence

The company logo sequence runs inside `game_startup_init` after
`load_textures_step` completes and the splash fade-out finishes.

### Activation / gating

- When textures finish, the game loads `splashReflexive` and `splash10Tons`,
  runs `game_startup_init_prelude`, starts the sound thread, and clamps
  `startup_splash_timer` to `0.5` if it is larger.

- This handoff is gated by startup latches:
  `startup_bootstrap_pending` (`0x004aaf86`) -> `startup_logo_sequence_active` (`0x004aaf9c`),
  with `startup_skip_requested` (`0x004aaf94`) controlling fast-forward behavior.

- A 5-tick delay (`Sleep(5)` per tick) runs before the logos display, tracked by
  `startup_post_load_settle_ticks` (`0x004aaf98`).

### Timing model

- The internal timer (`startup_splash_timer`) advances by `frame_dt * 1.1`.
- For logo rendering, it uses `t = startup_splash_timer - 2.0`.
- If the user skips (key/mouse), `t` accelerates by `frame_dt * 4.0` inside a
  logo window (`[1, 5)` or `[7, 11)`) and jumps to `16.0` outside one.

### 10tons logo (512×128)

- Fade in: `t` in `[1.0, 2.0)` → alpha = `t - 1.0` (0→1).
- Hold: `t` in `[2.0, 4.0)` → alpha = 1.0.
- Fade out: `t` in `[4.0, 5.0)` → alpha = `1.0 - (t - 4.0)` (1→0).

### Reflexive logo (512×256)

- Fade in: `t` in `[7.0, 8.0)` → alpha = `t - 7.0`.
- Hold: `t` in `[8.0, 10.0)` → alpha = 1.0.
- Fade out: `t` in `[10.0, 11.0)` → alpha = `1.0 - (t - 10.0)`.

### Handoff to theme

- While the logos run (`startup_intro_enabled`), `music_play_exclusive` keeps
  the intro track playing.
- When `startup_splash_timer > 14.0`, `music_fade_out_all` mutes the intro and
  `crimson_theme` starts in the same frame (or `crimsonquest` plus
  `demo_mode_start` in the demo), ending the logo sequence. The splash textures
  are freed and `game_frame_update` becomes the frame callback.

## 5. Main Asset Loading Loop (`load_textures_step`)

The game enters a loop where it calls `load_textures_step` (`0x0042abd0`) repeatedly.
While this loop runs, the `loading` texture (`load\loading.jaz`) is displayed on screen.

`load_textures_step` returns `0` while busy and `1` when finished. It uses
`startup_texture_load_stage` (`0x004aaf88`) to track progress (`0..9`).

### Loading Steps

| Step | Assets Loaded |
| --- | --- |
| **0** | **Creatures:** `trooper`, `zombie`, `spider` (sp1/sp2), `alien`, `lizard`, `smallWhite` font. |
| **1** | **Projectiles/Bodies:** `arrow`, `bullet16`, `bulletTrail`, `bodyset`, `projs` (projectiles). |
| **2** | **UI Basics:** `ui_iconAim`, `ui_button` (Sm/Md), `ui_check` (On/Off), `ui_rect` (On/Off), `bonuses`. |
| **3** | **Indicators & Particles:** `ui_indBullet`, `ui_indRocket`, `ui_indElectric`, `ui_indFire`, `particles`. |
| **4** | **UI Cursor & Panels:** `ui_indLife`, `ui_indPanel`, `ui_arrow`, `ui_cursor`, `ui_aim`. |
| **5** | **Terrain Textures:** `ter_q1`..`q4` (base/tex1) OR `ter_fb` (fallback) if high-res failed. |
| **6** | **UI Text & Numbers:** `ui_textLevComp`, `ui_textQuest`, `ui_num1`..`num5`. |
| **7** | **HUD / Weapon Icons:** `ui_wicons`, `ui_gameTop`, `ui_lifeHeart`, `ui_clockTable`, `ui_clockPointer`. |
| **8** | **Muzzle Flash & Dropdowns:** `muzzleFlash`, `ui_dropDown` (On/Off). |
| **9** | **Finalization:** Creates `bullet_i` and `aim64` sprites. Sets `game_state_id = 0`. |

## 6. Startup Finalization
(`game_startup_init_prelude` @ `0x0042b090`)

Once loading is complete, `game_startup_init` runs
`game_startup_init_prelude` (`decomp/1.9/crimsonland/crimsonland/game_startup_init_prelude.cpp`):

1. **Effect/UV Tables:** `effect_uv_tables_init`.
2. **Databases:** `perks_init_database`, `weapon_table_init`.
3. **Game Core:** `game_core_init`.
4. **Easter Eggs:** On Sep 12, Nov 8 and Dec 18 (local date) it loads the `balloon` texture (`balloon.tga`).
5. **Gameplay Reset:** `gameplay_reset_state`, `terrain_generate_random`.
6. **Registry:** Reads the `timePlayed` counter into `time_played_ms`.

## 7. Main Loop

The game enters the main loop with `game_state_id = 0` (Main Menu). The per-frame
input/hotkey pass here is `game_frame_update` (`0x0040c1c0`).
