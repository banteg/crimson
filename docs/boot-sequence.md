---
tags:
  - status-in-progress
---

# Boot / Loading Sequence

This page documents the boot-up sequence from process entry to the main menu.
The sequence is derived from `crimsonland_main` analysis and the iterative asset loader `load_textures_step`.

## 1. System Initialization
(`crimsonland_main` start)

1. **DirectX / System Checks:** Verifies DX8.1+, SSE support, etc.
2. **Path Setup:** Sets current working directory (`crt_getcwd`).
3. **Console Init:** Registers commands (`console_register_command`) and core cvars (`register_core_cvars`).
4. **Config Load:** Loads `crimson.cfg` and executes `autoexec.txt`.
5. **Grim2D Init:**
   - `grim_init_system`
   - `grim_apply_config` (Resolution/Window mode)
6. **Audio/Terrain Init:** `init_audio_and_terrain` (`0x0042a9f0`).

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

## 3. Splash Screen Rendering (Runtime Evidence)

Runtime capture (`artifacts/frida/share/splash_draw_calls.jsonl`) shows the
exact draw calls for the splash/loading screen at 800x600. Key facts:

- **Background:** black clear. No `backplasma` or `mockup` draw calls appear in
  the captured splash frame.
- **Drawn textures:** `cl_logo`, `loading`, `logo_esrb`.
- **Band frame:** 1px rectangle around the logo band, rendered using
  `cl_logo` as a solid-tinted quad.

### Geometry (800x600)

- **Logo:** `x=144, y=268, w=512, h=64` (centered).
- **Loading text:** `x=528, y=316, w=128, h=32` (right-aligned to logo).
- **ESRB:** `x=543, y=471, w=256, h=128` (bottom-right, 1px margin).
- **Band frame:** a 808x128 rectangle centered on the logo:
  - Top: `x=-4, y=232, w=808, h=1`
  - Bottom: `x=-4, y=360, w=809, h=1`
  - Left: `x=-4, y=232, w=1, h=128`
  - Right: `x=804, y=232, w=1, h=128`

### Colors / alpha

- Logo/Loading/ESRB are drawn with a shared fade alpha (observed sequence:
  `0.03, 0.23, 0.42, 0.598, 0.772, 0.932, 1.0`).
- Band frame color ≈ `#95AFC6` (r=0.5843, g=0.6863, b=0.7765).
- Band frame alpha = `logo_alpha * 0.7`.

> **Note:** The capture only logs splash draws in frame 0, so timing/duration
> of the fade remains unknown; this is a geometry + layering reference.

## 4. Splash Render Routine (Static + Runtime)

The draw calls above map to a single render routine located between
`load_textures_step` and `crimsonland_main` (addresses around `0x0042be90` to
`0x0042c1e2`). It is not named in the decompiler output but the assembly is
clear. The routine:

### State / fade

- `DAT_004aaf90` is incremented each tick by `DAT_00480840` (frame delta).
- `alpha = clamp(2.0 * DAT_004aaf90, 0.0, 1.0)`; clamped by comparing against
  constants `1.0` and `0.0`.
- The same `alpha` is used for `logo_esrb`, `loading`, and `cl_logo`.
- The band frame uses `alpha * 0.7` (validated in runtime capture).

### Render setup (per frame)

From the assembly around `0x0042be90`:

- `grim_clear_color(0, 0, 0, 1)` (vtable +0x2c).
- `grim_set_render_state(0x15, 1)` (vtable +0x20).
- `grim_set_color(1, 1, 1, alpha)` (vtable +0x114).
- `grim_set_uv(0, 0, 1, 1)` (vtable +0x100).
- `grim_set_rotation(0)` (vtable +0xfc).

### Draw order (per pass)

Each pass uses `grim_get_texture_handle` + `grim_bind_texture`, then
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

> The band frame draw is implemented inside `grim.dll` (callsites in the DLL),
> but the geometry and color are confirmed via Frida capture.

## 5. Company Logo Sequence (Static)

The company logo sequence runs inside `game_startup_init` after
`load_textures_step` completes and the splash fade-out finishes.

### Activation / gating

- When textures finish, the game loads `splashReflexive` and `splash10Tons`,
  runs `game_startup_init_prelude`, starts the sound thread, and clamps
  `_DAT_004aaf90` to `0.5` if it is larger. `[static]`
- A 5-tick delay (`Sleep(5)` per tick) runs before the logos display. `[static]`

### Timing model

- The internal timer (`_DAT_004aaf90`) advances by `frame_dt * 1.1`. `[static]`
- For logo rendering, it uses `t = _DAT_004aaf90 - 2.0`. `[static]`
- If the user skips (key/mouse), time jumps to `t = 16.0` when not inside a
  fade window; otherwise it accelerates by `frame_dt * 4.0`. `[static]`

### 10tons logo (512×128)

- Fade in: `t` in `[1.0, 2.0)` → alpha = `t - 1.0` (0→1). `[static]`
- Hold: `t` in `[2.0, 4.0)` → alpha = 1.0. `[static]`
- Fade out: `t` in `[4.0, 5.0)` → alpha = `1.0 - (t - 4.0)` (1→0). `[static]`

### Reflexive logo (512×256)

- Fade in: `t` in `[7.0, 8.0)` → alpha = `t - 7.0`. `[static]`
- Hold: `t` in `[8.0, 10.0)` → alpha = 1.0. `[static]`
- Fade out: `t` in `[10.0, 11.0)` → alpha = `1.0 - (t - 10.0)`. `[static]`

### Handoff to theme

- When `_DAT_004aaf90 > 14.0`, the intro is muted and `crimson_theme` (or
  `crimsonquest` in demo mode) begins, ending the logo sequence. `[static+runtime]`

## 6. Main Asset Loading Loop (`load_textures_step`)

The game enters a loop where it calls `load_textures_step` (`0x0042abd0`) repeatedly.
While this loop runs, the `loading` texture (`load\loading.jaz`) is displayed on screen.

`load_textures_step` returns `0` while busy and `1` when finished. It uses a state variable (`DAT_004aaf88`) to track progress (0-9).

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

## 7. Startup Finalization
(`game_startup_init` @ `0x0042b290`)

Once loading is complete (`step > 9`):

1. **Effect/UV Tables:** `effect_uv_tables_init`.
2. **Databases:** `perks_init_database`, `weapon_table_init`.
3. **Game Core:** `game_core_init`.
4. **Easter Eggs:** Checks system date (e.g. Sep 12, Nov 8, Dec 18) for special behavior (`s_balloon`).
5. **Gameplay Reset:** `gameplay_reset_state`, `terrain_generate_random`.
6. **Registry:** Updates "Time Played" counter.

### Boot music handoff (runtime evidence)

Frida trace (`artifacts/frida/share/music_intro_trace.jsonl`) shows the **intro
track is played inside `game_startup_init`**, then muted and replaced by
`crimson_theme`:

- `sfx_play_exclusive(music_track_intro_id)` at `0x0042b69a`
- `sfx_mute_all(music_track_intro_id)` at `0x0042b556`
- `sfx_play_exclusive(music_track_crimson_theme_id)` at `0x0042b584`

Measured timing from the same trace:

- Intro starts ~20.4s after process start and plays for ~12.7s.
- Theme starts immediately after intro mute (same frame).

Additional `sfx_mute_all` calls with return addresses in `FUN_00447420`
(`0x00447420`) occur later during UI transitions (menu flow), not the boot
sequence.

## 8. Main Loop

The game enters the main loop (likely `FUN_0040c1c0` wrapper) with `game_state_id = 0` (Main Menu).

## Decompile Notes: Post-logo render setup (early draw pipeline)

Immediately after the splash textures are loaded in `crimsonland_main`
(`texture_get_or_load` calls for backplasma/mockup/logo_esrb/loading/cl_logo),
the decompiler shows a short block of Grim2D vtable calls before input setup:

- `grim_clear_color` (`vtable +0x2c`) called twice.
- `grim_set_render_state` (`vtable +0x20`) called with several state/value pairs:
  - state `0x36`, value `1` (exact meaning TBD).
  - another call with `value = 1.0f` (seen on stack as `0x3f800000`).

This block likely clears the screen and sets basic render state (blend, filtering,
or color) before the first visible splash draw. The exact per-frame draw loop
is still not obvious from the decompile; we need a callsite that renders
`logo_esrb` / `loading` / `cl_logo` (or the texture manager drawing by name).

**Next step:** locate the draw function that consumes the splash textures by
finding callsites that reference their texture IDs (or texture manager lookup),
and map the Grim2D calls to the runtime draw order.

## Verification

To verify the "Loading" screen behavior:
- Check if `load\loading.jaz` is displayed fullscreen during the asset loading phase.
- Ensure the loop processes all 10 steps of `load_textures_step`.
