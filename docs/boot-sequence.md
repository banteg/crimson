---
tags:
  - status-verified
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
| `backplasma` | `load\backplasma.jaz` | Main menu background plasma? |
| `mockup` | `load\mockup.jaz` | Menu overlay/mockup? |
| `logo_esrb` | `load\esrb_mature.jaz` | "Mature 17+" rating logo. |
| `loading` | `load\loading.jaz` | Full-screen "Loading..." image. |
| `cl_logo` | `load\logo_crimsonland.tga` | Crimsonland logo. |

> **Note:** `splash10tons` and `splashReflexive` strings exist in the binary but their explicit `texture_get_or_load` calls are not visible in `crimsonland_main` decompilation. They are likely loaded/rendered in a sub-function or dynamically by name.

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

## 4. Company Logo Sequence (Inferred)

Between the splash and main asset loop, the game renders the company logos.
Exact logic is still unresolved in decompilation; likely sequence:

1. **10tons splash:** `splash10tons` (inferred from string presence).
2. **Reflexive splash:** `splashReflexive` (inferred from string presence).

## 5. Main Asset Loading Loop (`load_textures_step`)

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

## 6. Startup Finalization
(`game_startup_init` @ `0x0042b090`)

Once loading is complete (`step > 9`):

1. **Effect/UV Tables:** `effect_uv_tables_init`.
2. **Databases:** `perks_init_database`, `weapon_table_init`.
3. **Game Core:** `game_core_init`.
4. **Easter Eggs:** Checks system date (e.g. Sep 12, Nov 8, Dec 18) for special behavior (`s_balloon`).
5. **Gameplay Reset:** `gameplay_reset_state`, `terrain_generate_random`.
6. **Registry:** Updates "Time Played" counter.

## 7. Main Loop

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
