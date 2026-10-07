# Quest 1.1 client contract evidence

**Status: restored rendering changes canonical state at tick 0; stopped for review.** Run start is authoritative and still matches all 36,343 verifier snapshot fields. After restoring omitted original cvar registration and UI table/default setup, tick 0 completes. Its only differing field is `globals.player_weapon_popup_timer[0]`: client `1.9766666889190674` versus verifier `2.0`. Recovered HUD code decrements that timer at `ui_render_hud.cpp:779–780`. The remaining 36,342 fields agree at tick 0, including RNG. The harness stops before sending tick 1. No divergence or RNG ownership was fixed or reclassified; full client `RunResult` comparison is unavailable after this intentional stop.

This is step 1 evidence only. `build.py --target client` emits `build/client/client`, a native headless executable from the unchanged 168-unit verifier selection plus the 32 explicitly listed units in [sources.json](sources.json). It does not produce a backend or release client. The normal native/WASM targets retain their source list, host and flags. The client refuses the standard verifier output directories.

## Constraints and baseline

- Matrix: 134/134 cases and 357,500 ticks; the regenerated report equals checked-in `results/matrix.json` as a JSON value.
- Gate: 142/142 streams; the regenerated report equals checked-in `results/gate.json` as a JSON value. Typ-o remains explicitly unsupported.
- Comparator control: native verifier against unchanged WASM verifier, all 1,441 recording ticks plus initialization and all 36,343 schema fields agree. State stream SHA256: `af9f632b6fc9facf6dc8a563481082ad29904be68a345097ac987c510b0eeadf`.
- Comparator negative control: injected RNG differences at snapshots 2/3 and health at snapshot 4 are reported separately at first ticks 1 and 3; the final result alone would not detect them.
- Current-artifact preservation control: both native and WASM verifier executables remained byte-identical around the setup-restored client build/rerun. The user accepted the earlier macOS native rebuild metadata exception.
- Recording probe: all 41 slots statically referenced by the compiled selection log once; RNG-outside-tick, unsupported Grim slot, Survival and Quest 1.2 controls abort with named reasons.
- No tracked edits under `decomp/`, `host/api.h` or `patches/`; no SDL, GL, Emscripten, mixer, decoder or audio-device implementation.

The user accepted the macOS native rebuild metadata exception. The earlier repeated-rebuild UUID/object-timestamp/code-signature analysis remains in [native-rebuild.json](../results/client-step1/native-rebuild.json); no reproducible-linking change is part of this PR. This rerun does not rebuild the verifier and preserves both existing artifacts exactly.

| Artifact | Before SHA256 | After SHA256 | Byte identity |
| --- | --- | --- | --- |
| native | `79e4ba66a196a0f5a913a5318f8643c9313ca4c7ceed0ee1464f2edcd10355c7` | `79e4ba66a196a0f5a913a5318f8643c9313ca4c7ceed0ee1464f2edcd10355c7` | True |
| wasm | `b925731b352eef830b2c219cd7a250bf93e6c7fda76e28741fd9bcd36272647a` | `b925731b352eef830b2c219cd7a250bf93e6c7fda76e28741fd9bcd36272647a` | True |

Client SHA256: `0dad28327f387f7f383db7df4cce3fea333dbc04f655c5f86ada26e6b907873d`. Compiler: Apple clang version 21.0.0 (clang-2100.3.34.2); Zig 0.17.0. The client inherits the verifier build flags (`-O2`, C++17, no exceptions/RTTI, no strict aliasing, wrapping integers, FP contraction off, existing portable math and rule patches).

## Session contract and remaining review items

1. **Input and commands:** use the existing `PortableConfig`, finite normalized F32 input tuple and ordered batches of at most 16 semantic commands. Only one-player Quest 1.1 is accepted. Preserve the recording bug policy, unlocks, canonical 1024×768 viewport and input schemes. Screen clicks must eventually become commands at the same boundary; raw UI mutation is not an approved alternate command seam.
2. **Simulation clock:** one accepted `portable_step_many` boundary includes the validated command prelude, fixed F32 1/60 dt, Reflex Boost handling, recovered update/render orchestration, run-down accounting and existing end-of-tick RNG draw. `ClientTickScope` covers that boundary and closes on all returns. UI or wall-clock time must not enter it.
3. **Initialization:** run start is authoritative. Reset, quest construction, terrain generation and bootstrap draws use the same LCG inside `portable_init` that the verifier checks. The corrected guard permits randomness only inside initialization or a simulation tick, and remains closed otherwise. The existing `in_tick` log field denotes this authorized scope, including initialization; it is not a claim that initialization advances gameplay time.
4. **Pause and presentation:** fully paused/menu/perk presentation should advance no authoritative time or RNG. Preserve the command transition tick before pausing; clear accumulated gameplay debt on pause/restart/tab suspension. The current evidence target rejects pause and unrelated states. Its command-triggered recovered perk-screen call is instrumented in the transition tick; it is not evidence of a valid independent paused UI clock.
5. **Render work:** keep weapon guards, effect-queue processing, corpse and terrain bakes once per authoritative tick. For zero/multiple simulation ticks per display frame, preserve ordered persistent work from every tick and present only the latest transient scene. No display cadence scheduler exists here. The restored perk screen also calls world rendering; duplicate authoritative work must be investigated before adopting it. Nothing was moved or deduplicated.
6. **Completion:** preserve terminal outcome versus incomplete stream, the simulated 500 ms run-down, pending perks, final RNG and all player fields. Derive `RunResult` with the existing gate reducer. Early abort/rejection must never pass as zero compared ticks. A complete client result can only be compared after the complete input stream.
7. **Resources and Grim queries:** stable resource IDs/dimensions/font metrics and synchronous queries must be defined before initialization. All used slots record ordered calls. Baseline sentinel returns are retained as evidence (texture handle 1, text width 0, input from the existing host); none is certified neutral. The original UI table/default stage and native-width storage are restored; asset-backed menu/prompt geometry and the full menu layout remain unbootstrapped. The menu-layout asset remainder aborts by name.
8. **Sound:** compile the recovered trigger guards, cooldown/sample-rate/pan calculations and record trigger entry. The first actual playback/volume/pan-device boundary aborts by name; no buffers/devices are created. Music-selection RNG remains unchanged. Direct `rand()` voice stealing is inventoried but its recovered device routine is not linked. Proposed presentation RNG ownership below is not applied.
9. **Unsupported paths:** named aborts cover modes/quests outside this slice, pause, console activation, demo/tutorial/trial paths, persistence, preset loading, Windows key-name lookup, UI element callbacks, sound devices, unrelated state transitions and Grim slots absent from this closure. A successful compile does not prove all indirect/data dependencies are valid; linking the wider baseline does not authorize its other modes.

## Dependency closure

The closure is the existing verifier selection plus these added bodies. All 200 selected units compile and link. Runtime closure completes world/HUD rendering and tick 0, then stops at its first differing canonical field. Verifier return stubs remain unchanged. Client-only replacements remove the world/HUD/prompt/cursor stubs and call the recovered perk screen when a command requests it. Generated copies alone intercept Windows/device/callback boundaries. No recovered file is edited.

| Added source | Purpose |
| --- | --- |
| [terrain_render](../../decomp/1.9/crimsonland/ui_render/terrain_render.cpp) | Terrain/world pass |
| [hud_update_and_render](../../decomp/1.9/crimsonland/ui_render/hud_update_and_render.cpp) | HUD and gauges |
| [ui_render_hud](../../decomp/1.9/crimsonland/ui_render/ui_render_hud.cpp) | HUD and gauges |
| [bonus_hud_slot_update_and_render](../../decomp/1.9/crimsonland/ui_render/bonus_hud_slot_update_and_render.cpp) | HUD and gauges |
| [perk_prompt_update_and_render](../../decomp/1.9/crimsonland/game/perk_prompt_update_and_render.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [perk_selection_screen_update](../../decomp/1.9/crimsonland/game/perk_selection_screen_update.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_render_aim_indicators](../../decomp/1.9/crimsonland/game/ui_render_aim_indicators.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_render_aim_enhancement](../../decomp/1.9/crimsonland/ui_render/ui_render_aim_enhancement.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_draw_progress_bar](../../decomp/1.9/crimsonland/ui_render/ui_draw_progress_bar.cpp) | HUD and gauges |
| [ui_draw_textured_quad](../../decomp/1.9/crimsonland/ui_render/ui_draw_textured_quad.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_draw_clock_gauge_at](../../decomp/1.9/crimsonland/game/ui_draw_clock_gauge_at.cpp) | HUD and gauges |
| [ui_draw_clock_gauge](../../decomp/1.9/crimsonland/game/ui_draw_clock_gauge.cpp) | HUD and gauges |
| [ui_element_render](../../decomp/1.9/crimsonland/ui_elements/ui_element_render.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_element_update](../../decomp/1.9/crimsonland/ui_elements/ui_element_update.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_elements_max_timeline](../../decomp/1.9/crimsonland/ui_elements/ui_elements_max_timeline.c) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_elements_update_and_render](../../decomp/1.9/crimsonland/ui_render/ui_elements_update_and_render.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_menu_item_update](../../decomp/1.9/crimsonland/ui_widgets/ui_menu_item_update.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_button_update](../../decomp/1.9/crimsonland/ui_widgets/ui_button_update.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_cursor_render](../../decomp/1.9/crimsonland/ui_render/ui_cursor_render.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [input_key_name](../../decomp/1.9/crimsonland/game/input_key_name.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [sfx_play](../../decomp/1.9/crimsonland/audio/sfx_play.cpp) | Sound trigger only; device boundary aborts |
| [sfx_play_panned](../../decomp/1.9/crimsonland/audio/sfx_play_panned.cpp) | Sound trigger only; device boundary aborts |
| [ui_focus_draw](../../decomp/1.9/crimsonland/ui_widgets/ui_focus_draw.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_focus_set](../../decomp/1.9/crimsonland/ui_widgets/ui_focus_set.c) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_focus_update](../../decomp/1.9/crimsonland/ui_widgets/ui_focus_update.cpp) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_get_element_index](../../decomp/1.9/crimsonland/ui_elements/ui_get_element_index.c) | Perk/prompt, widget, focus, cursor and UI dependency |
| [ui_mouse_inside_rect](../../decomp/1.9/crimsonland/game/ui_mouse_inside_rect.c) | Perk/prompt, widget, focus, cursor and UI dependency |
| [console_register_cvar](../../decomp/1.9/crimsonland/console/console_register_cvar.cpp) | Original registration and allocation |
| [console_cvar_find](../../decomp/1.9/crimsonland/console/console_cvar_find.cpp) | Registration list lookup only |
| [register_core_cvars](../../decomp/1.9/crimsonland/game/register_core_cvars.cpp) | Original 13 defaults |
| [ui_menu_layout_init](../../decomp/1.9/crimsonland/menus/ui_menu_layout_init.cpp) | Only original table/default prefix; remainder aborts |
| [ui_element_init_defaults](../../decomp/1.9/crimsonland/menus/ui_element_init_defaults.cpp) | Original UI element defaults |

## Original setup restorations and cvar defaults

1. Link the unchanged `register_core_cvars`, `console_register_cvar` and its one list-lookup dependency, `console_cvar_find`. Call registration during client initialization after data reset, then apply `PortableConfig.friendly_fire` to the registered cvar (0 for this recording). The requested fallback is unnecessary; no console command or render subsystem is linked.
2. Expand only generated client cvar pointers and the registration-list storage for native pointer width. Generate a matching `cvar_float_t.value` offset and assert it equals `console_cvar_entry_t.value` (20 bytes on this host). Existing float-only readers now read the original registered values. The small `crt_atof_l` shim parses the numeric defaults with `strtod`; there is no verifier edit or replacement default.
3. The next tick-0 crash was `ui_element_table[0] == nullptr` at original `ui_elements_max_timeline.c:8`; LLDB identifies the call from `ui_elements_update_and_render`. Restore the original `ui_menu_layout_init` prefix, lines 265–331, containing table bindings and the 41-element defaults loop. It runs as `client_ui_table_defaults_init` during initialization after viewport configuration. Its asset/menu layout remainder stays outside this slice; calling `ui_menu_layout_init` aborts as `ui:menu-layout-assets`. This is a partial setup restoration, not a claim that menu/prompt geometry is ready.
4. Allocate all 42 UI records and the 41-pointer table at native width in generated client data; rebase its original table aliases. The separate prompt record remains at reset values until recovered prompt code runs. No callbacks or asset loading are enabled.

Every restoration is client-only. Initialization still agrees on the entire existing schema. The raw trace records these 13 defaults before applying the run configuration; [setup.json](../results/client-step1/setup.json) holds the defaults, comparisons and restored crash sites.

| Cvar | Original default text | Verifier hand-wired value | Match |
| --- | --- | --- | --- |
| `cv_silentloads` | `1` | Not wired | — |
| `cv_terrainFilter` | `1` | Not wired | — |
| `cv_bodiesFade` | `1` | 1 | Yes |
| `cv_uiTransparency` | `1` | Not wired | — |
| `cv_uiPointFilterPanels` | `0` | Not wired | — |
| `cv_enableMousePointAndClickMovement` | `0` | Not wired | — |
| `cv_verbose` | `0` | 0 | Yes |
| `cv_terrainBodiesTransparency` | `0` | 0.8 | **No** |
| `cv_uiSmallIndicators` | `0` | Not wired | — |
| `cv_aimEnhancementFade` | `0.7` | Not wired | — |
| `cv_friendlyFire` | `0` | PortableConfig (0 here) | Run override after registration |
| `cv_showFPS` | `0` | Not wired | — |
| `cv_padAimDistMul` | `96` | 128 | **No** |

`cv_terrainBodiesTransparency` (verifier 0.8, original 0) and `cv_padAimDistMul` (verifier 128, original 96) are verifier-default findings. `cv_bodiesFade` (1) and `cv_verbose` (0) match. These cvars are outside the current snapshot schema; the default mismatches are not being reported as a proven cause of the tick-0 field difference. The verifier is unchanged.

## Every observed divergence or blocker

| Evidence | First differing tick | Observation |
| --- | --- | --- |
| Initialization full state | None | All 36,343 fields agree. |
| `globals.player_weapon_popup_timer[0]` | **0** | Client 1.9766666889190674 (`0x3ffd036a`) versus verifier 2.0 (`0x40000000`); recovered `ui_render_hud.cpp:779–780` subtracts `frame_dt * 1.4f`. |
| Other full-state fields | None through tick 0 | All other 36,342 words agree, including RNG, health, experience, effects, pools and pending state. |
| Out-of-scope RNG | None observed | Startup draws are inside `portable_init`; the only tick-0 draw is the existing host tail. |
| Later ticks / terminal client `RunResult` | Unavailable | Input stops before tick 1 on the first differing snapshot; no terminal client result is manufactured from the prefix. |

The HUD timer is already a canonical schema field. Its mutation proves that this recovered rendering path changes verifier-compared state, even though this one tick shows no RNG, health or experience difference. No timer ownership decision, relocation or fix is made. See [divergence.json](../results/client-step1/divergence.json) for exact bits and source attribution, and [replay.json](../results/client-step1/replay.json) for all differences at the stopping boundary.

The comparator sends initialization and each tick only after comparing the previous snapshot. It closes input at the first differing boundary, so later client ticks do not execute. The verifier separately finishes its full reference stream; that is not a complete client comparison. The earlier full-stream negative control still finds both transient RNG and health differences at their first ticks, and the new stop control halts at its first planted RNG difference (tick 1) without sending tick 2.

### Observed slot and RNG usage

Initialization logs 6,861 Grim calls and 10,594 RNG draws: `gameplay_reset_state` 386, `terrain_generate_random` 5,106, `terrain_generate` 5,100, `quest_start_selected` 1 and the host init tail 1. It also logs two guarded `sfx_play_panned` triggers. Tick 0 logs 368 Grim calls and one host-tail RNG draw. There are 30 distinct observed slots across initialization and tick 0.

`grim_measure_text_width` is not reached before the stop. Its statically consumed headless result remains 0. The perk screen and its second world pass are also not reached. Font metrics and duplicate world work remain unresolved leads, not additional confirmed differences.

| Phase | Slot | Calls | Return read (static flag) |
| --- | --- | --- | --- |
| portable_init | `grim_begin_batch` | 6 | False |
| portable_init | `grim_bind_texture` | 6 | False |
| portable_init | `grim_clear_color` | 2 | False |
| portable_init | `grim_draw_quad_xy` | 3400 | False |
| portable_init | `grim_end_batch` | 6 | False |
| portable_init | `grim_get_config_var` | 1 | True |
| portable_init | `grim_get_texture_handle` | 6 | True |
| portable_init | `grim_set_color` | 8 | False |
| portable_init | `grim_set_config_var` | 20 | False |
| portable_init | `grim_set_render_target` | 4 | False |
| portable_init | `grim_set_rotation` | 3400 | False |
| portable_init | `grim_set_uv` | 2 | False |
| tick_0 | `grim_begin_batch` | 37 | False |
| tick_0 | `grim_bind_texture` | 37 | False |
| tick_0 | `grim_draw_circle_filled` | 1 | False |
| tick_0 | `grim_draw_circle_outline` | 1 | False |
| tick_0 | `grim_draw_fullscreen_quad` | 1 | False |
| tick_0 | `grim_draw_quad` | 31 | False |
| tick_0 | `grim_draw_rect_filled` | 4 | False |
| tick_0 | `grim_draw_text_mono` | 1 | False |
| tick_0 | `grim_draw_text_mono_fmt` | 1 | False |
| tick_0 | `grim_draw_text_small` | 1 | False |
| tick_0 | `grim_draw_text_small_fmt` | 5 | False |
| tick_0 | `grim_end_batch` | 38 | False |
| tick_0 | `grim_get_texture_handle` | 3 | True |
| tick_0 | `grim_is_key_active` | 5 | True |
| tick_0 | `grim_is_key_down` | 2 | True |
| tick_0 | `grim_is_mouse_button_down` | 1 | True |
| tick_0 | `grim_set_atlas_frame` | 8 | False |
| tick_0 | `grim_set_color` | 46 | False |
| tick_0 | `grim_set_color_ptr` | 1 | False |
| tick_0 | `grim_set_color_slot` | 4 | False |
| tick_0 | `grim_set_config_var` | 79 | False |
| tick_0 | `grim_set_rotation` | 21 | False |
| tick_0 | `grim_set_sub_rect` | 2 | False |
| tick_0 | `grim_set_uv` | 35 | False |
| tick_0 | `grim_submit_vertices_transform` | 2 | False |
| tick_0 | `grim_was_key_pressed` | 1 | True |

Verifier full `RunResult`:

```json
{
  "outcome": "quest_completed",
  "elapsed_ms": 20112,
  "kills": 10,
  "shots_fired": 44,
  "shots_hit": 14,
  "rng_state": 1430815715,
  "pending_perks": 0,
  "quest_final_ms": 15112,
  "players": [
    {
      "experience": 1250,
      "health": 100.0,
      "most_used_weapon_id": 1
    }
  ]
}
```

## Grim slot table and proposed dispositions

Offsets are original 32-bit vtable offsets, not native pointer strides. `read` is a conservative static flag for a non-void result used in an expression in the selected recovered sources. It is attached to every recorded invocation of that slot; it does not imply every invocation reads the result or that the result is authoritative. `used` means static closure use, not replay coverage. Thirty slots were observed across initialization and completed tick 0; exact counts are above. The 41-slot probe calls the recording implementation directly and is not recovered render evidence.

| Slot / offset | Method | Return | Used | Read | Proposed disposition |
| --- | --- | --- | --- | --- | --- |
| 0 / 0x000 | `grim_release` | `void` | False | False | Outside slice: named abort |
| 1 / 0x004 | `grim_set_paused` | `void` | False | False | Outside slice: named abort |
| 2 / 0x008 | `grim_get_version` | `float` | False | False | Outside slice: named abort |
| 3 / 0x00c | `grim_save_screenshot` | `bool` | False | False | Outside slice: named abort |
| 4 / 0x010 | `grim_apply_config` | `bool` | False | False | Outside slice: named abort |
| 5 / 0x014 | `grim_init_system` | `bool` | False | False | Outside slice: named abort |
| 6 / 0x018 | `grim_shutdown` | `void` | False | False | Outside slice: named abort |
| 7 / 0x01c | `grim_apply_settings` | `bool` | False | False | Outside slice: named abort |
| 8 / 0x020 | `grim_set_config_var` | `void` | True | False | Ordered graphics configuration and query state |
| 9 / 0x024 | `grim_get_config_var` | `grim_config_value_t` | True | True | Original table setup query; sentinel 0 retained, resource/config contract unresolved |
| 10 / 0x028 | `grim_get_error_text` | `char *` | False | False | Outside slice: named abort |
| 11 / 0x02c | `grim_clear_color` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 12 / 0x030 | `grim_set_render_target` | `bool` | True | False | Ordered persistent target switch; specify success/failure result |
| 13 / 0x034 | `grim_get_time_ms` | `int` | False | False | Outside slice: named abort |
| 14 / 0x038 | `grim_set_time_ms` | `void` | False | False | Outside slice: named abort |
| 15 / 0x03c | `grim_get_frame_dt` | `float` | False | False | Outside slice: named abort |
| 16 / 0x040 | `grim_get_fps` | `float` | False | False | Outside slice: named abort |
| 17 / 0x044 | `grim_is_key_down` | `unsigned char` | True | True | Normalized input/query contract; baseline mapping only |
| 18 / 0x048 | `grim_was_key_pressed` | `bool` | True | True | Normalized input/query contract; baseline mapping only |
| 19 / 0x04c | `grim_flush_input` | `void` | True | False | Session boundary side effect; audit command ordering |
| 20 / 0x050 | `grim_get_key_char` | `int` | False | False | Outside slice: named abort |
| 21 / 0x054 | `grim_set_key_char_buffer` | `void` | False | False | Outside slice: named abort |
| 22 / 0x058 | `grim_is_mouse_button_down` | `unsigned char` | True | True | Normalized input/query contract; baseline mapping only |
| 23 / 0x05c | `grim_was_mouse_button_pressed` | `bool` | False | False | Outside slice: named abort |
| 24 / 0x060 | `grim_get_mouse_wheel_delta` | `float` | False | False | Outside slice: named abort |
| 25 / 0x064 | `grim_set_mouse_pos` | `void` | False | False | Outside slice: named abort |
| 26 / 0x068 | `grim_get_mouse_x` | `float` | False | False | Outside slice: named abort |
| 27 / 0x06c | `grim_get_mouse_y` | `float` | False | False | Outside slice: named abort |
| 28 / 0x070 | `grim_get_mouse_dx` | `float` | False | False | Outside slice: named abort |
| 29 / 0x074 | `grim_get_mouse_dy` | `float` | False | False | Outside slice: named abort |
| 30 / 0x078 | `grim_get_mouse_dx_indexed` | `float` | False | False | Outside slice: named abort |
| 31 / 0x07c | `grim_get_mouse_dy_indexed` | `float` | False | False | Outside slice: named abort |
| 32 / 0x080 | `grim_is_key_active` | `unsigned char` | True | True | Normalized input/query contract; baseline mapping only |
| 33 / 0x084 | `grim_get_config_float` | `float` | True | True | Normalized input/query contract; baseline mapping only |
| 34 / 0x088 | `grim_get_slot_float` | `float` | False | False | Outside slice: named abort |
| 35 / 0x08c | `grim_get_slot_int` | `int` | False | False | Outside slice: named abort |
| 36 / 0x090 | `grim_set_slot_float` | `void` | False | False | Outside slice: named abort |
| 37 / 0x094 | `grim_set_slot_int` | `void` | False | False | Outside slice: named abort |
| 38 / 0x098 | `grim_get_joystick_x` | `int` | False | False | Outside slice: named abort |
| 39 / 0x09c | `grim_get_joystick_y` | `int` | False | False | Outside slice: named abort |
| 40 / 0x0a0 | `grim_get_joystick_z` | `int` | False | False | Outside slice: named abort |
| 41 / 0x0a4 | `grim_get_joystick_pov` | `int` | True | True | Normalized input/query contract; baseline mapping only |
| 42 / 0x0a8 | `grim_is_joystick_button_down` | `unsigned char` | False | False | Outside slice: named abort |
| 43 / 0x0ac | `grim_create_texture` | `bool` | False | False | Outside slice: named abort |
| 44 / 0x0b0 | `grim_recreate_texture` | `bool` | False | False | Outside slice: named abort |
| 45 / 0x0b4 | `grim_load_texture` | `bool` | False | False | Outside slice: named abort |
| 46 / 0x0b8 | `grim_save_texture` | `bool` | False | False | Outside slice: named abort |
| 47 / 0x0bc | `grim_destroy_texture` | `void` | False | False | Outside slice: named abort |
| 48 / 0x0c0 | `grim_get_texture_handle` | `int` | True | True | Stable manifest IDs; preserve baseline 1 for this evidence |
| 49 / 0x0c4 | `grim_bind_texture` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 50 / 0x0c8 | `grim_draw_fullscreen_quad` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 51 / 0x0cc | `grim_draw_fullscreen_color` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 52 / 0x0d0 | `grim_draw_rect_filled` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 53 / 0x0d4 | `grim_draw_rect_outline` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 54 / 0x0d8 | `grim_draw_circle_filled` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 55 / 0x0dc | `grim_draw_circle_outline` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 56 / 0x0e0 | `grim_draw_line` | `void` | False | False | Outside slice: named abort |
| 57 / 0x0e4 | `grim_draw_line_quad` | `void` | False | False | Outside slice: named abort |
| 58 / 0x0e8 | `grim_begin_batch` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 59 / 0x0ec | `grim_flush_batch` | `void` | False | False | Outside slice: named abort |
| 60 / 0x0f0 | `grim_end_batch` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 61 / 0x0f4 | `grim_submit_vertex_raw` | `void` | False | False | Outside slice: named abort |
| 62 / 0x0f8 | `grim_submit_quad_raw` | `void` | False | False | Outside slice: named abort |
| 63 / 0x0fc | `grim_set_rotation` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 64 / 0x100 | `grim_set_uv` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 65 / 0x104 | `grim_set_atlas_frame` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 66 / 0x108 | `grim_set_sub_rect` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 67 / 0x10c | `grim_set_uv_point` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 68 / 0x110 | `grim_set_color_ptr` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 69 / 0x114 | `grim_set_color` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 70 / 0x118 | `grim_set_color_slot` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 71 / 0x11c | `grim_draw_quad` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 72 / 0x120 | `grim_draw_quad_xy` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 73 / 0x124 | `grim_draw_quad_rotated_matrix` | `void` | False | False | Outside slice: named abort |
| 74 / 0x128 | `grim_submit_vertices_transform` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 75 / 0x12c | `grim_submit_vertices_offset` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 76 / 0x130 | `grim_submit_vertices_offset_color` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 77 / 0x134 | `grim_submit_vertices_transform_color` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 78 / 0x138 | `grim_draw_quad_points` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 79 / 0x13c | `grim_draw_text_mono` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 80 / 0x140 | `grim_draw_text_mono_fmt` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 81 / 0x144 | `grim_draw_text_small` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 82 / 0x148 | `grim_draw_text_small_fmt` | `void` | True | False | Record ordered presentation operation; future owned renderer |
| 83 / 0x14c | `grim_measure_text_width` | `int` | True | True | Shared font metrics; audit hit geometry; baseline 0 unproven |

## Rand caller table and proposed ownership

All 64 recovered `crt_rand` caller files and the separate direct-`rand()` playback caller are listed below, including those outside the client link. Precise call expressions and compiled callsites are regenerated in `build/client/evidence/inventory.json`; the generated inventory is not committed. Linked callers keep the existing shared LCG and consumption order; presentation classification is only a proposal for later review. Rendering, camera shake and sound-selection draws already in the baseline are retained authoritative, regardless of their visual names. A file-level proposal is not a read/write or noninterference proof.

| Caller | Recovered lines | Linked | Proposed class / evidence |
| --- | --- | --- | --- |
| [music_play_exclusive.cpp](../../decomp/1.9/crimsonland/audio/music_play_exclusive.cpp) | 20 | True | Authoritative: retain current verifier LCG |
| [bonus_spawn_at.cpp](../../decomp/1.9/crimsonland/crimsonland/bonus_spawn_at.cpp) | 54, 55, 56, 57 | True | Authoritative: retain current verifier LCG |
| [bonus_spawn_at_pos.cpp](../../decomp/1.9/crimsonland/crimsonland/bonus_spawn_at_pos.cpp) | 35 | True | Authoritative: retain current verifier LCG |
| [bonus_try_spawn_on_kill.cpp](../../decomp/1.9/crimsonland/crimsonland/bonus_try_spawn_on_kill.cpp) | 21, 48, 51, 55, 104, 105, 106, 107 | True | Authoritative: retain current verifier LCG |
| [creature_alloc_slot.c](../../decomp/1.9/crimsonland/crimsonland/creature_alloc_slot.c) | 10 | True | Authoritative: retain current verifier LCG |
| [creature_apply_damage.cpp](../../decomp/1.9/crimsonland/crimsonland/creature_apply_damage.cpp) | 68, 81, 109, 111, 113, 115, 124 | True | Authoritative: retain current verifier LCG |
| [creature_handle_death.c](../../decomp/1.9/crimsonland/crimsonland/creature_handle_death.c) | 57, 69, 123, 129 | True | Authoritative: retain current verifier LCG |
| [creature_spawn.c](../../decomp/1.9/crimsonland/crimsonland/creature_spawn.c) | 45, 48 | True | Authoritative: retain current verifier LCG |
| [creature_update_all.cpp](../../decomp/1.9/crimsonland/crimsonland/creature_update_all.cpp) | 166, 175, 250, 621, 660, 753, 760, 767 | True | Authoritative: retain current verifier LCG |
| [fx_queue_add_random.cpp](../../decomp/1.9/crimsonland/crimsonland/fx_queue_add_random.cpp) | 42, 45, 46, 50 | True | Authoritative: retain current verifier LCG |
| [fx_spawn_particle.cpp](../../decomp/1.9/crimsonland/crimsonland/fx_spawn_particle.cpp) | 26, 41 | True | Authoritative: retain current verifier LCG |
| [fx_spawn_particle_slow.cpp](../../decomp/1.9/crimsonland/crimsonland/fx_spawn_particle_slow.cpp) | 25, 40 | True | Authoritative: retain current verifier LCG |
| [fx_spawn_sprite.c](../../decomp/1.9/crimsonland/crimsonland/fx_spawn_sprite.c) | 14, 25 | True | Authoritative: retain current verifier LCG |
| [highscore_sync_worker.cpp](../../decomp/1.9/crimsonland/crimsonland/highscore_sync_worker.cpp) | 105 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [particle_pool_global_init.cpp](../../decomp/1.9/crimsonland/crimsonland/particle_pool_global_init.cpp) | 26 | False | Presentation candidate: particle/menu/UI initialization; outside slice |
| [player_take_damage.cpp](../../decomp/1.9/crimsonland/crimsonland/player_take_damage.cpp) | 44, 49, 56, 118, 124, 135, 143 | True | Authoritative: retain current verifier LCG |
| [projectile_update.cpp](../../decomp/1.9/crimsonland/crimsonland/projectile_update.cpp) | 215, 225, 256, 268, 287, 288, 299, 300, 320, 456, 464, 466, 469, 481, 490, 503, 508, 558, 703, 708, 709, 718, 719, 728, 729, 776, 782, 783, 804, 810, 811, 832, 838, 839, 856, 941, 949, 958, 967, 1027, 1049, 1051 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_blood_splatter.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_blood_splatter.cpp) | 29, 31, 36, 38, 41 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_burst.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_burst.cpp) | 16, 17, 18, 20 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_explosion_burst.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_explosion_burst.cpp) | 48, 81, 83, 85, 87, 89 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_freeze_shard.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_freeze_shard.cpp) | 14, 21, 23, 30, 32, 34 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_freeze_shatter.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_freeze_shatter.cpp) | 22, 26, 34 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_ion_hit_sparks.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_ion_hit_sparks.cpp) | 38, 40, 42, 44 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_shrinkifier_hit.cpp](../../decomp/1.9/crimsonland/effects/effect_spawn_shrinkifier_hit.cpp) | 39, 41, 43, 45 | True | Authoritative: retain current verifier LCG |
| [effect_spawn_splitter_hit_burst.c](../../decomp/1.9/crimsonland/effects/effect_spawn_splitter_hit_burst.c) | 23, 29, 32 | True | Authoritative: retain current verifier LCG |
| [bonus_apply.cpp](../../decomp/1.9/crimsonland/game/bonus_apply.cpp) | 106, 110, 220, 224, 229, 237, 242, 292, 293, 294 | True | Authoritative: retain current verifier LCG |
| [camera_update.cpp](../../decomp/1.9/crimsonland/game/camera_update.cpp) | 22, 23, 24, 31, 32, 33 | True | Authoritative: retain current verifier LCG |
| [demo_setup_variant_1.cpp](../../decomp/1.9/crimsonland/game/demo_setup_variant_1.cpp) | 19, 20, 29, 30 | False | Authoritative candidate: unsupported demo simulation |
| [demo_setup_variant_3.cpp](../../decomp/1.9/crimsonland/game/demo_setup_variant_3.cpp) | 19, 20, 29, 30 | False | Authoritative candidate: unsupported demo simulation |
| [game_frame_update.cpp](../../decomp/1.9/crimsonland/game/game_frame_update.cpp) | 427, 444, 452 | False | Mixed: authoritative frame draw at 427; presentation candidates at 444/452 |
| [perk_apply.cpp](../../decomp/1.9/crimsonland/game/perk_apply.cpp) | 33, 125 | True | Authoritative: retain current verifier LCG |
| [perks_generate_choices.c](../../decomp/1.9/crimsonland/game/perks_generate_choices.c) | 88 | True | Authoritative: retain current verifier LCG |
| [perks_update_effects.cpp](../../decomp/1.9/crimsonland/game/perks_update_effects.cpp) | 41, 127, 132, 137, 142, 147, 172, 179, 187, 192 | True | Authoritative: retain current verifier LCG |
| [survival_spawn_creature.cpp](../../decomp/1.9/crimsonland/game/survival_spawn_creature.cpp) | 30, 50, 66, 70, 76, 86, 109, 112, 120, 125, 134, 139, 152, 158, 163, 168, 175, 181 | True | Authoritative: retain current verifier LCG |
| [survival_update.cpp](../../decomp/1.9/crimsonland/game/survival_update.cpp) | 222, 226, 235, 244, 253, 269, 273, 282, 291, 300 | True | Authoritative: retain current verifier LCG |
| [bonus_pick_random_type.cpp](../../decomp/1.9/crimsonland/gameplay/bonus_pick_random_type.cpp) | 16, 27 | True | Authoritative: retain current verifier LCG |
| [game_status_global_init.cpp](../../decomp/1.9/crimsonland/gameplay/game_status_global_init.cpp) | 23, 24, 25, 26 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [gameplay_reset_state.cpp](../../decomp/1.9/crimsonland/gameplay/gameplay_reset_state.cpp) | 266, 310, 334 | True | Authoritative: retain current verifier LCG |
| [gameplay_run_state_init.c](../../decomp/1.9/crimsonland/gameplay/gameplay_run_state_init.c) | 12 | True | Authoritative: retain current verifier LCG |
| [highscore_init_sentinels.c](../../decomp/1.9/crimsonland/gameplay/highscore_init_sentinels.c) | 17 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [player_update_heading.cpp](../../decomp/1.9/crimsonland/gameplay/player_update_heading.cpp) | 273, 312, 320, 378, 379, 415, 451, 1132, 1134, 1145, 1151, 1174, 1175, 1216, 1247, 1371, 1378, 1394, 1401, 1431, 1438, 1608, 1615, 1653, 1660, 1805, 1812 | True | Authoritative: retain current verifier LCG |
| [highscore_load_table.c](../../decomp/1.9/crimsonland/highscore/highscore_load_table.c) | 35 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [highscore_record_init.c](../../decomp/1.9/crimsonland/highscore/highscore_record_init.c) | 24 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [highscore_update_record.c](../../decomp/1.9/crimsonland/highscore/highscore_update_record.c) | 24 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [highscore_write_record.c](../../decomp/1.9/crimsonland/highscore/highscore_write_record.c) | 26 | False | Presentation/persistence candidate: tags/seeds; outside slice |
| [credits_secret_alien_zookeeper_update.cpp](../../decomp/1.9/crimsonland/mods/credits_secret_alien_zookeeper_update.cpp) | 277, 291 | False | Presentation candidate: particle/menu/UI initialization; outside slice |
| [perk_select_random.c](../../decomp/1.9/crimsonland/perks/perk_select_random.c) | 10 | True | Authoritative: retain current verifier LCG |
| [creature_spawn_template.cpp](../../decomp/1.9/crimsonland/quests/creature_spawn_template.cpp) | 154, 160, 190, 206, 530, 544, 558, 566, 574, 582, 586, 590, 598, 602, 606, 614, 618, 622, 630, 634, 638, 646, 650, 656, 665, 681, 697, 709, 725, 730, 739, 883, 921, 932, 943 | True | Authoritative: retain current verifier LCG |
| [quest_build_deja_vu.cpp](../../decomp/1.9/crimsonland/quests/quest_build_deja_vu.cpp) | 41 | True | Authoritative: retain current verifier LCG |
| [quest_build_sweep_stakes.cpp](../../decomp/1.9/crimsonland/quests/quest_build_sweep_stakes.cpp) | 39 | True | Authoritative: retain current verifier LCG |
| [quest_build_target_practice.cpp](../../decomp/1.9/crimsonland/quests/quest_build_target_practice.cpp) | 51, 52 | True | Authoritative: retain current verifier LCG |
| [quest_build_the_killing.cpp](../../decomp/1.9/crimsonland/quests/quest_build_the_killing.cpp) | 20, 30, 69, 70, 77, 78, 85, 86 | True | Authoritative: retain current verifier LCG |
| [quest_build_the_random_factor.cpp](../../decomp/1.9/crimsonland/quests/quest_build_the_random_factor.cpp) | 49 | True | Authoritative: retain current verifier LCG |
| [quest_start_selected.cpp](../../decomp/1.9/crimsonland/quests/quest_start_selected.cpp) | 46 | True | Authoritative: retain current verifier LCG |
| [sfx_entry_start_playback.cpp](../../decomp/1.9/crimsonland/sound/sfx_entry_start_playback.cpp) | 45 | False | Presentation candidate: device-dependent voice stealing; direct rand() |
| [creature_spawn_tinted.c](../../decomp/1.9/crimsonland/typo/creature_spawn_tinted.c) | 31, 39 | False | Authoritative candidate: unsupported gameplay |
| [typo_gameplay_update_and_render.cpp](../../decomp/1.9/crimsonland/typo/typo_gameplay_update_and_render.cpp) | 123, 136 | False | Authoritative candidate: unsupported gameplay |
| [typo_player_update.cpp](../../decomp/1.9/crimsonland/typo/typo_player_update.cpp) | 136, 137, 212, 219 | False | Authoritative candidate: unsupported gameplay |
| [typo_target_name_assign_random.cpp](../../decomp/1.9/crimsonland/typo/typo_target_name_assign_random.cpp) | 15, 22, 35, 43, 51, 58 | False | Authoritative candidate: unsupported gameplay |
| [typo_word_pick_fragment.cpp](../../decomp/1.9/crimsonland/typo/typo_word_pick_fragment.cpp) | 11 | False | Authoritative candidate: unsupported gameplay |
| [typo_word_pick_highscore_name.cpp](../../decomp/1.9/crimsonland/typo/typo_word_pick_highscore_name.cpp) | 59 | False | Authoritative candidate: unsupported gameplay |
| [terrain_generate.cpp](../../decomp/1.9/crimsonland/ui_render/terrain_generate.cpp) | 62, 64, 65, 85, 87, 88, 108, 110, 111 | True | Authoritative: retain current verifier LCG |
| [terrain_generate_random.cpp](../../decomp/1.9/crimsonland/ui_render/terrain_generate_random.cpp) | 47, 48, 49, 60, 65, 70, 98, 100, 101, 120, 122, 123, 142, 144, 145 | True | Authoritative: retain current verifier LCG |
| [ui_text_input_update.cpp](../../decomp/1.9/crimsonland/ui_widgets/ui_text_input_update.cpp) | 86 | False | Presentation candidate: particle/menu/UI initialization; outside slice |
| [weapon_pick_random_available.cpp](../../decomp/1.9/crimsonland/weapons/weapon_pick_random_available.cpp) | 7, 10, 12 | True | Authoritative: retain current verifier LCG |
| `host/host.cpp::portable_init` | Bootstrap tail `crt_rand()` | Client-generated host | Authoritative run-start draw; authorized by initialization scope; observed once |
| `host/host.cpp::portable_step_many` | Tick tail `crt_rand()` | Client-generated host | Authoritative baseline frame draw; inside tick |

The setup-restored replay reports no out-of-scope RNG caller through completed tick 0. Startup draws listed above are observed authoritative work. The standalone guard probe still aborts outside initialization/ticks. Static entries must not be presented as observed presentation callers.

## Reproduce

```sh
uv run --no-sync python crimson-core/build.py --target client
uv run --no-sync python crimson-core/checks/client_evidence.py
# Expected exit 1: first canonical difference at tick 0; stop before tick 1.
# --before path/to/hashes.json records native/wasm identity against your captured baseline.
node crimson-core/checks/matrix.mjs
uv run --no-sync python crimson-core/checks/gate.py --jobs 8
```

Do not rebuild the native verifier when checking preservation of an existing executable: copy/hash it first. The client build never needs to rebuild either verifier. Compact setup/divergence JSON, call summaries, guard controls and baseline equality are checked in under [results/client-step1](../results/client-step1/). The existing ranked fixture is `tests/fixtures/replays/quest-1.1-completed.crd`; `results/gate.json` identifies it. The full call trace, generated inventory and private `.rsi` stream are produced on demand under `build/client/evidence`; `.rsi` contains no claimed result.

Run-start ownership is resolved and the earlier native metadata exception is accepted. Original cvar registration and the minimum original table/default stage are restored. The first canonical state divergence is reported at tick 0 and remains unfixed. Review it before continuing; font metrics and the possible duplicate world pass still lack later replay evidence. This PR remains a draft.

The client CI step and client artifact uploads were removed. `checks/client_contract.py` remains a local tool that validates instrumentation, verifier preservation and the comparator control while reporting the actual replay result; it no longer asserts a particular failure. No client build was added to the ordinary core CI run.
