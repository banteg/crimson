---
tags:
  - status-draft
---

# In-game console (tilde)

Crimsonland includes a developer-style console that appears in-game and accepts
commands and cvar assignments. This page summarizes the static findings that
back the tilde/backquote console behavior.

## Open / close (runtime)

- The console is toggled in-game with the tilde/backquote key (`~` / `` ` ``).
- The open flag is `console_open_flag` (`0x0047eec8`); when set, many gameplay
  update loops early‑out and input is redirected to the console.
- `console_set_open` (`0x004018b0`) sets the open flag and toggles input capture:
  - Writes `console_open_flag` (`0x0047eec8`) via the console state struct.
  - Writes `console_input_enabled` (`0x0047f4d4`).
  - Calls Grim2D vtable `+0x4c` to flush input.
- Runtime capture shows the tilde hotkey path calls `console_set_open` from
  `0x0040c39a` (call stack: `0x0040c39a -> console_set_open -> DINPUT8::GetDeviceState -> grim`).
- The containing per-frame input/update function starts at `0x0040c1c0`
  (no EBP frame; begins with `sub esp, 0x28`).

#### Hotkey check (runtime)

The hotkey check is performed via Grim2D key polling:

```
0040c36d 6a29            push    29h              ; DIK_GRAVE
0040c37d ff5248          call    dword ptr [edx+48h]  ; grim key-down check
0040c380 84c0            test    al,al
0040c382 7416            je      0040c39a
0040c384 8a15c8ee4700    mov     dl,[console_open_flag]
0040c38f 3ad3            cmp     dl,bl
0040c391 0f94c0          sete    al               ; al = (open_flag == 0)
0040c394 50              push    eax
0040c395 e81655ffff      call    console_set_open
```

Additional context:

- The hotkey check sits inside a larger per-frame input/update block that also polls
  `DIK_F12 (0x58)`.
- The block is gated by `audio_suspend_flag` (`0x004aaf84`): when non-zero it calls
  `audio_resume_all` (`0x0042a5f0`) and returns early (skipping the tilde toggle).

## Input handling (static)

- Text input is polled via Grim2D `get_key_char` (vtable `+0x50`) in
  `console_input_poll` (`0x00401060`).
- Enter (`0x0d`) sets `console_input_ready` and NUL-terminates the buffer.
- Backspace (`0x08`) deletes one char.
- The input buffer is capped at `0x3ff` chars.
- Navigation/selection keys are handled in the console update loop
  (`0x00401a40`) via Grim2D key checks (vtable `+0x44` and `+0x48`):
  - Up/Down (`0xC8` / `0xD0`) browse history.
  - Left/Right (`0xCB` / `0xCD`) move the caret.
  - PageUp/PageDown (`0xC9` / `0xD1`) adjust scroll.
  - Home (`0xC7`) and End (`0xCF`) jump to start/end.
  - Tab (`0x0F`) triggers autocomplete (cvars first, then commands).
  - Ctrl (`0x1D` / `0x9D`) modifies some history/scroll actions.

Relevant globals (see `analysis/ghidra/maps/data_map.json`):
- `console_input_enabled` (`0x0047f4d4`)
- `console_input_ready` (`0x0047ea58`)
- `console_input_buffer` (`0x0047e448`) + length (`0x0047ea54`)
- `console_prompt_string` (`0x004712c0`, prompt format `"> %s"`)
- `console_height_px` (`0x0047eeb8`)

## Command / cvar dispatch (static)

`console_exec_line` (`0x00401940`) tokenizes the input and then:

1) If the first token matches a cvar, it either:
   - Prints current value when invoked with no value.
   - Updates the value when called with exactly one argument (parses float and
     stores both string + float).
2) Else if the token matches a command, it calls the command handler.
3) Otherwise it prints `Unknown command "%s"`.

The cvar paths emit:
- `"%s" is "%s" (%ff)`
- `"%s" set to "%s" (%ff)`

## Built-in commands (static registration)

`console_init` (`0x00401560`) registers the core commands below. The handlers have been mapped:

- `cmdlist` → `console_cmdlist` (`0x00401370`): prints each command name and
  a summary line (`"%i commands"`).
- `vars` → `console_vars` (`0x004013c0`): prints each cvar name and a summary
  line (`"%i variables"`).
- `set` → `console_cmd_set` (`0x00401510`): expects 2 args (`set <var> <value>`);
  otherwise prints usage. Uses `console_register_cvar` and prints
  `"'%s' set to '%s'"`.
- `echo` → `console_echo` (`0x00401410`): `echo on` / `echo off` toggles
  `console_echo_enabled`; otherwise prints args back to the console.
- `quit` → `console_cmd_quit` (`0x00401240`): sets the quit flag (`0x0047ea50`).
- `clear` → `console_clear_log` (`0x004011a0`): clears the console log list and
  resets scroll state.
- `extendconsole` → `console_cmd_extend` (`0x00401340`): sets
  `console_height_px` (`0x0047eeb8`) to ~480.
- `minimizeconsole` → `console_cmd_minimize` (`0x00401360`): sets
  `console_height_px` (`0x0047eeb8`) to 300.
- `exec` → `console_cmd_exec` (`0x00401250`): loads a script file and feeds each
  line into `console_exec_line`; prints `Executing '%s'` or a “cannot open”
  error.

## Startup commands (registered in crimsonland_main)

`crimsonland_main` registers several additional commands during startup:

- `setGammaRamp` → `console_cmd_set_gamma_ramp` (`0x0042c3d0`).
- `snd_addGameTune` → `console_cmd_snd_add_game_tune` (`0x0042c360`).
- `generateterrain` → `console_cmd_generate_terrain` (`0x0042a970`).
- `telltimesurvived` → `console_cmd_tell_time_survived` (`0x0042a860`).
- `setresourcepaq` → `console_cmd_set_resource_paq` (`0x0042a7c0`).
- `loadtexture` → `console_cmd_load_texture` (`0x0042a780`).
- `openurl` → `console_cmd_open_url` (`0x0042a890`).
- `sndfreqadjustment` → `console_cmd_snd_freq_adjustment` (`0x0042a930`).

## Known console variables (cvars)

Core cvars are registered in `register_core_cvars` (`0x00402c00`) and during startup.
These can be used for debugging or tweaking engine behavior:

| Cvar | Role (inferred) |
| --- | --- |
| `cv_showFPS` | Displays framerate counter |
| `cv_verbose` | Enables verbose logging (useful for debugging) |
| `cv_friendlyFire` | Toggles friendly fire |
| `cv_silentloads` | Suppress loading screen text/transitions |
| `cv_bodiesFade` | Controls corpse fading time |
| `cv_terrainBodiesTransparency` | Controls corpse transparency on terrain |
| `cv_terrainFilter` | Texture filtering setting for terrain |
| `cv_uiTransparency` | HUD transparency |
| `cv_uiPointFilterPanels` | UI filtering mode |
| `cv_uiSmallIndicators` | Use smaller UI elements |
| `cv_enableMousePointAndClickMovement` | Click-to-move (accessibility/debug) |
| `cv_aimEnhancementFade` | Aim assist visual feedback |
| `cv_padAimDistMul` | Gamepad aiming sensitivity/distance |
| `v_width` | Viewport width (registered after autoexec) |
| `v_height` | Viewport height (registered after autoexec) |

## Scripts and logs

- `exec` is used to run scripts such as `autoexec.txt` and
  `music\\game_tunes.txt`.
- Console output can be flushed to `console.log` via `console_flush_log`
  (`0x00402860`), which uses `game_build_path` to resolve the filename.

## Open questions

- None for the console hotkey path right now; the function entry at `0x0040c1c0`
  is confirmed in WinDbg.
