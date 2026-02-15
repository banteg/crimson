---
tags:
  - frida
  - layout
  - status-validation
---

# Panel state resolution sweep

`scripts/frida/panel_state_resolution_sweep.js` is the capture script for issue
`#165` ("support all resolutions").

It automates panel/text capture per launcher resolution:

1. Force known panel-heavy states via `game_state_set`.
2. Capture UI element geometry (`ui_element_render`) and text draws
   (`grim_draw_text_mono` / `grim_draw_text_small`) in each state.
3. Write one log file per active resolution.

Default sweep targets:

- `0,1,2,3,4,11,14,15,16,17,20,26,5,6,7,8,12,21`

These cover menu and panel states while skipping known non-panel/unsafe states
like quit transition (`10`) and plugin runtime (`22`).

## Attach flow

1. Start launcher and choose a resolution.
2. Attach the script.
3. Press "Start Game".
4. Wait for `sweep_done` in the log.

Attach command:

```text
frida -n crimsonland.exe -l C:\share\frida\panel_state_resolution_sweep.js
```

Just shortcut (Windows VM):

```text
just frida-panel-state-resolution-sweep
```

## Output

Default directory: `C:\share\frida` (override with `CRIMSON_FRIDA_DIR`).

Output filename pattern:

- `panel_state_resolution_capture_<WIDTH>x<HEIGHT>_<RUNID>.jsonl`

Examples:

- `panel_state_resolution_capture_640x480_20260215_214455_99cf7b0e.jsonl`
- `panel_state_resolution_capture_1920x1080_20260215_215103_1a04f3dc.jsonl`

Each row includes:

- current state globals (`state_id`, `state_pending`, `state_prev`)
- resolution globals (`screen_width`, `screen_height`, `windowed`)
- UI transition globals (`timeline`, `direction`, `alpha`)
- panel element payloads (`panel_element`)
- text payloads (`panel_text`)
- per-state summary rows (`state_result`)
- run summary row (`sweep_done`)

## Useful env overrides

- `CRIMSON_PANEL_SWEEP_STATES=...` override state list.
- `CRIMSON_PANEL_SWEEP_START_DELAY_MS=...` wait before first forced transition.
- `CRIMSON_PANEL_SWEEP_ENTER_TIMEOUT_MS=...` timeout waiting for state activation.
- `CRIMSON_PANEL_SWEEP_SETTLE_MS=...` wait after entering a state.
- `CRIMSON_PANEL_SWEEP_DWELL_MS=...` capture duration per state.
- `CRIMSON_PANEL_SWEEP_MAX_UNIQUE_PANELS=...` per-state panel event cap.
- `CRIMSON_PANEL_SWEEP_MAX_UNIQUE_TEXTS=...` per-state text event cap.
- `CRIMSON_PANEL_SWEEP_CONSOLE=1` mirror JSONL rows to console.
