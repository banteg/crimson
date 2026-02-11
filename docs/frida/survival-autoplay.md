---
tags:
  - frida
  - differential-testing
  - automation
---

# Survival autoplay sidecar

`scripts/frida/survival_autoplay.js` runs the original game in Survival mode
without manual input so you can record differential captures repeatedly.

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
```

Just shortcut (Windows VM):

```text
just frida-survival-autoplay
```

## What it does

- Forces `config_game_mode = 1` (Survival).
- Forces P1 to native computer controls:
  - `config_player_mode_flags[0] = 5`
  - `config_aim_scheme[0] = 5`
- Starts gameplay automatically (`gameplay_reset_state` + `game_state_set(9)`).
- Auto-picks one perk per perk screen and resumes gameplay.
- Optionally restarts after game over.

## Use with differential capture

Run this sidecar in one terminal, then run the capture script in another:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
```

This keeps the run unattended while `gameplay_diff_capture.js` writes
`gameplay_diff_capture.json`.

## Output

- `C:\share\frida\survival_autoplay.jsonl`

## Env knobs

- `CRIMSON_FRIDA_AUTOPLAY_START=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_START_DELAY_MS=1000`
- `CRIMSON_FRIDA_AUTOPLAY_RESTART=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_RESTART_DELAY_MS=1200`
- `CRIMSON_FRIDA_AUTOPLAY_PLAYER=0` (P1 index)
- `CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT=1`
- `CRIMSON_FRIDA_AUTOPLAY_MODE=1` (Survival)
- `CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE=5` (Computer)
- `CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME=5` (Computer)
- `CRIMSON_FRIDA_AUTOPLAY_PERKS=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_PERK_DELAY_MS=120`
- `CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF=1|0` (default `1`)

