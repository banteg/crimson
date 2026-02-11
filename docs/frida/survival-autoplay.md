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
- Forces P1 to digital movement + native auto-aim:
  - `config_player_mode_flags[0] = 2`
  - `config_aim_scheme[0] = 5`
- Starts gameplay automatically (`gameplay_reset_state` + `game_state_set(9)`).
- Overrides Grim key queries to steer movement with:
  - creature kiting / orbiting
  - bonus pickup priority
  - anti-corner center pull + trapped rush escape
  - anti-jitter calm threshold and key-hold smoothing
- Auto-picks one perk per perk screen and resumes gameplay.
- By default, runs one Survival run and stops after death to avoid score-screen glitches.
- Optional auto-restart remains available.

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
- `CRIMSON_FRIDA_AUTOPLAY_RESTART=1|0` (default `0`)
- `CRIMSON_FRIDA_AUTOPLAY_STOP_AFTER_DEATH=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_RESTART_DELAY_MS=1200`
- `CRIMSON_FRIDA_AUTOPLAY_PLAYER=0` (P1 index)
- `CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT=1`
- `CRIMSON_FRIDA_AUTOPLAY_MODE=1` (Survival)
- `CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE=2` (Digital movement)
- `CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME=5` (Computer auto-aim)
- `CRIMSON_FRIDA_AUTOPLAY_INPUT_OVERRIDE=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_PERKS=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_PERK_DELAY_MS=120`
- `CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF=1|0` (default `1`)

Movement tuning:

- `CRIMSON_FRIDA_AUTOPLAY_DEADZONE=0.30`
- `CRIMSON_FRIDA_AUTOPLAY_CALM_THREAT=180`
- `CRIMSON_FRIDA_AUTOPLAY_CALM_VECTOR=0.16`
- `CRIMSON_FRIDA_AUTOPLAY_THREAT_RADIUS=225`
- `CRIMSON_FRIDA_AUTOPLAY_DANGER_RADIUS=90`
- `CRIMSON_FRIDA_AUTOPLAY_CORNER_MARGIN=96`
- `CRIMSON_FRIDA_AUTOPLAY_BONUS_RADIUS=280`
- `CRIMSON_FRIDA_AUTOPLAY_BONUS_WEIGHT=2.2`
- `CRIMSON_FRIDA_AUTOPLAY_RUSH_FRAMES=10`
- `CRIMSON_FRIDA_AUTOPLAY_RUSH_DIST=180`
- `CRIMSON_FRIDA_AUTOPLAY_JITTER_HOLD=4`
