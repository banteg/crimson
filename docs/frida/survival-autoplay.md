---
tags:
  - frida
  - differential-testing
  - automation
---

# Survival auto aim/fire sidecar

`scripts/frida/survival_autoplay.js` keeps the original game's native computer
assist for aiming/firing while leaving run flow manual.

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
```

Just shortcut (Windows VM):

```text
just frida-survival-autoplay
```

## What it does

- Does **not** auto-start Survival.
- Does **not** inject movement input.
- Does **not** auto-pick perks.
- Suppresses player movement by default during gameplay frames so computer assist
  does not steer the character.
- Enforces control config for the selected player:
  - `config_player_mode_flags[player]` (default `5`)
  - `config_aim_scheme[player]` (default `5`)
- Optionally enforces `config_game_mode = 1` (Survival) without forcing state transitions.

## Use with differential capture

Run this sidecar in one terminal, then run the capture script in another:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
```

Then start the run manually in-game. The sidecar keeps auto aim/fire mode pinned
while `gameplay_diff_capture.js` records.

## Output

- `C:\share\frida\survival_autoplay.jsonl`

## Env knobs

- `CRIMSON_FRIDA_AUTOPLAY_PLAYER=0` (P1 index)
- `CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT=1`
- `CRIMSON_FRIDA_AUTOPLAY_ENFORCE_MODE=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_MODE=1` (Survival)
- `CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE=5`
- `CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME=5`
- `CRIMSON_FRIDA_AUTOPLAY_DISABLE_MOVEMENT=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME=1|0` (default `1`)
- `CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF=1|0` (default `1`)
