---
tags:
  - frida
  - differential-testing
  - automation
---

# Survival control sidecar

`scripts/frida/survival_autoplay.js` keeps the original game's control scheme
values pinned while leaving run flow manual.

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
- Only enforces control config for the selected player:
  - `config_player_mode_flags[player]` (default `2`, static movement)
  - `config_aim_scheme[player]` (default `5`, computer aiming)
- Does **not** patch game mode, player count, or demo-mode flags.

## Use with differential capture

Run this sidecar in one terminal, then run the capture script in another:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
```

Then start the run manually in-game. The sidecar keeps control scheme values
pinned while `gameplay_diff_capture.js` records.

## Output

- `C:\share\frida\survival_autoplay.jsonl`

## Env knobs

- `CRIMSON_FRIDA_AUTOPLAY_PLAYER=0` (P1 index)
- `CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE=2`
- `CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME=5`
- `CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME=1|0` (default `1`)
