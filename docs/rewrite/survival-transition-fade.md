---
tags:
  - status-analysis
  - transitions
---

# Survival entry fade (decompile notes)

This page documents the **menu → Survival** fade behavior using the static decompile as the
authoritative source. The goal is to mirror the original pipeline and identify any missing
runtime triggers before changing the rewrite behavior.

## Fullscreen fade overlay (render order)

The classic renderer applies a fullscreen black overlay using `screen_fade_alpha`
(`DAT_00487264`) **after the world render** and **before UI elements**:

- `gameplay_render_world` (`0x00405960`) draws `grim_draw_fullscreen_color(0,0,0,screen_fade_alpha)`
  after projectiles/bonuses.
- `game_update_generic_menu` (`0x00406af0`) draws the same fullscreen color after the menu/world
  pass and before `ui_elements_update_and_render`.

This ordering matches the observed effect: **ground can dim while UI panels slide out**,
because the UI is rendered after the fade overlay.

## Fade update rates (authoritative)

The main update loop updates `screen_fade_alpha` every frame:

```c
if (screen_fade_ramp_flag == 0) {
  screen_fade_alpha -= frame_dt * 2.0;
} else {
  screen_fade_alpha += frame_dt * 10.0;
}
screen_fade_alpha = clamp(screen_fade_alpha, 0.0, 1.0);
```

Decompile reference: `crimsonland.exe_decompiled.c` around the `screen_fade_alpha` update
block (see ~`0x0040c4b7` region and the `DAT_0048702c` checks).

Implication: **fade-to-black is very fast** (~0.1s at 60fps), while **fade-from-black**
is slower (~0.5s at 60fps).

## Trigger observations (static)

Static references to `screen_fade_ramp_flag` (`DAT_0048702c`):

- Set to `0` on `game_state_set(9)` (Survival/Rush/Quests gameplay entry).
- The only *explicit* set to `1` found in the decompile is tied to the menu path that
  queues `game_state_pending = 0x12` (Typ‑o‑Shooter).

**No static write** to `screen_fade_ramp_flag = 1` was found on the Survival start path
(`game_state_pending = 9` with game mode 1).

### Interpretation

The observed Survival entry fade in the original build is **not explained by the current
decompile alone**. Possibilities:

- The fade trigger is set by a code path not captured in the current decompile dump.
- The visible effect is driven by a different transition mechanism (e.g., UI timeline and
  render ordering) rather than a ramped `screen_fade_alpha`.

## Next steps (runtime evidence)

To resolve this, capture a runtime trace when selecting **Survival** from the Play Game menu:

- Track writes to `DAT_0048702c` and `DAT_00487264` during the transition.
- Record `ui_elements_timeline` and `ui_transition_direction` across the menu close.

If no ramp is observed, keep Survival without the fade overlay; if a ramp is observed, align
the rewrite to the confirmed trigger.
