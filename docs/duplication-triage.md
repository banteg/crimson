# Duplicate code triage (R0801)

Source report: `artifacts/duplication/pylint-r0801.txt` (baseline)

## Infrastructure duplicates (shared helpers)

- `crimson.game_world` ↔ `crimson.views.projectile_fx`: beam trail rendering + projectile color selection.
- `crimson.views.player` ↔ `crimson.views.projectile_fx`: camera clamp/lerp block.
- `crimson.views.aim_debug` ↔ `crimson.views.projectile_render_debug`: debug view bootstrap (small font + config load).

## Math / small helpers

- `crimson.views.player` ↔ `crimson.views.projectile_fx`: clamp/lerp uses (candidate for `grim.math` helpers).

## UI widget patterns

- `crimson.views.perks` ↔ `crimson.views.survival`: perk list render + selection handling (two blocks).
- `crimson.views.bonuses` ↔ `crimson.views.sprites` / `crimson.views.particles`: grid overlay drawing.
- `crimson.views.bonuses` ↔ `crimson.views.particles`: texture scale-to-fit + hover cell highlight.
- `crimson.views.bonuses` ↔ `crimson.views.wicons`: debug asset viewer open/close/draw scaffold.
- `crimson.views.camera_shake` ↔ `crimson.views.projectile_render_debug`: basic movement + aim input capture.

## Content-ish repetition

- `crimson.quests.tier2` ↔ `crimson.quests.tier4`: spawn-at sequences for zombie waves.
- `crimson.game_world` ↔ `crimson.views.projectile_fx`: projectile frame table (`_KNOWN_PROJ_FRAMES`) + beam type set.
