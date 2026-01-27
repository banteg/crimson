# Projectile render debug (pistol parity)

This debug view isolates the gameplay projectile loop with a fixed arena and
static targets. It is intended to validate pistol behavior against
`projectile_render` and the gameplay fire/reload paths.

## Run

```bash
uv run crimson view projectile-render-debug
```

## Controls

- `WASD` move
- `LMB` fire
- `R` reload
- `[` / `]` cycle weapons
- `Space` pause
- `T` reset targets
- `Backspace` reset scene
- `Esc` quit

## Pistol parity checklist

The pistol is `weapon_id=0` (rewrite ids are 0‑based). This view exercises:

- **Aim + spread math** via `player_update` + `player_fire_weapon`.
- **Projectile update + hit detection** via `projectiles.update` against static
  `TargetDummy` entries.
- **Projectile rendering** for the pistol:
  - Bullet streaks using `bulletTrail` texture.
  - Bullet sprite using `bullet16` (`bullet_i`) texture.
- **SFX**:
  - Fire + reload from `weapon.fire_sound` / `weapon.reload_sound`.
  - Hit SFX via the shared projectile hit path.
- **Impact decals** baked into the ground renderer using the FX queues.

## Notes / intentional deviations

- Targets are lightweight `Damageable` dummies, not full creature AI.
- No bonus/perk HUD or progression logic is active in this view.
- Audio is optional: it is only initialized when `artifacts/runtime/crimson.cfg`
  exists (created by `ensure_crimson_cfg`).

## Trail fade fidelity (pistol)

Native `projectile_render` draws pistol bullet trails with **per‑vertex alpha**
on a single quad (via `grim_set_color_slot` + `grim_draw_quad_points`), which
creates a head→tail gradient along the trail.

Rewrite now renders the trail as a **per‑vertex quad** (RLGL), matching the
head→tail alpha gradient from the exe.

### Candidate approaches

1) **Per‑vertex quad (best fidelity, low draw cost)**  
   Use Raylib RLGL to draw the trail as a quad with per‑vertex colors (matching
   the native `grim_draw_quad_points` semantics). This is closest to the exe and
   remains one draw call per projectile.

2) **Multi‑segment trail (good approximation, higher draw cost)**  
   Split the trail into N quads along the line and fade alpha per segment.
   Simple to implement with existing `draw_texture_pro`, but adds draw calls and
   looks stepped.

3) **Shader gradient (high fidelity, more complexity)**  
   A custom shader could fade alpha along the quad UV, but adds shader plumbing
   and is overkill for a single effect.

**Chosen approach:** per‑vertex quad via RLGL (option 1). It is closest to the
exe and should be cheaper than multi‑segment trails.
