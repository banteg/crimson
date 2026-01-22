# Rewrite tech tree (Python + raylib)

Checkboxes are status for the Python + raylib rewrite. Each item includes what
it unlocks for parity. Goal: 100% replication of game logic.

## Foundations

- [x] PAQ archive reader + extract CLI -> Unlocks: asset extraction + texture cache.
- [x] JAZ decoder -> Unlocks: sprites, UI, terrain textures.
- [x] Texture cache (JAZ/TGA/JPG) -> Unlocks: boot splash, menu, views.
- [x] Raylib window loop + screenshot hotkey -> Unlocks: visual debugging.
- [x] `crimson.cfg` loader/writer -> Unlocks: screen settings + audio toggles.
- [x] Console log + command stubs -> Unlocks: boot logging + future console flow.

## Boot + front-end

- [x] Splash screen draw + fade timings -> Unlocks: boot parity visuals.
- [x] Stage-based texture loading -> Unlocks: menu/demo assets on time.
- [x] Company logo sequence + skip -> Unlocks: intro flow parity.
- [x] Intro/theme music playback -> Unlocks: boot/menu audio parity.
- [x] Main menu layout + animation scaffold -> Unlocks: menu navigation work.
- [x] Demo/attract scaffold -> Unlocks: idle flow and animation sanity checks.

## Data tables + content

- [x] Weapon table mirror -> Unlocks: weapon behavior modeling.
- [x] Perk/bonus tables -> Unlocks: perk/bonus logic.
- [x] Spawn template mapping -> Unlocks: creature labeling + quest spawns.
- [x] Quest builders (tiers 1-5) -> Unlocks: quest mode simulation.

## Rendering + debug views

- [x] Terrain render-target + procedural stamping -> Unlocks: ground parity and quest previews.
- [ ] Terrain decal baking (fx_queue_render parity) -> Unlocks: baked blood/scorch/corpses on ground.
- [x] Creature animation preview -> Unlocks: sprite timing validation.
- [x] Sprite/particle/bonus/weapon atlas previews -> Unlocks: asset alignment.
- [x] UI + font previews -> Unlocks: HUD/menu layout checks.

## Next (short term)

- [ ] Player input + movement state -> Unlocks: controllable gameplay loop.
- [ ] Weapon firing + reload timers -> Unlocks: combat timing parity.
- [ ] Projectile system (spawn/update/collide) -> Unlocks: damage + FX.
- [ ] Creature updates + spawners -> Unlocks: enemy waves in modes.
- [ ] Bonus/perk application logic -> Unlocks: timers + power-up effects.
- [ ] HUD overlay (health/ammo/bonuses) -> Unlocks: in-game UI parity.
- [ ] SFX playback (non-music) -> Unlocks: gameplay/audio feedback.
- [ ] Save/status integration -> Unlocks: persistence + unlock tracking.

## Later parity gates

- [ ] Mode loops (Survival/Rush/Quest) -> Unlocks: full gameplay.
- [ ] Credits/secret minigames -> Unlocks: secret path parity.
- [ ] Online high scores -> Unlocks: score submission parity.
- [ ] Mods (CMOD) loader -> Unlocks: mod parity.
