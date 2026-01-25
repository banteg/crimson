# Rewrite tech tree (Python + raylib)

Checkboxes are status for the Python + raylib rewrite. Each item includes what
it unlocks for parity. Goal: 100% replication of game logic.

## Foundations

- [x] PAQ archive reader + extract CLI -> Unlocks: asset extraction + texture cache.
- [x] JAZ decoder -> Unlocks: sprites, UI, terrain textures.
- [x] Texture cache (JAZ/TGA/JPG) -> Unlocks: boot splash, menu, views.
- [x] Raylib window loop + screenshot hotkey -> Unlocks: visual debugging.
- [x] `crimson.cfg` loader/writer -> Unlocks: screen settings + audio toggles.
- [x] Console UI overlay + commands/cvars -> Unlocks: interactive console parity.

## Boot + front-end

- [x] Splash screen draw + fade timings -> Unlocks: boot parity visuals.
- [x] Stage-based texture loading -> Unlocks: menu/demo assets on time.
- [x] Company logo sequence + skip -> Unlocks: intro flow parity.
- [x] Intro/theme music playback -> Unlocks: boot/menu audio parity.
- [x] Main menu layout + animation scaffold -> Unlocks: menu navigation work.
- [x] Main menu buttons wired (Play/Options/Stats/Mods/Quit) -> Unlocks: front-end screen plumbing.
- [x] Menu terrain persistence (no regen between screens) -> Unlocks: menu navigation fidelity.
- [x] Panel menu slide animation (panel + BACK) -> Unlocks: Play/Options/etc screen frame parity.
- [x] Menu sign shadow pass (fx_detail) -> Unlocks: exact menu draw-pass parity.
- [x] Demo/attract scaffold -> Unlocks: idle flow and animation sanity checks.
- [x] Demo loop parity (idle trigger + variant sequencing + restart rules) -> Unlocks: title-screen behavior parity.
- [x] Demo upsell overlay (demo builds) -> Unlocks: shareware messaging parity.
- [ ] Demo trial overlay (demo builds) -> Unlocks: trial messaging parity.
- [x] Demo purchase screen flow (demo builds) -> Unlocks: upsell UI parity.

## Data tables + content

- [x] Weapon table mirror -> Unlocks: weapon behavior modeling.
- [x] Perk/bonus tables -> Unlocks: perk/bonus logic.
- [x] Spawn template mapping -> Unlocks: creature labeling + quest spawns.
- [x] Quest builders (tiers 1-5) -> Unlocks: quest mode simulation.

## Rendering + debug views

- [x] Terrain render-target + procedural stamping -> Unlocks: ground parity and quest previews.
- [x] Terrain decal baking (fx_queue_render port; used in `ground` view) -> Unlocks: baked blood/scorch/corpses on ground.
- [x] Creature animation preview -> Unlocks: sprite timing validation.
- [x] Sprite/particle/bonus/weapon atlas previews -> Unlocks: asset alignment.
- [x] UI + font previews -> Unlocks: HUD/menu layout checks.

## Next (short term)

- [ ] Options screen widgets (fx/audio/windowed toggles) -> Unlocks: config editing parity.
- [x] Player input + movement state (sandbox view) -> Unlocks: controllable gameplay loop.
- [x] Weapon firing + reload timers (sandbox view) -> Unlocks: combat timing parity.
- [x] Projectile system (spawn/update/hit subset) -> Unlocks: damage + FX.
- [ ] Creature updates + spawners -> Unlocks: enemy waves in modes.
- [ ] Replace DemoView toy simulation with real gameplay systems -> Unlocks: reuse gameplay loop for attract mode.
- [x] Bonus/perk application logic (subset) -> Unlocks: timers + power-up effects.
- [x] HUD overlay (health/ammo/bonuses) -> Unlocks: in-game UI parity.
- [x] SFX playback (non-music; demo wired) -> Unlocks: gameplay/audio feedback.
- [x] Save/status integration (`game.cfg` load/save + stats screen) -> Unlocks: persistence + unlock tracking.

## Later parity gates

- [ ] Mode loops (Survival/Rush/Quest) -> Unlocks: full gameplay.
- [ ] Credits/secret minigames -> Unlocks: secret path parity.
- [ ] Online high scores -> Unlocks: score submission parity.
- [ ] Mods (CMOD) loader -> Unlocks: mod parity.
