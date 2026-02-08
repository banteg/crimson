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
- [x] Play Game panel (mode select + dropdown + tooltips + F1 overlay) -> Unlocks: mode selection UI parity.
- [x] Quest select menu UI -> Unlocks: quest navigation + gating.
- [x] Demo/attract scaffold -> Unlocks: idle flow and animation sanity checks.
- [x] Demo loop parity (idle trigger + variant sequencing + restart rules) -> Unlocks: title-screen behavior parity.
- [x] Demo upsell overlay (demo builds) -> Unlocks: shareware messaging parity.
- [x] Demo trial overlay (demo builds) -> Unlocks: trial messaging parity (UI + timer logic wired; demo-build validation pending).
- [x] Demo purchase screen flow (demo builds) -> Unlocks: upsell UI parity.

## Data tables + content

- [x] Weapon table mirror -> Unlocks: weapon behavior modeling.
- [x] Perk/bonus tables -> Unlocks: perk/bonus logic.
- [x] Spawn template mapping -> Unlocks: creature labeling + quest spawns.
- [x] Quest builders (tiers 1-5) -> Unlocks: quest mode simulation.

## Rendering + debug views

- [x] Terrain render-target + procedural stamping -> Unlocks: ground parity and quest previews.
- [x] Terrain decal baking (fx_queue_render port; used in Survival/Demo via `GameWorld`) -> Unlocks: baked blood/scorch/corpses on ground.
- [x] Creature animation preview -> Unlocks: sprite timing validation.
- [x] Sprite/particle/bonus/weapon atlas previews -> Unlocks: asset alignment.
- [x] UI + font previews -> Unlocks: HUD/menu layout checks.

## Completed (gameplay integration)

- [x] Wire gameplay scene into the default `crimson` runner (player + camera + HUD) -> Unlocks: playtesting loop outside debug views.
- [x] Port `player_take_damage` + game over flow -> Unlocks: contact damage + death handling.
- [x] Game over / high score entry UI (Survival/Rush/Typ-o) -> Unlocks: post-run loop parity + score persistence.
- [x] Quest results / quest failed screens -> Unlocks: quest completion flow parity.
- [x] Integrate creature updates + spawners into runtime loop -> Unlocks: enemy waves in modes.
- [x] Integrate combat loop (projectiles -> creatures, death contract -> XP/bonuses/FX/SFX) -> Unlocks: combat parity.
- [x] Wire FX queues into gameplay ground renderer -> Unlocks: persistent blood/corpses in modes.
- [x] Implement Survival mode loop (rewrite runtime) -> Unlocks: first playable mode.
- [x] Replace DemoView toy simulation with gameplay scene -> Unlocks: reuse gameplay loop for attract mode.
- [x] Options screen (volume/detail/mouse + HUD toggle) -> Unlocks: basic config editing (video/controls parity pending).
- [x] Implement creature ranged attacks (`CreatureFlags.RANGED_ATTACK_*`) -> Unlocks: Survival enemy variety parity.
- [x] Implement split-on-death (`CreatureFlags.SPLIT_ON_DEATH`) -> Unlocks: splitter enemy parity.
- [x] Wire gameplay SFX/events (weapon fire/reload, hit, creature death) -> Unlocks: audio feedback parity.
- [x] Audio routing system with per-creature-type death SFX -> Unlocks: immersive audio parity.
- [x] Wire Rush/Quest/Typ-o/Tutorial mode loops into the default `crimson` runner -> Unlocks: additional playable modes.
- [x] Tutorial stage-based progression with hint system -> Unlocks: tutorial flow parity.
- [x] Typ-o-Shooter typing mechanics with target matching -> Unlocks: Typ-o mode parity.

## Gameplay building blocks (implemented, not fully integrated)

- [x] Player input + movement state (sandbox view) -> Unlocks: controllable gameplay loop.
- [x] Weapon firing + reload timers (sandbox view) -> Unlocks: combat timing parity.
- [x] Projectile system (spawn/update/hit subset) -> Unlocks: damage + FX.
- [x] Bonus/perk application logic (subset) -> Unlocks: timers + power-up effects.
- [x] HUD overlay (health/ammo/bonuses) -> Unlocks: in-game UI parity.
- [x] SFX playback (music + SFX; basic gameplay events wired) -> Unlocks: gameplay/audio feedback.
- [x] Save/status integration (`game.cfg` load/save + stats screen) -> Unlocks: persistence + unlock tracking.

## Gaps (still missing)

- Creature runtime parity gaps: AI edge cases and remaining per-weapon behaviors.
- Some gameplay SFX/events: perk UI selection sound, ranged enemy fire SFX.
- Multiplayer (2-4 players): multiple players spawn, but inputs are currently mirrored (shared controls).
- Full Options/Controls parity: key/axis rebinding, video/window mode editing, full widget set.
- Some progression/unlock wiring and statistics counters are still incomplete.
- High score list screen (post-run): implemented locally; online scores still missing.

## Later parity gates

- [ ] Multiplayer wiring (2-4 players) -> Unlocks: local multiplayer parity.
- [ ] Credits/secret minigames -> Unlocks: secret path parity.
- [ ] Online high scores -> Unlocks: score submission parity.
- [ ] Mods (CMOD) loader -> Unlocks: mod parity.
- [ ] Confirm demo idle threshold from original demo build -> Unlocks: attract timing parity.
