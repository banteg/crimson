# Rewrite (Python + raylib)

Goal: 100% parity with the classic game logic. For now the active rewrite is a
Python + raylib reference implementation that we can iterate quickly while
keeping close links to static/runtime evidence.

Code lives in `src/crimson/` (game) and `src/grim/` (engine), exercised via the
`crimson` CLI.

## How to run (current)

- `uv run crimson` (boot + splash/logo + menu + panels; Survival/Rush/Quests/Typ-o/Tutorial are all fully wired; menu idle triggers demo/attract)
- `uv run crimson --preserve-bugs` (re-enable known original exe bugs/quirks; useful for parity/diff testing)
- `uv run crimson view <name>` (debug views + mode views)
- `uv run crimson view survival` (Survival loop in the view runner)
- `uv run crimson view player` (player_update + weapons/projectiles + HUD sandbox)
- `uv run crimson quests 1.1` (quest spawn dump)
- `uv run crimson config` (inspect `crimson.cfg`)

## What exists now

### Boot + front-end

- Splash screen geometry and fade timings.
- Stage-based texture loading (boot stages 0..9).
- Company logo sequence (10tons / Reflexive) with skip behavior.
- Intro/theme music handoff.
- Main menu buttons + animations (Play/Options/Stats/Mods/Quit) with panel/back slide animation.
- Play Game panel (mode select + player count dropdown + tooltips + F1 “times played” overlay).
- Quest select menu UI (stage icons + hardcore toggle gating + quest list + counts overlay; quest gameplay wired).
- Options panel (volume/detail/mouse sliders + “UI Info texts”; Controls dropdowns + direction-arrow checkbox are interactive, while key/axis rebinding is still pending).
- Statistics panel (Summary/Weapons/Quests pages; playtime + weapon usage + quest counters).
- Menu terrain persists between screens (no regen on Options/Stats/etc navigation).
- Menu sign shadow pass matches the original when `fx_detail` is enabled.
- Demo/attract mode: idle trigger + variant sequencing; upsell overlay + trial overlay + purchase screen flow in demo builds.

### Assets + rendering

- PAQ archive reader and JAZ decoder (Construct-based).
- Texture cache from `crimson.paq` with JAZ/TGA/JPG loaders.
- Terrain renderer (render-target generation + UV scroll draw; decal baking via FX queues).
- Shared `GameWorld` renderer (terrain + sprites for player/creatures/projectiles/bonuses, with debug fallbacks when assets are missing).
- Raylib view runner with screenshot capture (P key).

### Data tables + content

- Quest builders for tiers 1-5 with metadata (titles, timers, terrain ids).
- Spawn template map used by quests and demo rendering.
- Weapon table, perk ids, and bonus ids mirrored into Python.

### Audio

- Music pack loader (`music.paq`) with raylib music streams.
- Intro + theme playback with volume from `crimson.cfg`.
- SFX system (`sfx.paq` or unpacked `assets_dir/sfx/*`) with key mapping + variant selection.
- Audio routing system (`AudioRouter`) with per-creature-type death SFX (zombie, lizard, alien, spider, trooper).
- Gameplay SFX hooks: weapon fire/reload, projectile hit (bullet/beam/explosion variants), creature death.
- Survival music trigger integration (game tune activation on first hits).

### Gameplay (modes)

- `GameWorld` owns the active runtime state: players, projectiles, creatures, bonuses/perks, FX queues, terrain, and sprite rendering.
- Survival/Rush/Quest/Typ-o/Tutorial loops are wired into the default `crimson` runner via `src/crimson/modes/*`.
  - Player/projectile updates, creature pool + spawns, XP/level/perk selection UI, HUD overlay, terrain decal baking.
  - Quest mode has all tiers 1-5 implemented with full spawn scripting.
  - Tutorial mode has full stage-based progression with hint system.
  - Typ-o-Shooter has typing mechanics with target matching and reload command.
- Game over / high score entry screen is implemented for Survival/Rush/Typ-o: [rewrite/game-over.md](game-over.md)
- Quest completion/failure screens are implemented (results + failed).
- Demo/attract mode reuses the same gameplay systems (no separate “toy sim”).

### Gameplay (sandbox)

These sandboxes are still useful for focused iteration:

- `player_update` port (movement, aiming, reload, firing, perk timers).
- Projectile pools (main + secondary) with basic spawn/update/hit logic.
- Bonus/perk application logic + bonus HUD state.
- HUD overlay renderer (`src/crimson/ui/hud.py`) exercised in `uv run crimson view player`.

### Persistence + console

- `game.cfg` status file decode/encode + checksum, loaded on boot and saved on exit.
- Statistics screen reads `game.cfg` values (quest unlock indices, mode play counters, checksum status).
- In-game console UI overlay (toggle with backtick) with commands + cvars.

### Debug views (raylib)

Available via `uv run crimson view <name>`:

- `empty` (empty window)
- `fonts` (font preview)
- `animations` (creature animation preview)
- `sprites` (sprite atlas preview)
- `terrain` (terrain texture preview)
- `ground` (procedural ground render)
- `projectiles` (projectile atlas preview)
- `projectile-render-debug` (projectile render parity sandbox)
- `projectile_fx` (projectile effects preview)
- `bonuses` (bonus icon preview)
- `wicons` (weapon icon preview)
- `ui` (UI texture preview)
- `particles` (particle atlas preview)
- `player` (player sandbox with weapons/projectiles/HUD)
- `survival` (survival mode view)
- `rush` (rush mode view)
- `game_over` (game over screen preview)
- `spawn_plan` (spawn plan visualization)
- `perks` / `perk_menu_debug` (perk selection UI)
- `camera_debug` / `camera_shake` (camera system)
- `decals_debug` / `corpse_stamp_debug` (decal system)
- `aim_debug` (aiming visualization)
- `player_sprite_debug` (player sprite variants)
- `small_font_debug` (font glyph testing)

See also:

- [Module map (Grim vs Crimson)](module-map.md)
- [Deterministic simulation PRD](deterministic-sim-prd.md)
- [Deterministic step pipeline](deterministic-step-pipeline.md)
- [Terrain (rewrite)](terrain.md)
- [Bonus pickups (rewrite)](bonuses.md)
- [Survival entry fade (decompile notes)](survival-transition-fade.md)
- [Original bugs (and rewrite fixes)](original-bugs.md)

## Known gaps (short list)

- Creature runtime parity gaps: remaining AI edge cases and per-weapon behaviors are still pending.
- Some gameplay SFX/events are still missing (perk UI selection sound, ranged enemy fire SFX).
- Multiplayer (2-4 players): multiple players spawn, but inputs are currently mirrored (shared controls).
- `game.cfg` progression/unlock wiring and some statistics counters are still incomplete.
- Full Options/Controls parity (video/window mode editing, full widget set).
- Online scores + mods/plugin interface (tracked but not yet implemented).

## Roadmap

See the rewrite tech tree: [rewrite/tech-tree.md](tech-tree.md)

See also: [Rewrite status / parity gaps](status.md)
