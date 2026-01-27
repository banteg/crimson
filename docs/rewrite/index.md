# Rewrite (Python + raylib)

Goal: 100% parity with the classic game logic. For now the active rewrite is a
Python + raylib reference implementation that we can iterate quickly while
keeping close links to static/runtime evidence.

Code lives in `src/crimson/` (game) and `src/grim/` (engine), exercised via the
`crimson` CLI.

## How to run (current)

- `uv run crimson game` (boot + splash/logo + menu + panels; Survival is playable; menu idle triggers demo/attract)
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
- Quest select menu UI (stage icons + hardcore toggle gating + quest list + counts overlay; quest gameplay pending).
- Options panel (volume/detail/mouse sliders + “UI Info texts”; Controls screen pending).
- Statistics panel (quest unlock + mode play counts + checksum + top weapons).
- Menu terrain persists between screens (no regen on Options/Stats/etc navigation).
- Menu sign shadow pass matches the original when `fx_detail` is enabled.
- Demo/attract mode: idle trigger + variant sequencing; upsell overlay + purchase screen flow in demo builds (trial overlay pending).

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
- Basic gameplay SFX hooks via `GameWorld` (weapon fire/reload, projectile hit, creature death).

### Gameplay (modes)

- `GameWorld` owns the active runtime state: players, projectiles, creatures, bonuses/perks, FX queues, terrain, and sprite rendering.
- Survival mode loop is wired into `crimson game` and the view runner (`uv run crimson view survival`).
  - Player/projectile updates, creature pool + spawns, XP/level/perk selection UI, HUD overlay, terrain decal baking.
- Game over / high score entry screen is implemented for Survival: [rewrite/game-over.md](game-over.md)
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
- `bonuses` (bonus icon preview)
- `wicons` (weapon icon preview)
- `ui` (UI texture preview)
- `particles` (particle atlas preview)

See also:

- [Module map (Grim vs Crimson)](module-map.md)
- [Terrain (rewrite)](terrain.md)

## Known gaps (short list)

- Quest/Rush/Typ-o/Tutorial gameplay loops are not wired yet (Survival is the current playable mode).
- Creature runtime parity gaps: ranged attacks (`CreatureFlags.RANGED_ATTACK_*`) and `SPLIT_ON_DEATH` are still pending.
- Some gameplay SFX/events are still missing (bonus pickup, perk UI, ranged enemy fire).
- Survival currently uses a fixed seed by default (good for repro, bad for variety).
- Survival is currently single-player only (Play Game panel exposes player count, but gameplay isn’t wired).
- `game.cfg` is loaded/saved, but progression/unlock wiring and high-score stat fields are still incomplete.
- High score list screen is not implemented yet (game over routes back to menu).
- Demo purchase URL is defunct (screen exists only for parity).

## Roadmap

See the rewrite tech tree: [rewrite/tech-tree.md](tech-tree.md)

See also: [Rewrite status / parity gaps](status.md)
