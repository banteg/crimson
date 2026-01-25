# Rewrite (Python + raylib)

Goal: 100% parity with the classic game logic. For now the active rewrite is a
Python + raylib reference implementation that we can iterate quickly while
keeping close links to static/runtime evidence.

Code lives in `src/crimson/` (game) and `src/grim/` (engine), exercised via the
`crimson` CLI.

## How to run (current)

- `uv run crimson game` (boot + splash/logo + menu scaffold; auto-copies missing `.paq` assets from `game_bins/`)
- `uv run crimson view <name>` (debug views)
- `uv run crimson view player` (player_update + weapons/projectiles + HUD sandbox)
- `uv run crimson quests 1.1` (quest spawn dump)
- `uv run crimson config` (inspect `crimson.cfg`)

## What exists now

### Boot + front-end

- Splash screen geometry and fade timings.
- Stage-based texture loading (boot stages 0..9).
- Company logo sequence (10tons / Reflexive) with skip behavior.
- Intro/theme music handoff.
- Main menu layout + animation scaffold (tab/enter selection logging).
- Menu terrain persists between screens (no regen on Options/Stats/etc navigation).
- Demo/attract-mode scaffold (variants + simple sprite anim phases; upsell overlay + purchase screen flow in demo builds).

### Assets + rendering

- PAQ archive reader and JAZ decoder (Construct-based).
- Texture cache from `crimson.paq` with JAZ/TGA/JPG loaders.
- Terrain renderer (render-target generation + UV scroll draw; decal baking helpers).
- Raylib view runner with screenshot capture (P key).

### Data tables + content

- Quest builders for tiers 1-5 with metadata (titles, timers, terrain ids).
- Spawn template map used by quests and demo rendering.
- Weapon table, perk ids, and bonus ids mirrored into Python.

### Audio

- Music pack loader (`music.paq`) with raylib music streams.
- Intro + theme playback with volume from `crimson.cfg`.
- SFX system (`sfx.paq` or unpacked `assets_dir/sfx/*`) with key mapping + variant selection.
- Weapon fire/reload SFX wired in demo toy simulation.

### Gameplay (sandbox)

These systems exist in `src/`, but are not yet wired into the main `crimson game` mode loops:

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

- No real gameplay mode loop wired into `crimson game` yet (Survival/Rush/Quest).
- Creature update + spawners exist as models/tests/docs, but are not integrated into a real-time loop yet.
- Ground decal baking via FX queues is only exercised in debug views (not in modes).
- `game.cfg` is loaded/saved, but most progression/unlock wiring is still missing.
- Demo purchase URL is defunct (screen exists only for parity).

## Roadmap

See the rewrite tech tree: [rewrite/tech-tree.md](tech-tree.md)
