# Rewrite (Python + raylib)

Goal: 100% parity with the classic game logic. For now the active rewrite is a
Python + raylib reference implementation that we can iterate quickly while
keeping close links to static/runtime evidence.

Code lives in `src/crimson/` and is exercised via the `crimson` CLI.

## How to run (current)

- `uv run crimson game` (boot + splash/logo + menu scaffold; auto-copies missing `.paq` assets from `game_bins/`)
- `uv run crimson view <name>` (debug views)
- `uv run crimson quests 1.1` (quest spawn dump)
- `uv run crimson entrypoint` (print boot plan)
- `uv run crimson config` (inspect `crimson.cfg`)

## What exists now

### Boot + front-end

- Splash screen geometry and fade timings.
- Stage-based texture loading (boot stages 0..9).
- Company logo sequence (10tons / Reflexive) with skip behavior.
- Intro/theme music handoff.
- Main menu layout + animation scaffold (tab/enter selection logging).
- Demo/attract-mode scaffold (variants + simple sprite anim phases; **purchase/upsell screen is out of scope**).

### Assets + rendering

- PAQ archive reader and JAZ decoder (Construct-based).
- Texture cache from `crimson.paq` with JAZ/TGA/JPG loaders.
- Terrain renderer (scatter-stamp generation + camera clamp).
- Raylib view runner with screenshot capture (P key).

### Data tables + content

- Quest builders for tiers 1-5 with metadata (titles, timers, terrain ids).
- Spawn template map used by quests and demo rendering.
- Weapon table, perk ids, and bonus ids mirrored into Python.

### Audio

- Music pack loader (`music.paq`) with raylib music streams.
- Intro + theme playback with volume from `crimson.cfg`.

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

## Known gaps (short list)

- No full gameplay loop (player, weapons, projectiles, AI, HUD).
- No save/status integration in runtime flow yet.
- SFX playback (non-music) is not wired.
- Mode loops (Survival/Rush/Quest) are not implemented.
- Demo purchase/upsell screen is intentionally skipped (storefront defunct).

## Roadmap

See the rewrite tech tree: [rewrite/tech-tree.md](tech-tree.md)
