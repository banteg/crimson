# Module map (Grim vs Crimson)

This page documents the proposed two-package split under `src/`:

- `src/grim/` = engine/platform layer (raylib wrapper, assets, rendering helpers).
- `src/crimson/` = game layer (modes, simulation, UI, persistence, data tables).

The intent is to mirror the original `grim.dll` vs `crimsonland.exe` boundary
while staying idiomatic for the Python rewrite.

## Principles

- `grim` should not import `crimson`.
- `crimson` can import `grim` helpers.
- Keep raylib calls confined to `grim` as much as practical.
- Prefer small moves that preserve working entrypoints (`uv run crimson ...`).

## Current code → target package

Subsystem | Current module(s) | Target | Notes
--- | --- | --- | ---
Window/loop/timing | `src/grim/app.py` | `src/grim/app.py` | Owns window init, main loop, fps, views.
Assets (PAQ/JAZ/cache) | `src/grim/paq.py`, `src/grim/jaz.py`, `src/grim/assets.py` | `src/grim/*` | Keep flat for now; split cache later if needed.
Input | `src/grim/input.py` | `src/grim/input.py` | Minimal wrapper + action map stub.
View protocol/context | `src/grim/view.py` | `src/grim/view.py` | Shared by debug views and view runner.
Atlas helpers | `src/crimson/atlas.py` | `src/grim/atlas.py` (future) | Scripts import `crimson.atlas` today.
Terrain rendering | `src/grim/terrain_render.py` | `src/grim/terrain_render.py` | Pure render pipeline; game selects params.
Audio (music) | `src/grim/audio.py` | `src/grim/audio.py` | Later: split `music.py` / `sfx.py`.
Config (crimson.cfg) | `src/grim/config.py` | `src/grim/config.py` | Global settings + persistence.
Console/log | `src/grim/console.py` | `src/grim/console.py` | Console as engine/debug layer.
Grim2D font | `src/crimson/grim2d/font.py` | `src/grim/grim2d/font.py` (future) | Keep low-level font helpers in `grim`.
CLI entrypoint | `src/crimson/cli.py` | `src/crimson/cli.py` | Stays in game package.
Entrypoint boot plan | `src/crimson/entrypoint.py` | `src/crimson/entrypoint.py` | Game flow + asset staging.
Main game flow | `src/crimson/game.py`, `src/crimson/demo.py` | `src/crimson/*` | State machine + demo flow.
Quests | `src/crimson/quests/*` | `src/crimson/quests/*` | Game content.
Data tables (Python) | `src/crimson/weapons.py`, `src/crimson/perks.py`, `src/crimson/bonuses.py`, `src/crimson/creatures/spawn.py` | `src/crimson/*` (or `src/crimson/data/*`) | Keep tables/enums in Python (no JSON move).
Debug views | `src/crimson/views/*` | `src/crimson/views/*` | Tooling/debug; may call `grim` drawing helpers.

## Prefix map (decomp → rewrite)

Prefix cluster | Proposed package
--- | ---
`grim_*` | `grim.*` (graphics/input/audio/assets/config)
`resource_*`, `buffer_reader_*` | `grim.paq` / `grim.assets`
`console_*` | `grim.console`
`ui_*`, `hud_*` | `crimson.ui.*`
`quest_*`, `survival_*`, `rush_*`, `demo_*`, `tutorial_*` | `crimson.modes.*`
`player_*`, `creature_*`, `projectile_*`, `bonus_*`, `effect_*`, `fx_*` | `crimson.sim.*`
`weapon_*`, `perk_*` | `crimson.*` (keep code-side Python tables/enums)
`highscore_*` | `crimson.persistence.*` / `crimson.services.*`
`mod_*` | `crimson.mods.*`

## Decisions (current)

- Input lives in `grim/input.py` (minimal wrapper; keep API surface small).
- Debug views stay under `crimson.views`.
- Keep `grim/` flat for now (no `grim/graphics/*` yet).
