# Rewrite (Python + raylib)

Goal: 100% parity with the classic game logic. For now the active rewrite is a
Python + raylib reference implementation that we can iterate quickly while
keeping close links to static/runtime evidence.

Code lives in `src/crimson/` (game) and `src/grim/` (engine), exercised via the
`crimson` CLI.

## How to run (current)

- `uv run crimson` (boot + splash/logo + menu + panels; Survival/Rush/Quests/Typ-o/Tutorial are all fully wired; menu idle triggers demo/attract)
- `uv run crimson --preserve-bugs` (re-enable known original exe bugs/quirks; useful for parity/diff testing)
- `uv run crimson view <name>` (debug views)
- `uv run crimson view arsenal` (weapon/arsenal sandbox)
- `uv run crimson quests 1.1` (quest spawn dump)
- `uv run crimson config` (inspect `crimson.cfg`)
- `uv run crimson relay serve --bind 0.0.0.0 --port 31993` (run UDP relay)
- `uv run crimson net host --mode survival --players 2 --relay-host 127.0.0.1 --relay-port 31993` (host rollback room)
- `uv run crimson net join --code <ROOMCODE> --relay-host 127.0.0.1 --relay-port 31993` (join rollback room)

## Zig port (current WIP)

- Workspace: `crimson-zig/`
- Current headless CLI surface includes `replay list`, `replay verify`,
  `replay info`, `replay benchmark`, `replay verify-checkpoints`, and
  `replay diff-checkpoints`, plus native `dbg record` CDT trace export,
  `dbg verify`, `config`/`status` inspection, `quests` spawn-table dumps, and
  the installed `crimson-zig-asset-smoke` asset decode validator.
- Project direction is a full native Zig port, not just a replay verifier.
- The Zig tree now also has a real native desktop shell with boot/menu/gameplay/results/options/statistics flow and live Survival/Rush/Quests/Typ-o/Tutorial runs.
- Replay verification is still the most mature headless Zig surface, with native + wasm replay/checkpoint build targets already in-tree.
- Current state is advanced but still incomplete parity. The biggest remaining Zig work is replay/tooling breadth, product-shell parity including demo/trial polish, with network/LAN still deferred.
- See [Zig native port status](zig-verifier.md) for the current snapshot and [Zig port roadmap](zig-roadmap.md) for remaining work.

## What exists now

### Boot + front-end

- Splash screen geometry and fade timings.
- Stage-based texture loading (boot stages 0..9).
- Company logo sequence (10tons / Reflexive) with skip behavior.
- Intro/theme music handoff.
- Main menu buttons + animations (Play/Options/Stats/Mods/Quit) with panel/back slide animation.
- Play Game panel (mode select + player count dropdown + tooltips + F1 “times played” overlay).
- Quest select menu UI (stage icons + hardcore toggle gating + quest list + counts overlay; quest gameplay wired).
- Options panel (volume/detail/mouse sliders + “UI Info texts”; Controls supports 1..4 player selection, per-player direction-arrow toggle, and right-panel key/button/axis rebinding).
- Statistics hub (High scores / Weapons / Perks / Credits panels; playtime + weapon usage + quest counters).
- Menu terrain persists between screens (no regen on Options/Stats/etc navigation).
- Menu terrain selection matches original unlock-gated random variants (`(0,1,0)`, `(2,3,2)`, `(4,5,4)`, `(6,7,6)`).
- Survival/Rush regenerate terrain on start (menu terrain does not carry into a fresh gameplay run).
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
- Game over / high score entry screen is implemented for Survival/Rush/Typ-o.
- Quest completion/failure screens are implemented (results + failed).
- Demo/attract mode reuses the same gameplay systems (no separate “toy sim”).

### Gameplay (sandbox)

These sandboxes and runtime modules are still useful for focused iteration:

- `player_update` port (movement, aiming, reload, firing, perk timers).
- Projectile pools (main + secondary) with basic spawn/update/hit logic.
- Bonus/perk application logic + bonus HUD state.
- HUD overlay renderer (`src/crimson/ui/hud.py`) validated by mode integration tests.

### Persistence + console

- `game.cfg` status file decode/encode + checksum, loaded on boot and saved on exit.
- Statistics screen reads `game.cfg` values (quest unlock indices, mode play counters, checksum status).
- In-game console UI overlay (toggle with backtick) with commands + cvars.

### Debug views (raylib)

Available via `uv run crimson view <name>`:

- `fonts` (font preview)
- `game_over` (game over screen preview)
- `spawn-plan` (spawn plan visualization)
- `perk-menu-debug` (perk selection UI)
- `small-font-debug` (font glyph testing)
- `arsenal` (weapon/arsenal sandbox)
- `lighting-debug` (lighting/SDF sandbox)

See also:

- [Module map (Grim vs Crimson)](module-map.md)
- [RNG caller mapping workflow](rng-caller-mapping-workflow.md)
- [Mode systems](mode-systems.md)
- [Deterministic step pipeline](deterministic-step-pipeline.md)
- [Replay run start](replay-run-start.md)
- [Quest identifiers](quest-identifiers.md)
- [Netplay (rollback primary)](netplay-rollback.md)
- [LAN lockstep (fallback mode)](lan-lockstep.md)
- [Local multiplayer rewrite notes](local-multiplayer.md)
- [Rendering pipeline](rendering-pipeline.md)
- [Float parity policy](float-parity-policy.md)
- [Float expression precision map](float-expression-precision-map.md)
- [Beam rendering (classic + RTX)](beam-rendering.md)
- [CDT trace format (rewrite tooling)](cdt-trace-format.md)
- [Trace format alignment plan](trace-format-alignment.md)
- [Terrain (rewrite)](terrain.md)
- [Perks architecture (rewrite)](perks-architecture.md)
- [Original bugs (and rewrite fixes)](original-bugs.md)

## Known gaps (short list)

- Creature runtime parity gaps: remaining AI edge cases and per-weapon behaviors are still pending.
- Multiplayer (2-4 players): per-player local input is wired in Survival/Rush/Quest; deep scheme-by-scheme parity validation is still in progress.
- Rollback netplay is primary (relay + room codes, protocol v5, reconnect/resync hooks); remaining hardening work is focused on packet-impairment stress runs and lockstep fallback maintenance.
- `game.cfg` progression/unlock wiring is in place; some tail fields/counter semantics still need deeper mapping validation.
- Full Options/Controls parity (video/window mode editing, full widget set).
- Native online-score submission is out of scope; direction is a more advanced headless verification system.
- Mods/plugin runtime and Other Games/shareware ad flows are out of scope for the rewrite.

## Roadmap

See: [Rewrite status / parity gaps](status.md)
