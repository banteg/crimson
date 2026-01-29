# Crimsonland reverse engineering notes

Reverse engineering and rewriting Crimsonland v1.9.93 in Python + raylib.

!!! abstract "Current state"
    The rewrite now runs end-to-end: boot → menus/options → in-game for Survival,
    Rush, Quests (HUD + completion + results/failed flows), Tutorial, and
    Typ-o-Shooter, all via `uv run crimson game`. The front-end includes perk
    selection, statistics/high-scores screens, a console overlay, and the
    demo/trial overlay path for parity testing. Rendering covers terrain,
    sprites, decals, particles, and the core world draw order; audio covers
    music plus most moment-to-moment SFX (weapons, bonuses, level-ups, and
    creature deaths). Remaining work is mostly breadth and polish: full
    weapon/creature coverage, multiplayer (2–4 players) completeness, remaining
    SFX/event hooks, and continued binary map/type recovery.

<!-- data-map-coverage:start -->
Data map coverage: 15.42% (471 / 3055 symbols)
<!-- data-map-coverage:end -->

## Analysis

- [Binary Analysis](binary-analysis.md)
- [Entrypoint trace](entrypoint.md)
- [Boot / Loading Sequence](boot-sequence.md)
- [Detangling notes](detangling.md)
- [Progress metrics](metrics.md)

## Rewrite (Python + raylib)

- [Rewrite overview](rewrite/index.md)
- [Rewrite status / parity gaps](rewrite/status.md)
- [Rewrite tech tree](rewrite/tech-tree.md)
- [Terrain (rewrite)](rewrite/terrain.md)

## Crimsonland.exe

- [Crimsonland.exe overview (by concern)](crimsonland-exe/index.md)
- [State machine](crimsonland-exe/state-machine.md)
- [Frame loop](crimsonland-exe/frame-loop.md)
- [Gameplay glue](crimsonland-exe/gameplay.md)
- [Rendering pipeline](crimsonland-exe/rendering.md)
- [UI and menus](crimsonland-exe/ui.md)
- [Main menu (state 0)](crimsonland-exe/main-menu.md)
- [Screens and flows](crimsonland-exe/screens.md)
- [Demo / attract mode](crimsonland-exe/demo-mode.md)
- [Online high scores](crimsonland-exe/online-scores.md)
- [Mods (CMOD plugins)](crimsonland-exe/mods.md)
- [Terrain pipeline](crimsonland-exe/terrain.md)

## Formats & pipeline

- [Formats overview](formats/index.md)
- [PAQ archives](formats/paq.md)
- [JAZ textures](formats/jaz.md)
- [Fonts](formats/fonts.md)
- [Sprite atlas cutting](atlas.md)
- [Extraction pipeline](pipeline.md)
- [Python executable spec](python-executable-spec.md)
- [Save/status file (game.cfg)](save-status-format.md)
- [Config blob (crimson.cfg)](crimson-cfg.md)

## Data tables & IDs

- [Weapon table](weapon-table.md)
- [Weapon ID map](weapon-id-map.md)
- [UI weapon icons](ui-weapon-icons.md)
- [Perk ID map](perk-id-map.md)
- [Bonus ID map](bonus-id-map.md)
- [Bonus drop rates](bonus-drop-rates.md)
- [Game mode map](game-mode-map.md)
- [Quest builders](quest-builders.md)
- [Audio](audio.md)

## Structs & pools

- [Structs overview](structs/index.md)
- [Player struct](structs/player.md)
- [Creature pool struct](creatures/struct.md)
- [Projectile struct](structs/projectile.md)
- [Effects pools](structs/effects.md)

## Creatures

- [Creatures overview](creatures/index.md)
- [Spawning (templates)](creatures/spawning.md)
- [Animations](creatures/animations.md)
- [AI](creatures/ai.md)

## Grim2D

- [Grim2D overview](grim2d/index.md)
- [Grim2D API vtable](grim2d/api.md)
- [Grim2D API evidence](grim2d/api-evidence.md)
- [Grim2D runtime validation](grim2d/runtime-validation.md)

## Runtime tooling

- [Frida](frida/index.md)
- [WinDbg / CDB](windbg/index.md)

## Gameplay notes

- [UI elements](ui-elements.md)
- [In-game console](console.md)
- [Secrets](secrets/index.md)

## Tracking & meta

- [Work status model](work-status.md)
- [Worklog](worklog.md)
- [Build provenance and hashes](provenance.md)
- [Third-party libraries](third-party-libs.md)

## Cheatsheets

- [Frida GumJS](cheatsheets/frida.md)
- [raylib (Python)](cheatsheets/raylib.md)
- [Zensical Markdown](cheatsheets/zensical.md)
- [Zig 0.15](cheatsheets/zig.md)
