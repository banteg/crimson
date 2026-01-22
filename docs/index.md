# Crimsonland reverse engineering notes

Reverse engineering and rewriting Crimsonland v1.9.93 in Python + raylib.

!!! abstract "Current state"
    The rewrite boots to a working menu with terrain rendering, music playback, and
    demo/attract mode scaffolding. All 50 quest builders are runtime-validated and
    mirrored in Python. Asset pipeline (PAQ/JAZ) is complete. Next milestone:
    player input + weapon firing to unlock the gameplay loop.

## Analysis

- [Binary Analysis](binary-analysis.md)
- [Entrypoint trace](entrypoint.md)
- [Boot / Loading Sequence](boot-sequence.md)
- [Detangling notes](detangling.md)
- [Progress metrics](metrics.md)

## Rewrite (Python + raylib)

- [Rewrite overview](rewrite/index.md)
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
- [Game mode map](game-mode-map.md)
- [Quest builders](quest-builders.md)
- [Audio](audio.md)

## Structs & pools

- [Structs overview](structs/index.md)
- [Player struct](structs/player.md)
- [Creature struct](structs/creature.md)
- [Projectile struct](structs/projectile.md)
- [Effects pools](structs/effects.md)

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
