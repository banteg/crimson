# Crimsonland reverse engineering notes

Reverse engineering and rewriting Crimsonland v1.9.93 in Python + raylib.

!!! abstract "Current state"
    The rewrite boots to a working menu with terrain rendering, music playback, and
    demo/attract mode scaffolding. All 50 quest builders are runtime-validated and
    mirrored in Python. Asset pipeline (PAQ/JAZ) is complete. Next milestone:
    player input + weapon firing to unlock the gameplay loop.

## Analysis

- [Binary Analysis](binary-analysis.md) — Tracking
- [Entrypoint trace](entrypoint.md) — In progress
- [Boot / Loading Sequence](boot-sequence.md) — In progress
- [Detangling notes](detangling.md) — In progress
- [Progress metrics](metrics.md) — Tracking

## Rewrite (Python + raylib)

- [Rewrite overview](rewrite/index.md) — Draft
- [Rewrite tech tree](rewrite/tech-tree.md) — Tracking

## Crimsonland.exe

- [Crimsonland.exe overview (by concern)](crimsonland-exe/index.md) — Draft
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

- [PAQ archives](formats/paq.md) — Completed
- [JAZ textures](formats/jaz.md) — Completed
- [Fonts](formats/fonts.md) — Draft
- [Sprite atlas cutting](atlas.md) — In progress
- [Extraction pipeline](pipeline.md) — In progress
- [Python executable spec](python-executable-spec.md) — Draft
- [Save/status file (game.cfg)](save-status-format.md) — Draft
- [Config blob (crimson.cfg)](crimson-cfg.md) — Draft

## Data tables & IDs

- [Weapon table](weapon-table.md) — In progress
- [Weapon ID map](weapon-id-map.md) — Draft
- [UI weapon icon atlas](ui-wicons-map.md) — Tracking
- [Perk ID map](perk-id-map.md) — Draft
- [Bonus ID map](bonus-id-map.md) — Draft
- [Game mode map](game-mode-map.md) — Draft
- [Quest builders](quest-builders.md) — High confidence
- [Audio](audio.md) — Tracking

## Structs & pools

- [Structs overview](structs/index.md) — Draft
- [Player struct](structs/player.md) — Draft
- [Creature struct](structs/creature.md) — Draft
- [Projectile struct](structs/projectile.md) — Draft
- [Effects pools](structs/effects.md) — Draft

## Grim2D

- [Grim2D overview](grim2d/index.md) — Draft
- [Grim2D API vtable](grim2d/api.md) — Draft
- [Grim2D API evidence](grim2d/api-evidence.md) — Draft
- [Grim2D runtime validation](grim2d/runtime-validation.md) — Tracking

## Runtime tooling

- [Frida](frida/index.md) — In progress
- [WinDbg / CDB](windbg/index.md) — In progress

## Gameplay notes

- [UI elements](ui-elements.md) — Draft
- [In-game console](console.md) — Draft
- [Secrets and unlocks](secrets.md) — Draft
- [Secret Weapon Candidates](secret-weapon-candidates.md) — Draft

## Tracking & meta

- [Work status model](work-status.md) — Draft
- [Worklog](worklog.md) — Tracking
- [Build provenance and hashes](provenance.md) — Tracking
- [Third-party libraries](third-party-libs.md) — Tracking
- [Refactor attempt](refactor.md) — Planned

## Cheatsheets

- [Frida GumJS](cheatsheets/frida.md)
- [raylib (Python)](cheatsheets/raylib.md)
- [Zensical Markdown](cheatsheets/zensical.md)
- [Zig 0.15](cheatsheets/zig.md)
