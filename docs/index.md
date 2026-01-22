# Crimsonland reverse engineering notes

This site tracks the file formats and asset pipeline we have verified from the
decompiled Crimsonland v1.9.93 executable and game data.

Overall naming coverage: 36.4% (648 / 1779 functions named or inferred).
<!-- data-map-coverage:start -->
Data map coverage: 19.65% (654 / 3328 symbols)
<!-- data-map-coverage:end -->

## Overview and boot

- [Binary Analysis](binary-analysis.md) — Tracking
- [Entrypoint trace](entrypoint.md) — In progress
- [Boot / Loading Sequence](boot-sequence.md) — In progress

## Formats and pipeline

- [PAQ archives](formats/paq.md) — Completed
- [JAZ textures](formats/jaz.md) — Completed
- [Fonts](formats/fonts.md) — Draft
- [Sprite atlas cutting](atlas.md) — In progress
- [Extraction pipeline](pipeline.md) — In progress
- [Python executable spec](python-executable-spec.md) — Draft
- [Save/status file (game.cfg)](save-status-format.md) — Draft
- [Config blob (crimson.cfg)](crimson-cfg.md) — Draft

## Data tables and IDs

- [Weapon table](weapon-table.md) — In progress
- [Weapon ID map](weapon-id-map.md) — Draft
- [UI weapon icon atlas](ui-wicons-map.md) — Tracking
- [Perk ID map](perk-id-map.md) — Draft
- [Bonus ID map](bonus-id-map.md) — Draft
- [SFX ID map](sfx-id-map.md) — Tracking
- [SFX usage](sfx-usage.md) — Tracking
- [SFX labels](sfx-labels.md) — Tracking
- [Game mode map](game-mode-map.md) — Draft
- [Quest builders](quest-builders.md) — High confidence

## Structs and pools

- [Player struct](player-struct.md) — Draft
- [Creature struct](creature-struct.md) — Draft
- [Projectile struct](projectile-struct.md) — Draft
- [Effects pools](effects-struct.md) — Draft
- [Audio entry struct](audio-entry.md) — Draft

## Crimsonland.exe subsystems

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

## Grim2D

- [Grim2D overview](grim2d-overview.md) — Draft
- [Grim2D API vtable](grim2d-api.md) — Draft
- [Grim2D API evidence](grim2d-api-evidence.md) — Draft
- [Grim2D runtime validation notes](grim2d-runtime-validation.md) — Tracking

## Runtime tooling

- [Frida workflow](frida-workflow.md) — In progress
- [Frida sessions](frida/sessions.md) — Template
- [WinDbg / CDB workflow](windbg.md) — In progress

## Cheatsheets

- [Frida GumJS cheatsheet](cheatsheets/frida.md)
- [raylib (Python) cheatsheet](cheatsheets/raylib.md)
- [Zensical.org Markdown cheat sheet](cheatsheets/zensical.md)
- [Zig 0.15 cheatsheet](cheatsheets/zig.md)

## Gameplay notes and secrets

- [UI elements](ui-elements.md) — Draft
- [In-game console](console.md) — Draft
- [Secrets and unlocks](secrets.md) — Draft
- [Secret Weapon Candidates](secret-weapon-candidates.md) — Draft
- [Detangling notes](detangling.md) — In progress

## Tracking and meta

- [Progress metrics](metrics.md) — Tracking
- [Work status model](work-status.md) — Draft
- [Worklog](worklog.md) — Tracking
- [Build provenance and hashes](provenance.md) — Tracking
- [Third-party libraries](third-party-libs.md) — Tracking
- [Refactor attempt](refactor.md) — Planned
