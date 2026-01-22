# Crimsonland reverse engineering notes

This site tracks the file formats and asset pipeline we have verified from the
decompiled Crimsonland v1.9.93 executable and game data.

!!! note "Metrics snapshot"
    - Goal focus: evidence-backed understanding + rewrite parity (see [metrics](metrics.md)).
    - High-confidence: Quests (runtime-validated); PAQ/JAZ formats (format evidence).
    - Grim2D has runtime hits, but the subsystem is still draft.
    - Rewrite readiness: specs for PAQ/JAZ/Quest builders; tests and parity are TBD.
    - Known rewrite deltas: none recorded yet.

## Analysis

- [Binary Analysis](binary-analysis.md) — Tracking
- [Entrypoint trace](entrypoint.md) — In progress
- [Boot / Loading Sequence](boot-sequence.md) — In progress
- [Detangling notes](detangling.md) — In progress
- [Progress metrics](metrics.md) — Tracking

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
- [SFX ID map](sfx-id-map.md) — Tracking
- [SFX usage](sfx-usage.md) — Tracking
- [SFX labels](sfx-labels.md) — Tracking

## Structs & pools

- [Player struct](player-struct.md) — Draft
- [Creature struct](creature-struct.md) — Draft
- [Projectile struct](projectile-struct.md) — Draft
- [Effects pools](effects-struct.md) — Draft
- [Audio entry struct](audio-entry.md) — Draft

## Grim2D

- [Grim2D overview](grim2d-overview.md) — Draft
- [Grim2D API vtable](grim2d-api.md) — Draft
- [Grim2D API evidence](grim2d-api-evidence.md) — Draft
- [Grim2D runtime validation notes](grim2d-runtime-validation.md) — Tracking

## Runtime tooling

- [Frida workflow](frida-workflow.md) — In progress
- [Frida sessions](frida/sessions.md) — Template
- [WinDbg / CDB workflow](windbg.md) — In progress

## Gameplay notes

- [UI elements](ui-elements.md) — Draft
- [In-game console](console.md) — Draft
- [Secrets and unlocks](secrets.md) — Draft
- [Secret Weapon Candidates](secret-weapon-candidates.md) — Draft

## Cheatsheets

- [Frida GumJS cheatsheet](cheatsheets/frida.md)
- [raylib (Python) cheatsheet](cheatsheets/raylib.md)
- [Zensical.org Markdown cheat sheet](cheatsheets/zensical.md)
- [Zig 0.15 cheatsheet](cheatsheets/zig.md)

## Tracking & meta

- [Work status model](work-status.md) — Draft
- [Worklog](worklog.md) — Tracking
- [Build provenance and hashes](provenance.md) — Tracking
- [Third-party libraries](third-party-libs.md) — Tracking
- [Refactor attempt](refactor.md) — Planned
