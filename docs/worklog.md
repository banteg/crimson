# Worklog

Reverse-chronological log of notable repo changes, grouped by day.

## 2026-01-24

- Added a demo upsell purchase screen, aligned `demo_mode_start` sequencing, and improved purchase-screen copy/layout/backplasma to match the original.
- Matched menu slide animations and sign shadow pass, and kept the logo sign static between menu screens.
- Fixed small-font rendering to be pixel-perfect.
- Documented `fx_detail` flags/preset mapping and enabled `fx_detail` shadows by default.
- Added Frida tracing for menu logo pivot behavior.
- Named additional menu/logo-related callbacks in Ghidra and regenerated exports.

## 2026-01-23

- Ported creature spawning: spawn-plan builder/templates, spawn-id checklist, creature spawning docs, and a `crimson.creatures` package refactor.
- Improved terrain/ground parity: fixed density shift, stamp pivot/orientation, RNG consumption ordering, alpha handling, and first-frame black ground; added partial generation steps and decal baking helpers.
- Expanded Frida terrain tooling (stamp draw tracing, RNG-state capture, auto-dump on generate) and improved VM share file syncing.
- Added/expanded ground dump and quest builder tests (parity fixtures, stamp triplets, diff persistence, and snapshot rounding).
- Refactored engine/views helpers and aligned quest title/level UI overlays.
- Improved font fallbacks/accuracy by preferring PAQ fonts and matching Grim2D mono glyph positioning.
- Advanced demo/menu work with a teaser gameplay sim, upsell overlay, placeholder menu screens, panel layout fixes, terrain stability across menus, and animated quit/exit behavior.

## 2026-01-22

- Added IDA headless export/decompile flow, applied Ghidra maps during exports, and normalized signature parsing/typedef handling.
- Regenerated Ghidra and Binary Ninja exports (including full call graph) with updated Grim2D format wrapper signatures.
- Added a decompile signature diff tool and zipped additional analysis artifacts.
- Added a WSL Ghidra sync helper and documented the cross-OS `ghidra-sync` workflow.
- Mapped the mod SDK API and documented the demo/attract mode loop, plus demo-mode scaffolding and labeled globals.
- Improved Frida workflows (attach-only enforcement, configurable log paths, shortcut docs).
- Reworked docs/nav structure, metrics snapshot, status lifecycle, and assorted reference alignments.

## 2026-01-21

- Mapped and expanded mod API structs/vtables, highscore/mod info structs, and additional Ghidra data maps (creatures, projectiles, effects, UI, config/save).
- Updated Grim2D exports and vtable naming, plus Binary Ninja map/import workflows and Ghidra name-map function creation.
- Improved menu and terrain rendering parity (layout, scaling, pivot, sampling, glow pass, hover state, flicker fixes).
- Added a quest-driven ground preview and aligned ground rendering with config sizing.
- Documented menu state0 and terrain pipeline, and added audio/weapon struct docs.
- Added Frida mod API probe and tooling docs, plus zensical cheatsheet/markdown fixer.
- Added a `just zip decompile` command.

## 2026-01-20

- Added entrypoint/boot pipeline scaffolding (`crimson game` step-1 runner), boot logs/crash-to-file, cvars/console command wiring, and splash/logo timing improvements.
- Documented `crimson.cfg` and added loaders/inspectors, defaults alignment, and keybind/name slot docs.
- Added/expanded Raylib debug views (sprites, terrain, particles, UI, fonts) plus atlas/terrain/particle/icon previews and quest title layout matching.
- Improved font handling (mono font behavior, filtering, grid alignment, quest title/number positioning) with supporting docs.
- Added Frida probes/scripts for quest title colors, atlas UV selection, and boot music, with docs and hook fixes.
- Updated Ghidra/Binja exports/signatures and added the IGrim2D type header and safe signatures.
- Added bonus/perk code tables, creature type enum, and online high score protocol notes.
- Added screenshot capture for all views (hotkey `P`, saves to `screenshots/`).

## 2026-01-19

- Implemented quest builders for tiers 1–5, quest metadata, and a CLI for quest dumps.
- Added Frida tooling for quest build analysis and runtime probes (mode bytes, counts, logs).
- Documented console hotkey/secrets flow and updated Ghidra maps/exports accordingly.
- Added a CDB bridge for interactive sessions and expanded WinDbg workflow docs/justfile recipes for runtime sessions.
- Updated detangling notes for config flags and hardcore/full-version behavior.

## 2026-01-18

- Large Ghidra naming/mapping passes across Grim2D, audio, assets, CRT, and gameplay helpers.
- Synced third-party headers and documented version evidence (DirectX/DirectInput, libpng+zlib, ogg/vorbis).
- Built out Frida workflow: hooks, logging, reducers, session templates, and evidence summaries.
- Investigated secrets/credits paths (credits screen mapping, credits-flag probes/watchers, evidence summaries).
- Added a `game.cfg` (save/status) editor tool.
- Expanded Grim2D API evidence and runtime validation docs.

## 2026-01-17

- Massive data-map labeling for players, projectiles, effects, bonuses, and gameplay counters.
- Expanded Grim2D vtable mapping/evidence and related docs.
- Added atlas export tooling and spawn template generators; expanded atlas/FX docs.
- Added repo tooling (justfile, ghidra pipelines) and headers for analysis.
- Documented weapon/creature/projectile/effect structures and mappings.

## 2026-01-16

- Initialized the repo and extraction pipeline (PAQ/JAZ via Construct) with docs.
- Added an initial small-font renderer and weapons table parsing module, with supporting format notes.
- Added atlas slicing helpers and sprite atlas documentation.
- Established entrypoint tracing, detangling notes, and Ghidra name-map workflows.
- Added early Grim2D mapping docs and metrics tracking.
