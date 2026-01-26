# Worklog

Reverse-chronological log of notable repo changes, grouped by day.

## 2026-01-26

- Introduced `GameWorld` core and refactored survival around it; rendered terrain/sprites/decals and drove demo mode via `GameWorld` with new rendering/sim helpers.
- Built out the Play Game flow: mode select panel, quest select menu, perk selection flow, and statistics screen; matched perk menu layout and classic menu shadow blend.
- Added/expanded debug views for survival, projectiles (FX lab), camera, player sprites, decals, and small-font/vector-font comparisons (with screenshot hotkey).
- Improved gameplay parity: projectile behavior, pellet spreads/rocket splash + gameplay SFX, camera bounds/scale/shake, terrain render texture sampling, and player overlay sprite passes.
- Advanced creature parity (sprite rotation, movement/turning, anim scaling, staged deaths/corpse decals, and `fx_detail` shadow) with Frida traces for sprite/anim-phase timing.
- Large Ghidra typing pass: quest/player/perk/bonus/creature/audio/effect tables, `ui_button_t`, and hotspot globals; added a DAT-hotspots report, fixed Grim2D vtable conventions, and regenerated exports/metrics/decompiles.
- Updated docs for survival/combat status, weapon spread heat, fonts, and player sprite UV/recoil offsets; pruned addressed incoming notes.

## 2026-01-25

- Implemented the options screen and aligned options panel layout to the original; added Frida tracing for options panel behavior.
- Implemented in-game console UI with startup commands/docs; matched console backdrop colors and mono font advance.
- Added HUD overlay scaffolding and aligned layout with the decompile; added bonus pickups + sandbox rendering and matched bonus picker distribution/constants.
- Added survival XP progression and perk auto-pick; wired `player_update` runtime glue and added a player sandbox view.
- Implemented `game.cfg` status persistence; built FX pools + FX queue baking; extracted AI targeting logic and cleaned up AI internals.
- Added SFX loading/playback, split music and SFX modules, and mapped full SFX key/id tables; updated docs (survival/player contracts, status refresh, plan checkboxes) and tooling (py-spy recipe, Python 3.13 requirement).

## 2026-01-24

- Added a demo upsell purchase screen, aligned `demo_mode_start` sequencing, and improved purchase-screen copy/layout/backplasma to match the original; added an idle attract trigger.
- Ported and tested a large batch of spawn templates and timelines across tutorial/survival/rush/quest modes (spawn slots, milestone/wave ticks, quest timeline/tick); added `SpawnId` and builder-based spawn-plan dispatch.
- Added spawn-plan tooling: CLI commands, allocation reporting, and a debug view; simulated spawn slot ticking in views.
- Implemented projectile pools and default projectile meta/damage scaling; fixed bonus args + anim-phase resets and preserved `phase_seed` randomness.
- Matched menu slide animations and sign shadow pass, and kept the logo sign static between menu screens; added Frida tracing for logo pivot behavior.
- Fixed small-font rendering to be pixel-perfect; documented `fx_detail` flags/preset mapping and enabled `fx_detail` shadows by default.
- Added a Frida demo shareware patch script and improved full-version check handling.
- Named `creature_spawn_slot_alloc` and additional menu/logo callbacks in Ghidra; regenerated exports; enabled pytest-cov coverage reporting by default.

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
