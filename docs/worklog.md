---
tags:
  - status-tracking
---

# Worklog

Reverse-chronological log of notable repo changes, grouped by day.

## 2026-01-20

- Added entrypoint boot plan scaffolding and a `crimson game` step-1 runner.
- Documented `crimson.cfg` and added a Construct-based loader/writer.
- Added/expanded Raylib debug views (sprites, terrain, particles, UI, fonts) and quest title layout matching.
- Added a ground demo view that renders per-quest terrain (level switching + title overlay).
- Added Frida probes for quest title colors and atlas UV selection, plus supporting docs.
- Added screenshot capture for all views (hotkey `P`, saves to `screenshots/`).

## Notes

- “Console” in the classic game refers to both the on-screen tilde console and the `console.log` file; for reimplementation we’re starting with file/stdout logging only.

## 2026-01-19

- Implemented quest builders for tiers 1–5, quest metadata, and a CLI for quest dumps.
- Added Frida tooling for quest build analysis and runtime probes (mode bytes, counts, logs).
- Documented console hotkey/secrets flow and updated Ghidra maps/exports accordingly.
- Expanded WinDbg workflow docs and justfile recipes for runtime sessions.
- Updated detangling notes for config flags and hardcore/full-version behavior.

## 2026-01-18

- Large Ghidra naming/mapping passes across Grim2D, audio, assets, CRT, and gameplay helpers.
- Built out Frida workflow: hooks, logging, reducers, session templates, and evidence summaries.
- Investigated secrets/credits paths and added CDB bridge tooling for interactive debugging.
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
- Added atlas slicing helpers and sprite atlas documentation.
- Established entrypoint tracing, detangling notes, and Ghidra name-map workflows.
- Added early Grim2D mapping docs and metrics tracking.
