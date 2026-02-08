---
tags:
  - status-scoping
---

# PRD: Deterministic Simulation, Single RNG, and Differential Replay Validation

Last updated: 2026-02-07

## Context

We are porting the original game with high fidelity.
The original uses a single RNG stream; the rewrite historically separated simulation/presentation RNG and is migrating to single-stream behavior.
We need an architecture that supports:

- deterministic interactive play
- deterministic replay playback
- deterministic headless verification
- eventual differential testing against captures from the original game
- future multiplayer (LAN first, then networked lockstep improvements)
- highly studyable code that reads like an executable reference spec

## Problem Statement

Current deterministic infrastructure is strong but still has split-brain risk:

- RNG stream split (sim vs presentation) can diverge from original behavior.
- Live, replay, and headless modes are closer now, but not yet fully unified around a single-stream model.
- Differential testing against original captures needs first-class tick contracts and stable diagnostics.

## Product Goals

1. Use one authoritative RNG stream per world/session, matching original behavior.
2. Make headless simulation a first-class runtime mode that emits deterministic presentation commands.
3. Make renderer/audio consumers of commands only (no RNG, no gameplay mutations).
4. Verify deterministic parity via replay + sidecar checkpoints and command hashes.
5. Enable differential testing against original memory-hook captures and first-divergence investigation.
6. Keep architecture compatible with future multiplayer lockstep.
7. Organize gameplay features into small intent-focused modules (for example `crimson/bonuses/fire_bullets.py`) with explicit hook entrypoints.

## Non-Goals (for this PRD scope)

1. Implement full multiplayer networking stack.
2. Fully redesign rendering assets or UI systems.
3. Solve every remaining gameplay parity gap unrelated to deterministic pipeline.

## Guiding Principles

1. Simulation is authoritative.
2. Input stream is the only external driver of simulation.
3. Presentation commands are deterministic outputs of simulation tick processing.
4. Rendering/audio are side-effect consumers, not simulation participants.
5. Determinism diagnostics must identify first divergence quickly.
6. Code should prioritize readability and traceability over clever abstraction.

## Target Architecture

## Core Tick Contract

Single entrypoint (conceptual):

`tick(input_frame) -> TickResult(state_delta, presentation_commands, diagnostics)`

Where:

- `input_frame` is per-player input for one tick.
- `presentation_commands` includes render/sfx/music intent data only.
- `diagnostics` includes hashes and RNG markers.

## Runtime Modes (all call same tick contract)

1. Interactive mode:
   - live inputs -> tick -> consume presentation commands.
2. Replay playback mode:
   - replay inputs -> tick -> consume presentation commands.
3. Headless verification mode:
   - replay inputs -> tick -> discard presentation commands, compare diagnostics/checkpoints.

## RNG Model

1. One RNG stream owned by gameplay state.
2. Presentation planning consumes that same stream in deterministic order.
3. RNG diagnostics are phase-labeled for drift localization.

## Presentation Layer Boundaries

Simulation emits data commands (no texture handles, no raylib objects).
Renderer/audio layer maps commands to concrete assets/effects.

## Feature Module Topology and Hooks

Simulation behavior should be split into small feature modules with clear ownership.

Examples:

- `crimson/bonuses/fire_bullets.py`
- `crimson/bonuses/freeze.py`
- `crimson/perks/hot_tempered.py`
- `crimson/weapons/rocket_launcher.py`

Each feature module should contain:

- behavior: deterministic update/apply logic
- intent/spec notes: short docstring/comments describing original intent/parity caveats
- config/constants: local constants close to logic
- hook functions: explicit entrypoints used by the main tick pipeline

The tick pipeline should dispatch through registries or ordered hook lists rather than large mode-specific god functions.

## Functional Requirements

1. Single RNG stream is used for both gameplay and presentation command planning.
2. No renderer/audio code is allowed to consume simulation RNG.
3. Replay checkpoints include:
   - `state_hash`
   - `command_hash`
   - `rng_state`
   - selected `rng_marks`
4. Replay verification compares in this order:
   - command hash
   - state hash
   - detailed field diffs
5. Differential runner can compare rewrite outputs against original-capture sidecars and report first mismatch tick.
6. Input contract supports N players with deterministic ordering by player index.
7. Feature hooks are deterministic and side-effect-bounded (no hidden renderer/audio coupling).
8. Core tick orchestration module remains small and delegates feature logic to dedicated modules.

## Data Contracts

## Replay/Checkpoint Sidecar (Rewrite)

Per sampled tick:

- tick index
- state hash
- command hash
- rng state
- rng marks
- event summary

## Original Capture Sidecar (Target)

Per sampled tick (minimum viable set):

- tick index
- input snapshot (optional in sidecar if already in replay)
- command/event summary compatible with rewrite command hashing
- rng state (if capturable)
- selected world fields for debugging

## Rollout Plan and Progress

## Phase 0: Foundation (Done)

- [x] Shared deterministic tick pipeline introduced (`sim/step_pipeline.py`).
- [x] Live runtime, replay runners, and replay playback wired to shared deterministic step path.
- [x] Checkpoints now carry `command_hash`.
- [x] Replay verify fast-fails on `command_hash` mismatch.
- [x] Optional RNG trace mode added (`--trace-rng`).
- [x] Live-vs-headless parity tests for Survival/Rush added.

## Phase 1: Single RNG Stream Migration (In Progress)

- [x] Remove separate presentation RNG usage from runtime/replay code paths.
- [x] Feed presentation planning from the authoritative simulation RNG.
- [x] Preserve deterministic command order and existing parity behavior.
- [x] Update RNG tests to assert single-stream invariants.
- [x] Document any intentional fidelity deviations discovered during migration (none introduced in this migration slice; parity guarded by deterministic command/state hash tests).

## Phase 2: Headless-First Runtime API

- [x] Define explicit headless session API for stepping ticks and collecting outputs.
- [x] Refactor interactive/replay entrypoints to use headless session adapter directly.
- [x] Ensure render/audio layers consume commands only.
- [x] Add smoke tests for all three runtime modes calling the same tick API.

Current scope for the checked items is Survival/Rush deterministic loops (interactive + playback + replay verification).

## Phase 2.5: Studyability-First Module Refactor

- [x] Define module conventions for feature files (`behavior`, `intent/spec`, `config/constants`, `hooks`).
- [x] Introduce hook registries per subsystem (perks world-step hooks, bonus pickup FX hooks, presentation projectile-decal hooks).
- [x] Migrate high-churn features first (Fire Bullets impact decals, Freeze pickup/presentation helpers, Reflex Boosted and Final Revenge perk hooks) into dedicated modules.
- [x] Add lightweight architecture tests/checks that prevent growth of monolithic tick functions.

## Phase 3: Differential Testing with Original Captures

- [x] Define original capture schema and conversion pipeline.
- [x] Add comparator that reports first divergence tick with command/state/rng context.
- [x] Add tooling command to run diff quickly on replay + sidecar pairs.
- [ ] Add at least one golden differential fixture from original capture.

## Phase 4: Multiplayer Determinism Readiness

- [x] Promote per-player input frame contract as first-class (deterministic ordering).
- [x] Add lockstep-oriented tick validation tests for multi-player input streams.
- [x] Ensure replay and checkpoint formats remain compatible with multiplayer expansion.

## Acceptance Criteria

1. Given same replay input stream, interactive, playback, and headless modes produce identical `command_hash` and `state_hash` at sampled ticks.
2. Only one RNG state exists for simulation tick processing and presentation planning.
3. Diff tool reports first divergence tick and includes enough context to debug without manual binary tracing.
4. Multiplayer input schema is deterministic and replay-compatible.
5. Feature behavior is discoverable by file path and hook name (engineers can locate behavior quickly without tracing giant modules).

## Risks and Mitigations

1. Risk: single-stream migration changes existing behavior unexpectedly.
   Mitigation: migrate behind focused parity tests and checkpoint comparisons.
2. Risk: presentation command schema grows too engine-specific.
   Mitigation: enforce data-only command contract and keep renderer mapping separate.
3. Risk: original capture mapping lacks one-to-one fields early.
   Mitigation: compare command/event summaries first, then deepen field coverage iteratively.

## Open Questions

1. Which original-memory fields are cheapest/highest-value for early sidecar capture?
2. Do we need tick-level floating-point normalization for capture comparisons?
3. Should RNG marks be persisted in all checkpoints or only debug mode to keep files smaller?

## References

- `docs/rewrite/deterministic-step-pipeline.md`
- `src/crimson/sim/step_pipeline.py`
- `src/crimson/replay/checkpoints.py`
- `src/crimson/cli.py`
