---
tags:
  - status-parity
---

# Deterministic Step Pipeline

This page defines the current per-tick contract used by:

- playable runtime (`GameWorld.update`)
- replay verification runners (`sim/runners/*`)
- replay playback mode (`modes/replay_playback_mode.py`)
- oracle headless emission (`oracle.py`)

The shared implementation lives in `src/crimson/sim/step_pipeline.py`.
Mode/session orchestration lives in `src/crimson/sim/sessions.py`.
Feature hook registries now live under `src/crimson/features/`.
Multiplayer input normalization lives in `src/crimson/sim/input_frame.py`.

## Tick contract

Per tick, we run:

1. Inputs + mode flags are applied to world state.
2. Core simulation step runs (`WorldState.step`).
3. Presentation commands are planned deterministically (`apply_world_presentation_step`).

Output is a `DeterministicStepResult` with:

- `dt_sim`: effective dt after Reflex Boost scaling
- `events`: sim events (`hits`, `deaths`, `pickups`, `sfx`)
- `presentation`: deterministic presentation commands (`trigger_game_tune`, ordered `sfx_keys`)
- `command_hash`: stable checksum of the presentation command stream
- optional presentation-phase RNG draw trace (for debugging)

For Survival/Rush orchestration, the reusable wrappers are:

- `SurvivalDeterministicSession.step_tick(...)`
- `RushDeterministicSession.step_tick(...)`

These session adapters own mode-level elapsed timers and spawn pacing, and are now used by:

- replay runners (`run_survival_replay`, `run_rush_replay`)
- replay playback mode
- interactive Survival/Rush mode loops
- oracle headless stepping (summary/full/hash output)

## Why this matters

Before this refactor, live gameplay and headless replay paths duplicated parts of the tick pipeline.
That made divergence easier (different ordering, missing presentation planning, different RNG consumption windows).

Now, all major paths execute the same step planner and emit the same command stream shape.

## Studyability hook topology

The deterministic tick/presentation flow now dispatches selected behavior through explicit feature hooks:

- Perk world-step hooks:
  - registry: `src/crimson/features/perks/registry.py`
  - hooks: Reflex Boosted dt scaling, Final Revenge death burst
- Bonus pickup presentation hooks:
  - registry: `src/crimson/bonuses/pickup_fx.py`
  - hooks: Freeze/Reflex Boost pickup ring effects (+ shared burst behavior)
- Projectile decal presentation hooks:
  - registry: `src/crimson/features/presentation/projectile_decals.py`
  - hooks: Fire Bullets/Gauss large streak decals

This keeps `WorldState.step` and `apply_world_presentation_step` focused on orchestration while feature intent lives in dedicated modules.

## RNG policy

The pipeline now uses one authoritative RNG stream:

- simulation + presentation RNG: `state.rng`

`WorldState.step` and `apply_world_presentation_step` consume this same stream in a stable per-tick order across live/headless/playback paths. Replay verification can still trace presentation-phase draw counts per consumer label.

### RNG trace mode

Replay verification exposes `--trace-rng`:

```bash
uv run crimson replay verify replay.crdemo.gz --trace-rng
```

When enabled, checkpoints include presentation draw counters (e.g. `ps_draws_total`, per-consumer marks) to help localize drift.

## Replay checkpoints and verification

Checkpoints now store `command_hash` per sampled tick.

Verification order is:

1. compare `command_hash` first (fast fail on command-stream divergence)
2. compare deep `state_hash` and detailed checkpoint fields (slow diagnosis)

This keeps replay verification focused on the same command stream that feeds both presentation and headless validation.

There is also a sidecar-to-sidecar comparator path:

```bash
uv run crimson replay diff-checkpoints expected.checkpoints.json.gz actual.checkpoints.json.gz
```

It reports first divergence tick with command/state/rng context.

## Differential testing path

For original-game capture comparison, use capture-native verification first:

```bash
uv run crimson original verify-capture capture.json
```

This compares checkpoint state fields at captured ticks and reports first
divergence with field-level context. By default it ignores command/state hash
domains from the original executable and rewrite RNG mark/state domains.

Original-capture sidecars now have a dedicated schema + converter:

```bash
uv run crimson original convert-capture capture.json.gz expected.checkpoints.json.gz
```

`convert-capture` accepts canonical gameplay-diff capture files only (`.json` /
`.json.gz`).

The same command now also writes a replay file next to the checkpoints
(default: `expected.crdemo.gz`, override with `--replay`).
This replay is reconstructed from captured input telemetry and is intended for
inspection/debugging. It also bootstraps initial state from the first captured
tick, but checkpoint sidecars remain the authoritative verification artifact.

Some domains are still intentionally sparse in raw traces (for example detailed
death-ledger ownership/reward attribution), and remain explicit "unknown"
sentinels so differential comparison can focus on captured fields without false
mismatches.

The converted file can be compared directly with rewrite checkpoints using `replay diff-checkpoints`.
