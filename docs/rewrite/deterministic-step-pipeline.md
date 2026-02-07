---
tags:
  - status-parity
---

# Deterministic Step Pipeline

This page defines the current per-tick contract used by:

- playable runtime (`GameWorld.update`)
- replay verification runners (`sim/runners/*`)
- replay playback mode (`modes/replay_playback_mode.py`)

The shared implementation lives in `src/crimson/sim/step_pipeline.py`.

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

## Why this matters

Before this refactor, live gameplay and headless replay paths duplicated parts of the tick pipeline.
That made divergence easier (different ordering, missing presentation planning, different RNG consumption windows).

Now, all major paths execute the same step planner and emit the same command stream shape.

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

## Differential testing path

For original-game capture comparison, prefer matching at command/checksum level first:

1. tick index + command hash
2. event counters and SFX heads
3. deep state hashes / focused state diffs

This gives a stable coarse-to-fine pipeline while data mapping from the original continues to improve.
