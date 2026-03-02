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
Mode/session orchestration lives in `src/crimson/sim/sessions.py`.
Feature hook dispatch lives in subsystem-local registries/manifests.
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

For mode orchestration, deterministic sessions feed a unified playback driver:

- `SurvivalDeterministicSession.step_tick(...)`
- `RushDeterministicSession.step_tick(...)`
- `QuestDeterministicSession.step_tick(...)`
- `PlaybackDriver(replay, pipeline_options)`

These session adapters own mode-level elapsed timers and spawn pacing, and are now used by:

- replay verification/timeline extraction (`run_replay`, `run_replay_info`, via `PlaybackDriver`)
- replay playback mode
- interactive Survival/Rush mode loops

## Why this matters

Before this refactor, live gameplay and headless replay paths duplicated parts of the tick pipeline.
That made divergence easier (different ordering, missing presentation planning, different RNG consumption windows).

Now, all major paths execute the same step planner and emit the same command stream shape.

## Studyability hook topology

The deterministic tick/presentation flow now dispatches selected behavior through explicit feature hooks:

- Perk world-step hooks:
  - manifest: `src/crimson/perks/runtime/manifest.py`
  - contracts: `src/crimson/perks/runtime/hook_types.py`
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

`WorldState.step` and `apply_world_presentation_step` consume this same stream in a stable per-tick order across live/headless/playback paths.

### RNG trace mode

Replay checkpoint verification exposes `--trace-rng`:

```bash
uv run crimson replay verify-checkpoints replay.crd --trace-rng
```

When enabled, checkpoints include presentation draw counters (e.g. `ps_draws_total`, per-consumer marks) to help localize drift.

## Replay verify (headless score validation)

`replay verify` is simulation-first: it runs the replay headlessly and emits resulting run stats (ticks, elapsed time, score, kills, weapon/shots stats, RNG state).

Server-oriented / machine-readable flow:

```bash
uv run crimson replay verify replay.crd --format json
```

Claim validation flow (returns exit code `3` when replay header claimed stats mismatch):

```bash
uv run crimson replay verify replay.crd
```

## Replay info (timeline extraction for analysis/infographics)

`replay info` runs the same deterministic replay simulation and emits a chronological event timeline.

Default output includes core events (`bonus_pickup`, `weapon_change`, `perk_pick`,
`level_up`, `health_damage`, `health_heal`, `player_death`). Use `--verbose` to
also include extra context events (`perk_menu_open`, `state_transition`,
`creature_deaths`).

Default human output is compact line-oriented text:

```bash
uv run crimson replay info replay.crd
```

Machine-readable output:

```bash
uv run crimson replay info replay.crd --format json --json-out analysis/replay/info.json
```

Current JSON payload schema (`schema_version=1`) is a single document:

- top-level: `schema_version`, `status`, `replay`, `replay_sha256`, `summary`, `timeline`
- `summary`: `game_mode_id`, `tick_rate`, `ticks_simulated`, `elapsed_ms`, `player_count`, `event_count`, `event_counts_by_kind`
- `timeline[]`: `tick_index`, `elapsed_ms`, `elapsed_s`, `kind`, `player_index`, `detail`, `data`

This payload is intended for downstream replay analytics/visualization pipelines
(for example timeline charts and aggregate infographic generation on the website).

## Replay benchmark (headless/render throughput + optional hotspots)

`replay benchmark` runs replay simulation multiple times and reports wall-time
throughput metrics (`wall_ms`, ticks/second, and realtime multiplier).

Use `--mode headless` (default) for simulation-only timings (`run_replay`), or
`--mode render` to include update/draw presentation cost from replay playback.
Decode/load costs are still outside measured samples in both modes.

Timing-only run:

```bash
uv run crimson replay benchmark replay.crd --runs 8 --warmup-runs 2
```

Render-mode timing run:

```bash
uv run crimson replay benchmark replay.crd --mode render --runs 8 --warmup-runs 2
```

Machine-readable run:

```bash
uv run crimson replay benchmark replay.crd --format json --json-out analysis/replay/benchmark.json
```

Include one `cProfile` pass and hotspot summary:

```bash
uv run crimson replay benchmark replay.crd --profile --profile-sort cumtime --top 20 --profile-out artifacts/profiling/replay.pstats
```

Collect per-tick render telemetry + SVG timelines (render mode):

```bash
uv run crimson replay benchmark replay.crd --mode render --render-telemetry --render-telemetry-out artifacts/profiling/replay_telemetry.json --render-charts-out-dir artifacts/profiling/replay_charts
```

## Replay render (ffmpeg video export)

`replay render` plays back a replay offscreen, captures each frame, and encodes
an MP4 with `ffmpeg` (default 60fps, `libx264`, `crf=16`, `preset=slow`).

Default export:

```bash
uv run crimson replay render replay.crd
```

Custom output/quality:

```bash
uv run crimson replay render replay.crd --out artifacts/replay.mp4 --fps 60 --crf 14 --preset slow --overwrite
```

## Replay checkpoints comparison

Checkpoints now store `command_hash` per sampled tick.

Verification order is:

1. compare `command_hash` first (fast fail on command-stream divergence)
2. compare deep `state_hash` and detailed checkpoint fields (slow diagnosis)

This keeps replay verification focused on the same command stream that feeds both presentation and headless validation.

Replay-to-sidecar verification path:

```bash
uv run crimson replay verify-checkpoints replay.crd
```

Sidecar-to-sidecar comparator path:

```bash
uv run crimson replay diff-checkpoints expected.crd.chk actual.crd.chk
```

It reports first divergence tick with command/state/rng context.

## Differential testing path

For original-game comparison, use unified trace (`.cdt`) tooling.
Frida capture host finalizes raw JSONL directly into `.cdt`.

```bash
uv run scripts/frida/gameplay_diff_capture_host.py --raw-path gameplay_diff_capture.jsonl --output-dir traces
```

Then compare original-vs-rewrite traces directly:

```bash
uv run crimson dbg diff traces/original.cdt traces/rewrite.cdt
uv run crimson dbg bisect traces/original.cdt traces/rewrite.cdt
uv run crimson dbg focus traces/original.cdt traces/rewrite.cdt --tick <n>
```

This removes replay-side conversion bridges and keeps all implementations on one structural trace format.
