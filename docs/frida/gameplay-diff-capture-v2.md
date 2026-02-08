---
tags:
  - status-validation
  - frida
  - differential-testing
---

# Gameplay Differential Capture V2

`scripts/frida/gameplay_diff_capture_v2.js` captures deterministic gameplay
ticks as replay-like checkpoint rows plus rich event diagnostics.

Primary output:

- `C:\share\frida\gameplay_diff_capture_v2.jsonl`

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture_v2.js
```

Just shortcut (Windows VM):

```text
just frida-gameplay-diff-capture-v2
```

## Why use v2

- Emits `event: "tick"` rows aligned to `gameplay_update_and_render`.
- Each tick includes `checkpoint` fields compatible with
  `replay convert-original-capture`.
- Captures per-tick command/event summary (`projectile_spawn`, SFX, bonus apply,
  weapon assign, damage, creature spawns, state transitions).
- Captures both template-level and low-level creature spawn paths
  (`creature_spawn_template`, `creature_spawn`, `survival_spawn_creature`,
  `creature_spawn_tinted`) with caller buckets.
- Captures input-query telemetry (`input_primary_*`, `input_any_key_pressed`) and
  RNG usage (`crt_rand`) per tick, including hashes/callers.
- Emits per-player key state snapshots (`input_player_keys`) derived from
  `player_update` key queries, so replay conversion can avoid ambiguous
  `input_any_key` unions when opposite directions appear in the same tick.
- Emits per-tick diagnostics for timing/sampling analysis:
  `diagnostics.timing`, `diagnostics.spawn`, plus `checkpoint.debug`.
  Spawn diagnostics include low-level source buckets (`top_low_level_sources`).
- Emits session fingerprint metadata (`session_id`, module hash, pointer hash) for
  run-to-run provenance.
- Emits compact `before`/`after` snapshots (including input + bindings) and
  optional detailed entity samples.

## Convert to checkpoints

```text
uv run crimson replay convert-original-capture \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl \
  analysis/frida/original_capture_v2.checkpoints.json.gz
```

This also writes `analysis/frida/original_capture_v2.crdemo.gz` by default (override with `--replay`).
The replay file is best-effort (rebuilt from input telemetry) and useful for
visual inspection; it bootstraps from the first captured tick but still does
not guarantee sidecar-level parity. Checkpoint sidecars are the source of truth
for diffing.

## Verify capture directly against rewrite sim

```text
uv run crimson replay verify-original-capture \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl
```

This path does not depend on replay playback parity. It reconstructs inputs from
capture telemetry, runs headless sim, then compares checkpoint state fields at
captured ticks and prints first divergent fields.

## Useful env knobs

- `CRIMSON_FRIDA_V2_STATES=6,9,10` (override tracked game states)
- `CRIMSON_FRIDA_V2_ALL_STATES=1` (capture ticks for all states)
- `CRIMSON_FRIDA_V2_FOCUS_TICK=1234` (capture full snapshots/samples only around a specific tick)
- `CRIMSON_FRIDA_V2_FOCUS_RADIUS=30` (window around focus tick; default `0`)
- `CRIMSON_FRIDA_V2_TICK_DETAILS_EVERY=30`
- `CRIMSON_FRIDA_V2_CREATURE_SAMPLE_LIMIT=24`
- `CRIMSON_FRIDA_V2_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_V2_BONUS_SAMPLE_LIMIT=12`
- `CRIMSON_FRIDA_V2_INCLUDE_RAW_EVENTS=1`
- `CRIMSON_FRIDA_V2_INPUT_HOOKS=0` (disable input query hooks)
- `CRIMSON_FRIDA_V2_RNG_HOOKS=0` (disable rng hooks)
- `CRIMSON_FRIDA_V2_CREATURE_SPAWN_HOOK=0` (disable low-level `creature_spawn` hook)
- `CRIMSON_FRIDA_V2_RNG_HEAD=-1` (per-tick RNG sample head size; default unlimited, `0` disables head samples)
- `CRIMSON_FRIDA_V2_RNG_CALLERS=-1` (per-tick RNG caller buckets; default unlimited)
- `CRIMSON_FRIDA_PLAYER_COUNT=2` (optional override; default uses `config_player_count` from memory)

Default sample limits are unlimited (`-1`), and `0` disables that sample stream.
Backtraces are off by default (`CRIMSON_FRIDA_INCLUDE_BT=0`).
When `CRIMSON_FRIDA_V2_FOCUS_TICK` is set, raw events are emitted only for the
focus window.
