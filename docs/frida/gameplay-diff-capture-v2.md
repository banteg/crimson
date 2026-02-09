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
  `secondary_projectile_spawn`, weapon assign, damage, creature spawns, state transitions).
- Captures projectile hit resolves from native `creature_find_in_radius` when called by
  `projectile_update` (`event_counts.projectile_find_hit` + head rows with `corpse_hit`),
  so missing corpse-hit RNG branches can be diagnosed directly.
- Captures both template-level and low-level creature spawn paths
  (`creature_spawn_template`, `creature_spawn`, `survival_spawn_creature`,
  `creature_spawn_tinted`) with caller buckets.
- Captures input-query telemetry (`input_primary_*`, `input_any_key_pressed`) and
  RNG usage (`crt_rand`) per tick, including hashes/callers.
- Captures perk applications (`perk_apply`) including outside-tick carry
  (`perk_apply_outside_before`) so replay conversion can reconstruct picked perk IDs.
- Captures RNG rolls with stable per-session sequence IDs (`seq`), per-tick
  call indices (`tick_call_index`), and mirrored CRT state transitions
  (`state_before_u32`/`state_after_u32`) so branch drift can be anchored by
  RNG order instead of absolute tick numbers.
- Emits per-player key state snapshots (`input_player_keys`) derived from
  `player_update` key queries, so replay conversion can avoid ambiguous
  `input_any_key` unions when opposite directions appear in the same tick.
- Emits per-tick diagnostics for timing/sampling analysis:
  `diagnostics.timing`, `diagnostics.spawn`, plus `checkpoint.debug`.
  Spawn diagnostics include low-level source buckets (`top_low_level_sources`).
- Emits session fingerprint metadata (`session_id`, module hash, pointer hash) for
  run-to-run provenance.
- Emits compact `before`/`after` snapshots (including input + bindings) and
  detailed entity samples each captured tick by default.

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

## Divergence report + run narrative

```text
uv run python scripts/original_capture_divergence_report.py \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl \
  --float-abs-tol 2e-3 \
  --window 24 \
  --lead-lookback 1024 \
  --run-summary
```

`--run-summary` prints a compact timeline from the original recording
(bonus pickups, weapon assignments, perk picks when present, level-ups, and
state transitions) so divergence debugging has immediate run context.

If you only want a quick "what happened in this run?" mental model, use:

```text
uv run python scripts/original_capture_divergence_report.py \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl \
  --run-summary-short
```

`--run-summary-short` prints a shorter highlight list (bonus/weapon/perk/level/state).
Both modes can be tuned with `--run-summary-max-rows` and
`--run-summary-short-max-rows`.

The report also infers rewrite-side `rand_calls` from checkpoint RNG marks and
prints `rand_calls(e/a/d)` in the window table (`expected/actual/delta`), plus
focus-tick stage attribution (`secondary_projectiles`, `creatures`, etc.) and
rewrite death ledger head to localize large RNG bursts quickly. With v2 projectile
hit telemetry, the window also prints `p_hits(e/a)` (`capture projectile_find_hit`
vs rewrite `events.hit_count`).

Track each run in `docs/frida/differential-sessions.md`.

## Focus tick trace

When the divergence report points at a suspicious tick and you need deeper
rewrite-side mechanics (RNG callsites + collision near-misses + indexed sample
diffs), run:

```text
uv run python scripts/original_capture_focus_trace.py \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl \
  --tick 3453 \
  --near-miss-threshold 0.35 \
  --json-out analysis/frida/focus_trace_tick3453.json
```

This is especially useful when checkpoint fields still match but native RNG
callers indicate hidden branch drift (for example corpse-hit resolution).

`original_capture_focus_trace.py` now also prints `rng_value_alignment`:

- exact native-vs-rewrite RNG value prefix length for the focus tick,
- native-only tail draw count,
- dominant native `caller_static` buckets in that missing tail,
- a short inferred rewrite callsite preview for the missing native tail.

This makes it much easier to tell whether a focus mismatch is a midstream value
desync or a late-tick missing branch (prefix match + missing tail).

## Default capture profile

Without any extra env vars, v2 now captures full detail for every tracked tick:

- `before`/`after` snapshots on every tick.
- Detailed entity samples (`creatures`, `projectiles`, `secondary_projectiles`, `bonuses`) on every tick.
- Unlimited per-tick sample stream limits (`*_SAMPLE_LIMIT=-1` semantics).
- Unlimited RNG sample/caller heads (`CRIMSON_FRIDA_V2_RNG_HEAD=-1`, `CRIMSON_FRIDA_V2_RNG_CALLERS=-1`).
- Full per-roll RNG stream enabled by default (`CRIMSON_FRIDA_V2_RNG_ROLL_LOG=1`, unlimited by default).
- RNG mirror tracking on by default (`CRIMSON_FRIDA_V2_RNG_STATE_MIRROR=1`).
- Between-tick RNG rolls retained in tick-local diagnostics
  (`rng.outside_before_*`, `checkpoint.rng_marks.rand_outside_before_*`) with unlimited head by default.
- Between-tick perk-apply events retained in tick-local diagnostics
  (`perk_apply_outside_before`) with unlimited head by default.
- Unlimited event/phase head + tick event budget (`CRIMSON_FRIDA_V2_MAX_HEAD=-1`, `CRIMSON_FRIDA_V2_MAX_EVENTS_PER_TICK=-1`).
- Player count resolved from game memory (`config_player_count`) unless manually overridden.

Backtraces remain off by default (`CRIMSON_FRIDA_INCLUDE_BT=0`).

## Optional env knobs

- `CRIMSON_FRIDA_V2_STATES=6,9,10` (override tracked game states)
- `CRIMSON_FRIDA_V2_ALL_STATES=1` (capture ticks for all states)
- `CRIMSON_FRIDA_V2_TICK_DETAILS_EVERY=30` (throttle detailed entity samples)
- `CRIMSON_FRIDA_V2_CREATURE_SAMPLE_LIMIT=24`
- `CRIMSON_FRIDA_V2_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_V2_SECONDARY_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_V2_BONUS_SAMPLE_LIMIT=12`
- `CRIMSON_FRIDA_V2_INCLUDE_RAW_EVENTS=1`
- `CRIMSON_FRIDA_V2_INPUT_HOOKS=0` (disable input query hooks)
- `CRIMSON_FRIDA_V2_RNG_HOOKS=0` (disable rng hooks)
- `CRIMSON_FRIDA_V2_CREATURE_SPAWN_HOOK=0` (disable low-level `creature_spawn` hook)
- `CRIMSON_FRIDA_V2_RNG_HEAD=-1` (per-tick RNG sample head size; default unlimited, `0` disables head samples)
- `CRIMSON_FRIDA_V2_RNG_CALLERS=-1` (per-tick RNG caller buckets; default unlimited)
- `CRIMSON_FRIDA_V2_RNG_STATE_MIRROR=0` (disable mirrored CRT state tracking)
- `CRIMSON_FRIDA_V2_RNG_OUTSIDE_TICK_HEAD=256` (reduce between-tick RNG roll head retained on the next tick; `0` disables)
- `CRIMSON_FRIDA_V2_RNG_ROLL_LOG=0` (disable per-call `event: "rng_roll"` rows)
- `CRIMSON_FRIDA_V2_MAX_RNG_ROLL_LOG_EVENTS=-1` (cap for `rng_roll` row emission; `-1` unlimited)
- `CRIMSON_FRIDA_PLAYER_COUNT=2` (optional override; default uses `config_player_count` from memory)
- `CRIMSON_FRIDA_V2_FOCUS_TICK=1234` and `CRIMSON_FRIDA_V2_FOCUS_RADIUS=30` (optional focus tagging for diagnostics; does not gate snapshots/samples)

## RNG-Trace Defaults

The capture script now defaults to the full RNG divergence-trace profile:

```text
CRIMSON_FRIDA_V2_RNG_ROLL_LOG=1
CRIMSON_FRIDA_V2_MAX_RNG_ROLL_LOG_EVENTS=-1
CRIMSON_FRIDA_V2_RNG_HEAD=-1
CRIMSON_FRIDA_V2_RNG_CALLERS=-1
CRIMSON_FRIDA_V2_RNG_OUTSIDE_TICK_HEAD=-1
CRIMSON_FRIDA_V2_RNG_STATE_MIRROR=1
```

Set env vars only if you want to reduce or disable this tracing volume.
