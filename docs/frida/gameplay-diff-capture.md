---
tags:
  - status-validation
  - frida
  - differential-testing
---

# Gameplay Differential Capture

`scripts/frida/gameplay_diff_capture.js` captures deterministic gameplay ticks into a
JSONL event stream designed for robust incremental writes.

If you are starting from only a fresh capture artifact, follow
`docs/frida/differential-playbook.md` first.

Primary output:

- `C:\share\frida\gameplay_diff_capture.json`

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
```

Just shortcut (Windows VM):

```text
just frida-gameplay-diff-capture
```

## Capture format

The capture file is newline-delimited JSON rows:

- `{"event":"capture_meta","capture":{...}}` exactly once at start
- `{"event":"tick","tick":{...}}` once per captured gameplay tick

`uv run crimson original ...` commands load this stream and normalize it to the
typed `CaptureFile` schema in Python (`msgspec`).

Notes:

- The file is streamed incrementally and flushed on each write.
- Console output is filtered by default to high-signal lifecycle/errors only.
- Before detaching from a live Frida session, call `crimsonCaptureStop("manual_stop")`
  in the REPL and wait for the `capture_shutdown` log line.
- Loader behavior is strict: truncated trailing JSON rows are rejected.
- Loader accepts only stream rows (`capture_meta` + `tick`), not legacy
  monolithic JSON captures.
- Entity `samples` payloads are strictly typed (`creatures`, `projectiles`,
  `secondary_projectiles`, `bonuses`): schema/script drift should be fixed in
  instrumentation and re-captured, not handled via parser fallbacks.
- No top-level raw event stream is written; diagnostics stay in per-tick aggregates.
- Float precision contract: capture script emits memory-sourced float values as
  tagged float32 bit tokens (`"f32:XXXXXXXX"`). Tooling decodes these tokens at
  load time and treats decoded float32 values as authoritative.

## Convert to checkpoints + replay

```text
uv run crimson original convert-capture \
  artifacts/frida/share/gameplay_diff_capture.json \
  analysis/frida/gameplay_diff_capture.checkpoints.json.gz
```

This also writes `analysis/frida/gameplay_diff_capture.crdemo.gz` by default
(override with `--replay`).

## Verify capture directly against rewrite sim

```text
uv run crimson original verify-capture \
  artifacts/frida/share/gameplay_diff_capture.json
```

## Divergence report

```text
uv run crimson original divergence-report \
  artifacts/frida/share/gameplay_diff_capture.json \
  --float-abs-tol 2e-3 \
  --window 24 \
  --lead-lookback 1024 \
  --run-summary
```

Use `--run-summary-short` for a shorter narrative.

## Focus tick trace

```text
uv run crimson original focus-trace \
  artifacts/frida/share/gameplay_diff_capture.json \
  --tick 3453 \
  --near-miss-threshold 0.35 \
  --json-out
```

## Creature trajectory trace

```text
uv run crimson original creature-trajectory \
  artifacts/frida/share/gameplay_diff_capture.json \
  --creature-index 120 \
  --json-out
```

## Defaults

Without extra env vars, the script captures full per-tick detail:

- `before`/`after` snapshots every captured tick
- samples for `creatures`, `projectiles`, `secondary_projectiles`, `bonuses`
- unlimited head budgets by default (`-1` limits)
- RNG head + caller diagnostics, RNG mirror tracking, outside-tick carry
- perk-apply diagnostics and input query/key snapshots

## Optional env knobs

- `CRIMSON_FRIDA_STATES=6,9,10`
- `CRIMSON_FRIDA_ALL_STATES=1`
- `CRIMSON_FRIDA_CONSOLE_ALL_EVENTS=1`
- `CRIMSON_FRIDA_CONSOLE_EVENTS=start,ready,capture_shutdown,error,hook_error,hook_skip,tickless_event`
- `CRIMSON_FRIDA_TICK_DETAILS_EVERY=30`
- `CRIMSON_FRIDA_CREATURE_SAMPLE_LIMIT=24`
- `CRIMSON_FRIDA_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_SECONDARY_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_BONUS_SAMPLE_LIMIT=12`
- `CRIMSON_FRIDA_MAX_HEAD=-1`
- `CRIMSON_FRIDA_MAX_EVENTS_PER_TICK=-1`
- `CRIMSON_FRIDA_INPUT_HOOKS=0`
- `CRIMSON_FRIDA_RNG_HOOKS=0`
- `CRIMSON_FRIDA_SPAWNS=0`
- `CRIMSON_FRIDA_CREATURE_SPAWN_HOOK=0`
- `CRIMSON_FRIDA_CREATURE_DEATH_HOOK=0`
- `CRIMSON_FRIDA_BONUS_SPAWN_HOOK=0`
- `CRIMSON_FRIDA_RNG_ROLL_LOG=0`
- `CRIMSON_FRIDA_MAX_RNG_ROLL_LOG_EVENTS=-1`
- `CRIMSON_FRIDA_RNG_HEAD=-1`
- `CRIMSON_FRIDA_RNG_CALLERS=-1`
- `CRIMSON_FRIDA_RNG_OUTSIDE_TICK_HEAD=-1`
- `CRIMSON_FRIDA_RNG_STATE_MIRROR=0`
- `CRIMSON_FRIDA_INCLUDE_BT=1`
- `CRIMSON_FRIDA_INCLUDE_CALLER=0`

Capture loading in Python accepts `.json` and `.json.gz` only, with JSONL
row-stream capture rows as the canonical format.
