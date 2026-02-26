---
tags:
  - status-validation
  - frida
  - differential-testing
---

# Gameplay Differential Capture

`scripts/frida/gameplay_diff_capture.js` captures deterministic gameplay ticks.
By default it writes JSON stream rows directly to disk.

Use `scripts/frida/gameplay_diff_capture_host.py` to attach, force host row sink,
consume rows, and write framed msgpack compressed with zstd.

If you are starting from only a fresh capture artifact, follow
`docs/frida/differential-playbook.md` first.

Default direct-attach outputs (`frida -n ... -l gameplay_diff_capture.js`):

- non-quest fallback: `C:\share\frida\gameplay_diff_capture.json`
- quest mode: `C:\share\frida\gameplay_diff_capture.quest_<major>_<minor>.json`

Primary host outputs:

- default / non-quest fallback: `C:\share\frida\gameplay_diff_capture.msgpack.zst`
- quest mode: one file per stage, e.g. `C:\share\frida\gameplay_diff_capture.quest_1_1.msgpack.zst`

Attach:

```text
uv run scripts/frida/gameplay_diff_capture_host.py \
  --process crimsonland.exe \
  --script scripts\frida\gameplay_diff_capture.js \
  --output-dir C:\share\frida
```

File-sink capture with post-run msgpack conversion:

```text
uv run scripts/frida/gameplay_diff_capture_postpack.py \
  --process crimsonland.exe \
  --script scripts\frida\gameplay_diff_capture.js \
  --output-dir C:\share\frida
```

When postpack conversion succeeds, source `gameplay_diff_capture*.json/.json.gz`
files are deleted and only `*.msgpack.zst` outputs remain.

Optional sidecar for unattended recordings:

```text
frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
```

Just shortcut (Windows VM):

```text
just frida-gameplay-diff-capture
just frida-gameplay-diff-capture-postpack
```

## Quest campaign captures

Quest-mode ticks are routed automatically into per-stage files by default.
This lets you play through all quests in one Frida session and keep each quest
capture isolated.

Examples:

- `gameplay_diff_capture.quest_1_1.msgpack.zst`
- `gameplay_diff_capture.quest_1_2.msgpack.zst`
- `gameplay_diff_capture.quest_5_10.msgpack.zst`

If the same quest stage is recorded multiple times in one attach session, the
script appends a run suffix to avoid overwriting earlier runs
(`...quest_1_1.run2.msgpack.zst`, `...quest_1_1.run3.msgpack.zst`, etc.).

## Capture format

The host writes zstd-compressed framed msgpack rows:

- raw stream magic: `crimson_capture_msgpack_v1\n`
- per-row frame: `<u32 little-endian payload len><msgpack row payload>`
- row payload shape matches stream rows:
  - `{"event":"capture_meta","capture":{...}}` exactly once at start
  - `{"event":"tick","tick":{...}}` once per captured gameplay tick
- `capture_meta.capture_format_version` is required and must match the current
  loader version (`5`).

`uv run crimson original ...` commands load this stream and normalize it to the
typed `CaptureFile` schema in Python (`msgspec`).

Notes:

- The host streams rows incrementally and flushes the compressed stream on each write by default.
- Console output is filtered by default to high-signal lifecycle/errors only.
- Before detaching, stop the host cleanly (`Ctrl+C`) so it can call capture stop and finalize frames.
- Loader behavior is strict: truncated trailing stream rows are rejected.
- Loader behavior is strict: only captures with the current
  `capture_format_version` are accepted.
- Loader behavior is strict per row: each stream row must decode as either a
  typed `capture_meta` or typed `tick` row with no unknown/missing fields.
- Loader accepts only stream rows (`capture_meta` + `tick`), not legacy
  monolithic JSON captures.
- `capture_meta.config` now carries routing + provenance markers
  (`out_path`, `split_quest_files`, `quest_out_dir`, `quest_out_prefix`,
  `capture_profile`, `config_env_overrides`) so investigation notes can record
  which environment overrides were active for a run.
- Current checkpoints include direct kill count, perk snapshot
  (`pending_count`/`choices_dirty`/`choices`/`player_nonzero_counts`), and
  per-player bonus timers in checkpoint player rows.
- Entity `samples` payloads are strictly typed (`creatures`, `projectiles`,
  `secondary_projectiles`, `bonuses`): schema/script drift should be fixed in
  instrumentation and re-captured, not handled via parser fallbacks.
- Creature sample/lifecycle payloads include AI lineage context
  (`ai_mode`, `link_index`, `orbit_angle`, `orbit_radius`, `ai7_timer_ms`)
  to diagnose spawn/link timer drift without replay-side guesswork.
- `creature_update_micro` event heads provide slot-level movement internals
  (`creature_update_window` pre/post snapshots + `angle_approach` call traces),
  including link-lineage fields (`link_index`, `ai7_timer_ms`, link position,
  and link-distance buckets), and are enabled in default captures.
- Per-tick timing diagnostics now include mode-step presence and dt provenance
  (`mode_tick_event_count`, `mode_tick_present`, `mode_tick_mode_fn_head`,
  `frame_dt_source_before`, `frame_dt_source_after`) to debug timing-path
  parity without replay-side inference.
- No top-level raw event stream is written; diagnostics stay in per-tick aggregates.
- Float precision contract: capture script emits memory-sourced float values as
  tagged float32 bit tokens (`"f32:XXXXXXXX"`). Tooling decodes these tokens at
  load time and treats decoded float32 values as authoritative.
- Input metadata contract: `input_approx` rows include per-player `move_mode`
  and `aim_scheme` sampled from config globals.
- Quest tick rows include `quest_stage_major` / `quest_stage_minor` so tooling
  can map each file/tick back to a specific quest.

## Convert to checkpoints + replay

```text
uv run crimson original convert-capture \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  analysis/frida/gameplay_diff_capture.crd.chk
```

This also writes `analysis/frida/gameplay_diff_capture.crd` by default
(override with `--replay`).

Conversion output cutover:

- converted replay headers now carry `input_quantization="f32"`,
- converted replay input vectors and capture-derived float payload fields are
  canonicalized to float32 during conversion.

After this cutover, replay/checkpoint hashes change when artifacts are
regenerated. Always regenerate and version `.crd` and `.crd.chk` sidecar pairs
together.

## Verify capture directly against rewrite sim

```text
uv run crimson original verify-capture \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst
```

## Capture telemetry health

```text
uv run crimson original capture-health \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst
```

## Divergence report

```text
uv run crimson original divergence-report \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  --float-abs-tol 2e-3 \
  --window 24 \
  --lead-lookback 1024 \
  --run-summary
```

Use `--run-summary-short` for a shorter narrative.

## First-divergence bisect

```text
uv run crimson original bisect-divergence \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  --window-before 12 \
  --window-after 6 \
  --json-out
```

## Focus tick trace

```text
uv run crimson original focus-trace \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  --tick 3453 \
  --near-miss-threshold 0.35 \
  --json-out
```

## Creature trajectory trace

```text
uv run crimson original creature-trajectory \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  --creature-index 120 \
  --json-out
```

## Defaults

Without extra env vars, the script captures full per-tick detail:

- `before`/`after` snapshots every captured tick
- samples for `creatures`, `projectiles`, `secondary_projectiles`, `bonuses`
- unlimited head budgets by default (`-1` limits)
- RNG per-draw stream rows (`value/state_before/state_after/branch_id`), caller diagnostics, mirror tracking, outside-tick carry
- blood-splatter effect diagnostics (`effect_spawn_blood_splatter`) with per-tick caller and RNG-draw attribution
- perk-apply diagnostics and input query/key snapshots
- mode-step timing-path diagnostics (mode tick counts/presence + frame dt source
  before/after each tick)
- creature movement micro telemetry (`creature_update_window` +
  `angle_approach`) with per-kind per-tick head cap (`256`) and no slot/window
  filtering

## Optional env knobs

Creature micro hooks stay enabled by default for differential parity sessions.

- `CRIMSON_FRIDA_STATES=6,9,10`
- `CRIMSON_FRIDA_ALL_STATES=1`
- `CRIMSON_FRIDA_OUT_PATH=C:\share\frida\gameplay_diff_capture.msgpack.zst`
- `CRIMSON_FRIDA_CAPTURE_SINK=host` (`file` default; host launcher forces `host`)
- `CRIMSON_FRIDA_QUEST_OUT_DIR=C:\share\frida`
- `CRIMSON_FRIDA_QUEST_OUT_PREFIX=gameplay_diff_capture.quest_`
- `CRIMSON_FRIDA_CONSOLE_ALL_EVENTS=1`
- `CRIMSON_FRIDA_CONSOLE_EVENTS=start,ready,capture_shutdown,error,hook_error,hook_skip,tickless_event`
- `CRIMSON_FRIDA_CREATURE_SAMPLE_LIMIT=24`
- `CRIMSON_FRIDA_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_SECONDARY_PROJECTILE_SAMPLE_LIMIT=32`
- `CRIMSON_FRIDA_BONUS_SAMPLE_LIMIT=12`
- `CRIMSON_FRIDA_MAX_HEAD=-1`
- `CRIMSON_FRIDA_MAX_EVENTS_PER_TICK=-1`
- `CRIMSON_FRIDA_INPUT_HOOKS=0`
- `CRIMSON_FRIDA_RNG_HOOKS=0`
- `CRIMSON_FRIDA_EFFECTS=0`
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

For dynamic-gameplay investigations, prioritize divergence category/signatures
(`divergence_category`, dominant caller sets, hit shortfall profile) over
absolute tick alignment across captures.

Capture loading in Python accepts `.msgpack.zst`, `.json`, and `.json.gz`.
