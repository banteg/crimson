---
tags:
  - frida
  - differential-testing
  - workflow
---

# Differential Playbook

Use this when an agent is only given a new capture file (typically
`artifacts/frida/share/gameplay_diff_capture.json`) and needs to continue
original-vs-rewrite investigation.

This runbook is based on repeated patterns from Codex session logs under
`/Users/banteg/.codex/sessions/2026/02` across multiple Crimson worktrees.

## 1) Identify the capture artifact

Run:

```bash
ls -lh artifacts/frida/share/gameplay_diff_capture.json
shasum -a 256 artifacts/frida/share/gameplay_diff_capture.json
```

Record the SHA256 first. Session tracking is by capture SHA family.

## 2) Run a quick health check

Run:

```bash
uv run python - <<'PY'
from pathlib import Path
import hashlib
from crimson.original.capture import load_capture

p = Path("artifacts/frida/share/gameplay_diff_capture.json")
print("sha256", hashlib.sha256(p.read_bytes()).hexdigest())
cap = load_capture(p)
print("capture_format_version", int(cap.capture_format_version))
ticks = cap.ticks
print("ticks", len(ticks))
if ticks:
    print("first_tick", int(ticks[0].tick_index), "last_tick", int(ticks[-1].tick_index))
    print("first_gameplay_frame", int(ticks[0].gameplay_frame), "last_gameplay_frame", int(ticks[-1].gameplay_frame))
PY
```

Notes:

- Loader success is the gate. If it decodes cleanly, continue.
- Loader enforces exact `capture_format_version`; stale version captures must be
  re-recorded with the current script.
- Capture loading is strict: a truncated trailing JSONL row is a blocker and should be recaptured.

## 3) Decide session bookkeeping

Search for the SHA in `docs/frida/differential-sessions.md`.

- If SHA exists: append to that session entry.
- If SHA is new: create a new session entry.

Do not assume you can re-record the same gameplay timeline. Use event and RNG
anchors, not exact absolute tick equality across different recordings.

## 4) Baseline triage commands

Caching note:

- `original divergence-report` and `original focus-trace` now auto-use a local diagnostics cache daemon.
- First run for a new capture can block while the cache warms.
- Subsequent runs against the same capture should be significantly faster.
- Use `--no-cache` to force the legacy in-process path for debugging/regressions.

Run in this order:

```bash
uv run crimson original divergence-report \
  artifacts/frida/share/gameplay_diff_capture.json \
  --float-abs-tol 1e-3 \
  --window 24 \
  --lead-lookback 1024 \
  --run-summary-short \
  --run-summary-focus-context \
  --run-summary-focus-before 8 \
  --run-summary-focus-after 4 \
  --run-summary-short-max-rows 30 \
  --json-out analysis/frida/reports/capture_<sha8>_baseline.json

uv run crimson original bisect-divergence \
  artifacts/frida/share/gameplay_diff_capture.json \
  --window-before 12 \
  --window-after 6 \
  --json-out analysis/frida/reports/capture_<sha8>_bisect.json
```

If capture telemetry is missing `config_aim_scheme`/`input_approx.aim_scheme` for a
known run (for example sidecar-enforced computer aim), add
`--aim-scheme-player 0=5` to `verify-capture`, `divergence-report`,
`bisect-divergence`, `focus-trace`, and `visualize-capture`.

Then read the emitted `run_summary_focus_context` block first to orient around
major gameplay events near the focus tick (bonus pickups, perk picks, level-up,
weapon swaps, state transitions). This is the quickest way to confirm whether a
suspected mechanic (for example `Evil Eyes`) was actually active before the
first mismatch.

```bash
uv run crimson original verify-capture \
  artifacts/frida/share/gameplay_diff_capture.json \
  --float-abs-tol 1e-3 \
  --max-field-diffs 32
```

```bash
uv run crimson original focus-trace \
  artifacts/frida/share/gameplay_diff_capture.json \
  --tick <focus_tick> \
  --near-miss-threshold 0.35 \
  --json-out analysis/frida/reports/capture_<sha8>_focus_<focus_tick>.json
```

Interpretation rule:

- Treat `divergence-report` as primary for first sustained gameplay drift.
- `verify-capture` can fail earlier on transient timing mismatches and should be
  interpreted together with divergence output.

## 5) Check telemetry quality before gameplay patches

Run:

```bash
uv run python - <<'PY'
from pathlib import Path
import msgspec
from crimson.original.capture import load_capture

cap = load_capture(Path("artifacts/frida/share/gameplay_diff_capture.json.gz"))

key_rows = 0
key_rows_with_move = 0
perk_in_tick = 0
perk_outside_calls = 0
sample_creature_rows = 0
sample_creature_rows_with_ai_lineage = 0
lifecycle_rows = 0
lifecycle_rows_with_ai_lineage = 0
creature_update_micro_rows = 0
creature_update_micro_angle_rows = 0
creature_update_micro_window_rows = 0

for t in cap.ticks:
    for row in t.input_player_keys:
        key_rows += 1
        if any(v is not None for v in (
            row.move_forward_pressed,
            row.move_backward_pressed,
            row.turn_left_pressed,
            row.turn_right_pressed,
            row.fire_down,
            row.fire_pressed,
            row.reload_pressed,
        )):
            key_rows_with_move += 1
    perk_in_tick += len([e for e in t.perk_apply_in_tick if e.perk_id is not None])
    perk_outside_calls += int(t.perk_apply_outside_before.calls)
    if t.samples is not None:
        for creature in t.samples.creatures:
            sample_creature_rows += 1
            if creature.ai_mode is not None or creature.link_index is not None:
                sample_creature_rows_with_ai_lineage += 1
    for head in msgspec.to_builtins(t.event_heads):
        if not isinstance(head, dict):
            continue
        if head.get("kind") != "creature_lifecycle":
            if head.get("kind") == "creature_update_micro":
                creature_update_micro_rows += 1
                data = head.get("data") if isinstance(head.get("data"), dict) else {}
                event_kind = str(data.get("event_kind") or "")
                if event_kind == "angle_approach":
                    creature_update_micro_angle_rows += 1
                elif event_kind == "creature_update_window":
                    creature_update_micro_window_rows += 1
            continue
        data = head.get("data") if isinstance(head.get("data"), dict) else {}
        for key in ("added_head", "removed_head"):
            rows = data.get(key)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                lifecycle_rows += 1
                if row.get("ai_mode") is not None or row.get("link_index") is not None:
                    lifecycle_rows_with_ai_lineage += 1

print("key_rows", key_rows)
print("key_rows_with_any_signal", key_rows_with_move)
print("perk_apply_in_tick_entries", perk_in_tick)
print("perk_apply_outside_calls", perk_outside_calls)
print("sample_creature_rows", sample_creature_rows)
print("sample_creature_rows_with_ai_lineage", sample_creature_rows_with_ai_lineage)
print("creature_lifecycle_rows", lifecycle_rows)
print("creature_lifecycle_rows_with_ai_lineage", lifecycle_rows_with_ai_lineage)
print("creature_update_micro_rows", creature_update_micro_rows)
print("creature_update_micro_angle_rows", creature_update_micro_angle_rows)
print("creature_update_micro_window_rows", creature_update_micro_window_rows)
PY
```

If telemetry is missing/weak, patch Frida capture first and recapture. Avoid
stacking replay fallbacks when capture instrumentation is the real gap.

For creature-movement root-cause work (for example slot-level drift ancestry),
require non-zero `creature_update_micro_rows` and both non-zero
`creature_update_micro_angle_rows` and `creature_update_micro_window_rows` in
the target tick window.

## 6) Common mismatch classes

- Early position drift (`players[0].pos.*`): usually input reconstruction quality.
- XP/score-only one-tick blips: often timing/bridge artifacts; verify whether it
  self-heals on the next tick.
- RNG shortfall lead near focus tick: investigate missing branch/caller path
  before tuning downstream gameplay behavior.

## 7) Completion checklist

1. Add targeted tests for every replay/conversion behavior change.
2. Run `just check`.
3. Update `docs/frida/differential-sessions.md` with:
   - SHA
   - exact baseline commands
   - first mismatch progression
   - landed changes
   - next probe
4. Commit with conventional commits style.
