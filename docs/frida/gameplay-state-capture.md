---
tags:
  - status-validation
  - frida
---

# Gameplay/state capture

`scripts/frida/gameplay_state_capture.js` is the default "large run" capture for
gameplay-focused mapping work.

For deterministic replay-side differential work, prefer
`scripts/frida/gameplay_diff_capture_v2.js` (see
`docs/frida/gameplay-diff-capture-v2.md`).

It runs fully automatically after attach:

- Periodic compact/full snapshots of gameplay globals + player state.
- Transition snapshots around `game_state_set`, `ui_menu_assets_init`,
  `ui_menu_layout_init`, and key gameplay hooks.
- Per-frame deltas for `ui_menu_item_subtemplate_block_01..06`
  (`0x0048fd78..0x004902ff`) while in UI/gameplay-interest states
  (`0`, `2`, `4`, `6`, `9`).
- Automatic `MemoryAccessMonitor` write tracing for:
  - `0x0048fd78..0x004902ff` (UI subtemplate blocks),
  - gameplay timer/state ranges (`0x00480840..`, `0x00482600..`,
    `0x00486fac..`, `0x0048718c..`, `0x004aaf1c`, `0x004c3654`).
- `ui_element_render` pointer trace and `ui_menu_item_update` pointer trace to
  correlate render-time usage with subtemplate storage.

Output file:

- `C:\share\frida\gameplay_state_capture.jsonl` (default)
- override via `CRIMSON_FRIDA_DIR`

Attach:

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_state_capture.js
```

Just shortcut (Windows VM):

```text
just frida-gameplay-state-capture
```

Reduce the capture into compact summaries:

```text
uv run scripts/gameplay_state_capture_reduce.py \
  --log artifacts/frida/share/gameplay_state_capture.jsonl \
  --out analysis/frida/gameplay_state_capture_summary.json \
  --report analysis/frida/gameplay_state_capture_report.md \
  --sfx-candidates analysis/frida/gameplay_state_capture_sfx_candidates.json \
  --top 40
```

The reducer also emits `gameplay_state_capture_sfx_candidates.json` containing
high-confidence `event|function -> id` mappings for promotion into
`name_map.json` comments/docs.

Convert raw trace snapshots into replay-checkpoint sidecar format for
differential replay checks:

```text
uv run crimson replay convert-original-capture \
  artifacts/frida/share/gameplay_state_capture.jsonl \
  analysis/frida/original_capture.checkpoints.json.gz
```

This also writes `analysis/frida/original_capture.crdemo.gz` by default (override with `--replay`).
That replay is best-effort (rebuilt from telemetry) and mainly for visual
inspection. It bootstraps from the first captured tick but is not a strict
verification artifact. Checkpoint sidecars remain the verification target.

Verify the capture directly against rewrite simulation checkpoints:

```text
uv run crimson replay verify-original-capture \
  artifacts/frida/share/gameplay_state_capture.jsonl
```

This command compares checkpoint state fields at captured ticks and reports the
first mismatch with field-level details.

Notes:

- The converter uses sparse `snapshot_compact` / `snapshot_full` entries with
  `gameplay_frame > 0` and maps them to replay ticks.
- Fields that are not currently captured in raw trace snapshots are marked as
  unknown sentinels and ignored during checkpoint diffing.

Recommended session:

1. Main menu (`0`) -> Play menu (`1`) -> Options (`2`) -> Statistics (`4`).
2. Start gameplay (`9`), fire/reload, swap weapons, pick several bonuses, level
   up into perk screen (`6`), return to gameplay.
3. Run a quest to quest results (`8`) and quest fail (`12`) once each.
4. Visit Typ-o-Shooter (`18`) briefly.

This single pass yields enough evidence to continue field-level carving and type
fixes without manual REPL interactions.

Known caveat from the 2026-02-06 large run:

- `mem_watch_enabled` was present, but no `mem_watch_access` events were emitted
  (`0` hits in `analysis/frida/gameplay_state_capture_summary.json`). The script
  now normalizes multiple Frida op fields (`operation`/`type`/`access`/`kind`)
  and logs `operation_raw`; rerun a short capture to validate that mem-watch
  events are flowing.
