---
tags:
  - frida
  - differential-testing
  - parity
---

# Creature Update Static Audit Triage

This file tracks static parity findings from the hotspot review and the capture-driven verification loop for each fix.

## Working Capture

Use this capture as the primary canary unless a finding clearly points elsewhere:

- `artifacts/frida/share/gameplay_diff_capture.quest_1_8.json`

Create output folder once:

```bash
mkdir -p analysis/frida/reports/triage
```

## Triage Items

### 1) Freeze gate ordering in `creature_update_all` port

- [ ] Status: Open
- Rewrite location: `src/crimson/creatures/runtime.py:871`, `src/crimson/creatures/runtime.py:899`
- Native evidence: `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:56`, `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:560`
- Hypothesis: rewrite processes dead/corpse stages during freeze where native skips the full body under freeze gate.
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/01_freeze_gate_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/01_freeze_gate_after.json
```

### 2) Radioactive branch phase/order drift

- [ ] Status: Open
- Rewrite location: `src/crimson/creatures/runtime.py:974`, `src/crimson/creatures/runtime.py:993`
- Native evidence: `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:442`, `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:454`
- Hypothesis: rewrite executes radioactive before AI/movement/cooldown and can early-continue on kill; native evaluates this branch later in the creature body.
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/02_radioactive_order_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/02_radioactive_order_after.json
```

### 3) Ranged-vs-contact branch ordering drift

- [ ] Status: Open
- Rewrite location: `src/crimson/creatures/runtime.py:1089`, `src/crimson/creatures/runtime.py:1114`
- Native evidence: `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:474`, `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:493`
- Hypothesis: rewrite executes near-contact/contact before ranged fire, while native evaluates ranged branch first.
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/03_ranged_contact_order_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/03_ranged_contact_order_after.json
```

### 4) Missing `hit_flash_timer` decay

- [ ] Status: Open
- Rewrite location: `src/crimson/creatures/runtime.py:867` (loop has no decay), producer at `src/crimson/creatures/damage.py:128`
- Native evidence: `analysis/ghidra/derived/hotspots/creature_update_all/work/00426220_creature_update_all.work.c:51`
- Hypothesis: presentation timer persists longer than native and can alter downstream render-phase parity signals.
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/04_hit_flash_decay_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/04_hit_flash_decay_after.json
```

## Review Notes Per Item

For each item, capture:

- first mismatch tick/category
- `capture_hits` vs `rewrite_hits` near frontier
- `missing_tail` and dominant caller clusters
- whether the mismatch moved, changed class, or stayed identical
