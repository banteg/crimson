---
tags:
  - frida
  - differential-testing
  - parity
---

# Creature Update Static Audit Triage

> **Historical (superseded).** This page predates the `.cdt` capture format and
> uses the removed `crimson original divergence-report` tooling; its expected
> mismatches were all resolved by the 2026-06-12 parity audit. Do not follow
> these commands or expectations in new sessions - use
> [the differential playbook](differential-playbook.md) instead.

This file tracks static parity findings from the hotspot review and the capture-driven verification loop for each fix.

## Branch-Targeted Canaries

Signal matrix source:

- `analysis/frida/reports/triage/capture_branch_signal_summary.tsv`

Recommended primary canary per branch:

- Freeze gate ordering: `artifacts/frida/share/gameplay_diff_capture.quest_3_3.json`
  - `freeze_creature_ticks=349`, `freeze_damage_ticks=33`, `freeze_ticks=377`
- Radioactive branch ordering: `artifacts/frida/share/gameplay_diff_capture.quest_3_7.json`
  - `radioactive_ticks=1617`, `radioactive_proximity_ticks=217`, `radioactive_prox_damage_ticks=22`
- Ranged-vs-contact ordering: `artifacts/frida/share/gameplay_diff_capture.quest_3_10.json`
  - `creature_proj_spawn_ticks=105`, `player_damage_ticks=28`, `mixed_ranged_contact_ticks=1`
  - nearest ranged-vs-contact distance analysis: `spawn_within3=5`, `spawn_within5=7`
- Hit-flash decay: `artifacts/frida/share/gameplay_diff_capture.quest_3_10.json`
  - `hit_flash_candidate_ticks=1033`, `creature_damage_events=1281`

Secondary confirmers:

- Freeze: `artifacts/frida/share/gameplay_diff_capture.quest_1_7.json`, `artifacts/frida/share/gameplay_diff_capture.quest_4_1.json`
- Radioactive: `artifacts/frida/share/gameplay_diff_capture.quest_2_9.json`
- Ranged-vs-contact: `artifacts/frida/share/gameplay_diff_capture.quest_1_6.json`
- Hit-flash decay: `artifacts/frida/share/gameplay_diff_capture.quest_1_6.json`, `artifacts/frida/share/gameplay_diff_capture.quest_4_1.json`

Create output folder once:

```bash
mkdir -p analysis/frida/reports/triage
```

## Triage Items

### 1) Freeze gate ordering in `creature_update_all` port

- [ ] Status: Open
- Primary canary: `artifacts/frida/share/gameplay_diff_capture.quest_3_3.json`
- Rewrite location: `src/crimson/creatures/runtime.py:871`, `src/crimson/creatures/runtime.py:899`
- Native evidence: `creature_update_all` at `0x00426220`; freeze/body notes are preserved in `analysis/annotations/functions.json`.
- Hypothesis: rewrite processes dead/corpse stages during freeze where native skips the full body under freeze gate.
- Latest run delta: no change (`state_mismatch` at tick `30330` in both before/after).
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_3.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/01_freeze_gate_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_3.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/01_freeze_gate_after.json
```

### 2) Radioactive branch phase/order drift

- [ ] Status: Open
- Primary canary: `artifacts/frida/share/gameplay_diff_capture.quest_3_7.json`
- Rewrite location: `src/crimson/creatures/runtime.py:974`, `src/crimson/creatures/runtime.py:993`
- Native evidence: `creature_update_all` at `0x00426220`; periodic-damage ordering is preserved in `analysis/annotations/functions.json`.
- Hypothesis: rewrite executes radioactive before AI/movement/cooldown and can early-continue on kill; native evaluates this branch later in the creature body.
- Latest run delta: improved first mismatch from tick `35131` to `35975` (`rng_stream_mismatch`).
- New lead: hidden AI7 timer-state drift at tick `35963` (slot `10`/`17` `link_index` mismatch despite RNG value-prefix parity); see `analysis/frida/reports/triage/02_focus_trace_35963_probe.json`.
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_7.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/02_radioactive_order_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_7.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/02_radioactive_order_after.json
```

### 3) Ranged-vs-contact branch ordering drift

- [ ] Status: Open
- Primary canary: `artifacts/frida/share/gameplay_diff_capture.quest_3_10.json`
- Rewrite location: `src/crimson/creatures/runtime.py:1089`, `src/crimson/creatures/runtime.py:1114`
- Native evidence: `creature_update_all` at `0x00426220`; ranged/contact ordering is preserved in `analysis/annotations/functions.json`.
- Hypothesis: rewrite executes near-contact/contact before ranged fire, while native evaluates ranged branch first.
- Latest run delta: no change (`rng_stream_mismatch` at tick `40323` in both before/after).
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_10.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/03_ranged_contact_order_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_10.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/03_ranged_contact_order_after.json
```

### 4) Missing `hit_flash_timer` decay

- [ ] Status: Open
- Primary canary: `artifacts/frida/share/gameplay_diff_capture.quest_3_10.json`
- Rewrite location: `src/crimson/creatures/runtime.py:867` (loop has no decay), producer at `src/crimson/creatures/damage.py:128`
- Native evidence: `creature_update_all` at `0x00426220`; corpse/presentation notes are preserved in `analysis/annotations/functions.json`.
- Hypothesis: presentation timer persists longer than native and can alter downstream render-phase parity signals.
- Latest run delta: no change (`rng_stream_mismatch` at tick `40323` in both before/after).
- Baseline:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_10.json \
  --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 \
  --run-summary-short --run-summary-focus-context \
  --run-summary-focus-before 8 --run-summary-focus-after 6 \
  --run-summary-short-max-rows 40 --no-cache \
  --json-out analysis/frida/reports/triage/04_hit_flash_decay_before.json
```

- After fix:

```bash
uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_10.json \
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
