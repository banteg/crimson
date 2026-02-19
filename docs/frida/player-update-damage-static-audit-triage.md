---
tags:
  - frida
  - differential-testing
  - parity
---

# Player Update + Damage Static Audit Triage

This file tracks confirmed static parity findings that should be fixed in a separate follow-up PR.

Scope of this work file:

- include only confirmed findings from the static audit
- document code evidence and native references for each item
- define minimal acceptance criteria for parity fixes

Out of scope for this file:

- lower-confidence or unconfirmed items from the same review pass

## Confirmed Findings

### 1) Movement ladder collapsed vs native mode-flag dispatch

- [ ] Status: Open (confirmed)
- Severity: High
- Rewrite location: `src/crimson/gameplay.py:468`, `src/crimson/gameplay.py:705`
- Native evidence: `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:278`, `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:710`
- Confirmation details:
  - Rewrite currently branches into a digital-key path vs analog path and does not dispatch by `config_player_mode_flags` values `1/2/3/4/5`.
  - Native has a full mode ladder (`mode 1`, `mode 2`, `mode 3`, `mode 4`, `mode 5`) plus demo/computer fallback, with branch-specific turn/move behavior.
- Risk:
  - non-default control modes can diverge in heading approach, move speed ramps, and turn/aim coupling
- Acceptance criteria:
  - movement branch selection follows native mode ladder conditions
  - per-mode turn/move behavior matches native branch intent (including mode-4 target movement and demo fallback)

### 2) Reload start gate too permissive

- [ ] Status: Open (confirmed)
- Severity: Medium
- Rewrite location: `src/crimson/gameplay.py:692`, `src/crimson/gameplay.py:705`
- Native evidence: `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:901`, `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:908`
- Confirmation details:
  - Rewrite starts reload from a single `input_state.reload_pressed` path with limited checks.
  - Native gates reload start on a compound condition: demo mode off, alternate-weapon path not active, player mode flag not `4`, reload key active, reload timer zero, and single-player gate.
- Risk:
  - reload can start in states native would block, altering timing and downstream firing behavior
- Acceptance criteria:
  - reload start condition mirrors native gating order and predicates
  - mode-4 and non-single-player behavior follows native gating

### 3) Aim-scheme dispatch missing (direct aim assignment)

- [ ] Status: Open (confirmed)
- Severity: High
- Rewrite location: `src/crimson/gameplay.py:445`, `src/crimson/gameplay.py:451`
- Native evidence: `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:909`, `analysis/ghidra/derived/hotspots/player_update/work/004136b0_player_update.work.c:1048`
- Confirmation details:
  - Rewrite directly assigns `player.aim = input_state.aim` and derives heading from that vector.
  - Native dispatches by configured aim scheme (mouse, key aim, POV, axis aim, and demo/computer assist) before final heading resolution.
- Risk:
  - keyboard/joystick/computer aim intent and heading evolution diverge from native
- Acceptance criteria:
  - aim vector/heading update path dispatches by native aim scheme
  - mode interactions (`config_player_mode_flags` + aim scheme combinations) follow native branch behavior

### 4) Lethal damage bookkeeping moved out of damage function (ordering risk)

- [ ] Status: Open (confirmed structural divergence)
- Severity: Medium
- Rewrite location: `src/crimson/creatures/damage.py:117`, `src/crimson/creatures/damage.py:171`
- Current caller handling:
  - `src/crimson/sim/world_state.py:175`, `src/crimson/sim/world_state.py:225`
  - `src/crimson/creatures/runtime.py:423`, `src/crimson/creatures/runtime.py:471`
  - `src/crimson/creatures/runtime.py:906`, `src/crimson/creatures/runtime.py:923`
- Native evidence: `analysis/ghidra/derived/hotspots/creature_apply_damage/work/004207c0_creature_apply_damage.work.c:82`, `analysis/ghidra/derived/hotspots/creature_apply_damage/work/004207c0_creature_apply_damage.work.c:125`
- Confirmation details:
  - Rewrite `creature_apply_damage` returns a kill flag and does not run death bookkeeping inline.
  - Native lethal branch performs inline death handling (`creature_handle_death(...)`) as part of the same damage path.
  - Current rewrite callers do immediate follow-up handling, but ordering is now distributed across call sites.
- Risk:
  - future call sites can miss or misorder death handling side effects (kill counters, FX/SFX ordering, RNG order adjacency)
- Acceptance criteria:
  - either restore inline lethal bookkeeping parity in `creature_apply_damage`, or enforce one shared helper that guarantees immediate native-order lethal follow-up for every caller
  - add call-site guardrails so new damage paths cannot bypass lethal bookkeeping

## Suggested PR Slices

1. `player_update`: movement ladder parity by mode flags.
2. `player_update`: aim-scheme dispatch parity.
3. `player_update`: reload gate parity.
4. `creature_apply_damage`: lethal bookkeeping ordering hardening (inline or shared guaranteed wrapper).

## Verification Plan (follow-up PR)

- Use `docs/frida/differential-playbook.md` to pick canary captures and run before/after divergence reports for each slice.
- For each slice, record:
  - first mismatch tick/category
  - RNG missing-tail deltas around focus
  - whether drift moved later, changed class, or cleared
