# `player_update` renaming guide

This guide is for `work/004136b0_player_update.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `iVar7` -> `player_idx`
- `pfVar16` -> `player_pos_ptr`
- `ppVar6` -> `player_ptr`
- `uVar9` -> `rng_value`
- `pVar21` -> `projectile_type`
- `pcVar13` -> `creature_ptr`
- `pfVar1` -> `spread_heat_ptr` (behavior matches spread heat accumulation/cooling; decompile field label may lag)
- `local_24` -> `player_start_pos_y`

## Deeper pass notes

- Existing sectioning is stable for movement/aim/fire phases.
- Remaining readability lead is splitting reused scalar temps inside the weapon
  dispatch ladder (`line 1214+`) into per-weapon role names.

## Section Map (Current Work Copy)

- line 54: early frame gate (console/death short-circuit)
- line 69: always-on upkeep timers + low-health bleed pulse
- line 108: timed perk proc projectiles/effects
- line 257: spread damping gate behavior
- line 281: player-controlled movement mode ladder
- line 713: demo/auto-target movement path
- line 825: post-move spread/reload handling
- line 909: aim scheme updates (mouse/stick/keys)
- line 1045: fire gate (cooldown/reload/alt swap)
- line 1214: main weapon-id dispatch ladder
- line 1736: fire-bullets fallback stream
- line 1791: end-of-frame normalization/clamps

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
