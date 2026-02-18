# `creature_apply_damage` renaming guide

This guide is for `work/004207c0_creature_apply_damage.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `uVar3` -> `rng_value`
- `pfVar5` -> `living_fortress_timer_ptr`
- `iVar2` -> split by role in work copy (`perk_count`, `living_fortress_scan_count`, `debris_spawn_count`)
- `iVar4` -> `scale_roll`
- `fVar1` -> split by role in work copy (`heading_jitter`, `impulse_y`)

## Deeper pass notes

- Work copy keeps the damage-type perk stacks and lethal FX branch separated by
  role-specific temps so parity reads stay local to each phase.

## Section Map (Current Work Copy)

- line 24: damage-type 1 perk stack
- line 51: non-heavy heading jitter on hit
- line 65: ion-gun mastery multiplier path (`damage_type == 7`)
- line 70: already-dead shrink-only path
- line 77: live-target apply (`pyromaniac`, health, impulse)
- line 87: lethal resolution (death bookkeeping + SFX/debris FX)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
