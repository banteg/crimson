# `projectile_update` renaming guide

This guide is for `work/00420b90_projectile_update.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `local_e8` -> `slot_idx` (shared loop index across projectile/particle sweeps)
- `local_ec` -> `loop_idx`
- `local_e4` -> `plasma_ring_idx`
- `local_d8` -> `spray_max_offset`
- `local_cc` -> `substep_dx`
- `local_c8` -> `substep_dy`
- `cVar3` -> `particle_kind`
- `pVar4` -> `projectile_type`
- `sVar5` -> `secondary_type`
- `psVar14` -> `secondary_proj_ptr`

## Deeper pass notes

- Primary/secondary/particle passes are now section-mapped and stable for trace
  navigation.
- Highest-yield next split is the primary hit-resolution lane (`line 167+`),
  where one temp integer still carries several role transitions.

## Section Map (Current Work Copy)

- line 90: frame scalar setup (ion master modifier)
- line 97: primary projectile pool sweep
- line 101: lifetime/bounds gates before stepping
- line 132: substep integration and collision probing
- line 167: projectile-type hit FX/special behavior
- line 344: damage pool accounting and impact response
- line 478: expiring ion/gauss radius-damage path
- line 512: secondary projectile lifecycle loop
- line 812: sprite effect housekeeping pass
- line 830: particle simulation and on-contact logic

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
