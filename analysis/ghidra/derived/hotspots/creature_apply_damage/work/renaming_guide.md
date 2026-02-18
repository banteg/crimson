# `creature_apply_damage` renaming guide

This guide is for `work/004207c0_creature_apply_damage.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `uVar3` -> `rng_value`
- `pfVar5` -> `living_fortress_timer_ptr`

## Suggested section comments

- perk-scaled incoming damage modifiers
- post-hit velocity impulse apply
- lethal branch (death handling + death SFX/FX)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
