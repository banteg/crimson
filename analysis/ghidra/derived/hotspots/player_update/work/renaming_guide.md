# `player_update` renaming guide

This guide is for `work/004136b0_player_update.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## Suggested section comments

- input/state gate and alive checks
- aim target/heading updates
- movement and collision responses
- fire/reload gating
- perk and bonus side effects

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
