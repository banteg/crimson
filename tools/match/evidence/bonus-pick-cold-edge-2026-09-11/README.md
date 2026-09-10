# Bonus selection cold-edge source controls

`bonus_pick_random_type` remains non-exact: 75.925926%, 162/162 instructions,
prefix 55, and 20 mapped native references with no mismatches or unresolved
references. Both normalized exactness and encoded-body exactness remain false.
The canonical source and compiler configuration are unchanged.

The original stage-5 Nuke check starts at `0x00412628`, after the retry
backedge and before the success and fallback return tails. The retained
source places it beside the stage-4 checks. This changes branch destinations
throughout the rest of the function even when the other instructions agree.

## Replay

From the repository root:

```sh
uv run python tools/match/evidence/bonus-pick-cold-edge-2026-09-11/verify_controls.py \
  --out /tmp/bonus-pick-cold-edge
```

Use repeatable `--control family/name` arguments to select individual controls.
The verifier reconstructs each source from exact edits against the recorded
canonical source hash, forces a fresh compilation, and compares its measured
result with the recorded result. It rejects a changed canonical source,
compiler, or baseline flags. Individual option controls carry their own
recorded flags. The receipt also identifies the current compiler build key,
control file, and verifier by hashes.

## Recorded controls

All 166 controls compiled successfully. None is normalized or encoded exact.
They cover these specific forms:

| Family | Controls |
| --- | ---: |
| `acceptance-owner` | 5 |
| `goto-retry` | 6 |
| `quest-bonus-switch` | 11 |
| `eligibility-loop-condition` | 8 |
| `constant-controls` | 16 |
| `duplicated-tail` | 4 |
| `option-controls` | 12 |
| `stage5-helper-controls` | 18 |
| `combined-predicates` | 21 |
| `name-order-controls` | 6 |
| `common-prefix-controls` | 15 |
| `assigned-quest-controls` | 24 |
| `local-loop-controls` | 6 |
| `forbidden-id-controls` | 14 |

The highest ratio is 80.745342% for the Freeze-first shared Nuke predicate.
That candidate has only 160 instructions and shares a comparison that the
original keeps separate. Its larger ratio is not recovery of the native
instruction sequence, and it is not promoted.

Duplicating common filter code can put quest checks after the retry backedge,
but retains extra instructions and can move the stage-4 check too. These
controls isolate an effect of source structure; they are not matching sources.
The remaining controls either reproduce the existing sequence or introduce
other differences. No source, compiler option, or reference alias is promoted.

These are bounded experiments, not an exhaustive search or proof that the
function cannot be matched. The package records source and option controls;
it does not depend on modified compiler passes, binary patches, or the later
remake's behavior. Compilation alone is not an equivalence proof for every
experimental spelling.
