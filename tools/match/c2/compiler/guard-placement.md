# Loop inits and the inverted guard: where they land, and what the extra block costs

C2.DLL 12.00.8966 (image base 0x10700000), `/O2 /G5`. This note answers two questions about a
top-tested loop:

1. Does an initialisation end up before or after the guard (the copy of the loop test)?
2. Why does moving an init behind the guard change the global register allocation of unrelated
   values?

Evidence labels:

- **Verified** means observed in a compile trace. The traces used the IL stage dumps of
  `scripts/c2/il_stage_trace.py` and `scripts/c2/priority_trace.py`, or a matcher result.
- **Intervention** means allocator state was patched inside the observer and the patched object was
  scored. This is a sufficiency proof, not a source form.
- **Read** means taken from the existing notes cited.

## 1. The placement rule

| Init written as | Where it lands | Why |
|---|---|---|
| a statement before a `for`/`while` (including the for-init) | **before** the guard `jcc`, in the guard block | `invert_loop` 0x107447ad splices the whole header block into the block before the header, so the copied test is appended after the code already there. Nothing moves the init: invariant motion only hoists tuples that are inside the loop. [Verified: flow graph after 0x107053de. The guard block ends with the inits, then the compare and `jcc`; the next block is the empty preheader, flag 0x8000000.] |
| a statement inside an explicit `if (n > 0) { init; do … while }` | **after** the guard, in its own block | The init block is not empty, so `loop_ensure_preheader` 0x10743df7 puts a new empty preheader after it. [Verified at `build_live_ranges`: the init has its own block, followed by the empty preheader.] |
| an init created by the IV pass (a strength-reduced derived IV, or the rewrite of a basic IV that merge #1 folded into another) | **after** the guard, in its own block | `set_preheader_insert_point` 0x10744cc6 appends it to the end of the preheader ([strength-reduction.md](strength-reduction.md) §2). The next `cfg_reanalyze` (0x10706210, through `loop_ensure_preheader`) finds that preheader non-empty and inserts a new empty one after it. The SR init therefore ends up exactly like a user init inside an explicit guard. [Verified at `build_live_ranges`: a block with flags 1 holds the SR init, followed by the empty preheader with flags 0x8000000.] |

The three rows were verified on Snail Mail's initialize_dip_path_template_pair.

So **every init that executes after the guard costs one extra basic block**. It sits between the
guard block and the empty preheader. An init before the guard costs nothing.

A user init stays where it was written only while the variable survives the IV pass. If merge #1
(0x10746a2f) rewrites the variable in terms of another basic IV, SR rebuilds the value as a derived IV.
That IV has its own preheader init after the guard. The user's store before the guard becomes dead and
is deleted at the end of globopt (verified on Snail Mail's initialize_turnunder_path_template_pair).

## 2. What the extra block does to global colouring

`score_live_ranges` 0x10724b25 walks the blocks in list order. For each block let P be the number of
distinct candidate live ranges referenced in it, and w = `1 << depth`. Each range referenced in the
block gains P·w·S_b, where S_b is its raw savings in the block. Each range that is only live through the
block loses P·w ([regalloc.md](regalloc.md) §3.5, [invisible-ranges.md](invisible-ranges.md) for what P
counts).

`priority_trace.py` hooks the block-start call at 0x10724b72 (`bitset_intersects`) and records the
running priority of every range there. The difference between two consecutive records is exactly one
block's contribution.

Moving an init behind the guard changes two terms:

- **The entry block loses one referenced range.** The cursor's def is no longer in it, so P(block 1)
  drops by 1. Every range referenced there loses S_b1 once.
- **A new block exists.** Every range live through it pays P(new block)·w.

Whether that flips a colouring depends on the margin between the ranges competing for a register, so it
is a property of the rest of the function, not of the loop. A range that loses its register this way is
then split, and the new piece is rescored. The piece's priority can be much higher than the one that lost,
but it is a consequence of losing the register, not the cause. The deciding comparison is the one before
the split.

On equal priority the higher tie key goes first, and a constant's tie key is 0 (verified by the
`--bump-constant` intervention below).

## 3. Predicting from source (checklist)

1. Find the inits that run once before the loop. A for-init, or a statement just before a top-tested
   loop, lands before the guard. An explicit `if` guard with the init inside, a strength-reduced cursor
   (`(i+1)*sizeof`, `&a[i+1]`), or a basic IV that merge #1 folds into another lands after the guard
   and adds a block.
2. Merge #1 survivor ([strength-reduction.md](strength-reduction.md) §3, the same champion rules): among
   basic IVs with the same step, the one with more uses, or the one live after the loop, survives. The
   others become `survivor + (init_other − init_survivor)` and are rebuilt by SR with preheader inits.
   To keep a user init before the guard, write the loop with a single basic IV and derive the other value
   from it in the body.
3. If step 1 adds or removes a block, recompute the priorities that matter with
   `priority_trace.py --constant V --symbol ID` rather than guessing. The effect is P(entry block)·S of
   every range referenced in the entry block, plus P(new block) on every range live across it.

## 4. Tool

```sh
uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> --constant 0 --symbol 549
# re-render
uv run python scripts/c2/priority_trace.py --reuse <trace-dir> --constant 0 --range 39
# intervention (not a source form): +N to constant V's ranges that start in the first block
uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> --bump-constant 0 --bonus 12
```

The report lists every chooser call in order: range, symbol or constant, priority, tie key, block
span, allowed set and chosen register, plus splits and ranges with benefit ≤ 0. For each selected
range it then prints the per-block priority and benefit contributions in every scoring run. The trace
itself is fully preserving (whole-COFF, replay and missing-stream checks).

## Open questions

- The exact membership of P: 0x10724c3b popcounts the referenced ranges, then adds the def list and the
  referenced entries of the live list ([invisible-ranges.md](invisible-ranges.md) §1). P is not
  |block+0x48|, which holds ranges referenced or live of every class. The def-list path was not isolated.
