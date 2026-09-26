# Loop inits and the inverted guard: where they land, and what the extra block costs

C2.DLL 12.00.8966 (image base 0x10700000), `/O2 /G5`. This note answers two questions about a
top-tested loop:

1. Does an initialisation end up before or after the guard (the copy of the loop test)?
2. Why does moving an init behind the guard change the global register allocation of unrelated
   values?

It ends with two snail-mail cases, `initialize_dip_path_template_pair` (Dip) and
`initialize_turnunder_path_template_pair` (Turnunder).

Evidence labels:

- **Verified** means observed in a compile trace. The traces used the IL stage dumps of
  `scripts/c2/il_stage_trace.py` and the new `scripts/c2/priority_trace.py`, or a matcher result.
- **Intervention** means allocator state was patched inside the observer and the patched object was
  scored. This is a sufficiency proof, not a source form.
- **Read** means taken from the existing notes cited.

## 1. The placement rule

| Init written as | Where it lands | Why |
|---|---|---|
| a statement before a `for`/`while` (including the for-init) | **before** the guard `jcc`, in the guard block | `invert_loop` 0x107447ad splices the whole header block into the block before the header, so the copied test is appended after the code already there. Nothing moves the init: invariant motion only hoists tuples that are inside the loop. [Verified: Dip `tied_single`, flow graph after 0x107053de. Block 1 ends `i = 0; sample_offset = 168; cmp i, width; jcc`, and block 2 is the empty preheader, flag 0x8000000.] |
| a statement inside an explicit `if (n > 0) { init; do … while }` | **after** the guard, in its own block | The init block is not empty, so `loop_ensure_preheader` 0x10743df7 puts a new empty preheader after it. [Verified: Dip `tied_guarded`. At `build_live_ranges`, block 2 holds `sample_offset = 168` and block 3 is the empty preheader.] |
| an init created by the IV pass (a strength-reduced derived IV, or the rewrite of a basic IV that merge #1 folded into another) | **after** the guard, in its own block | `set_preheader_insert_point` 0x10744cc6 appends it to the end of the preheader ([strength-reduction.md](strength-reduction.md) §2). The next `cfg_reanalyze` (0x10706210, through `loop_ensure_preheader`) finds that preheader non-empty and inserts a new empty one after it. The SR init therefore ends up exactly like a user init inside an explicit guard. [Verified: Dip `iv_lead`. At `build_live_ranges`, block 2 (flags 1) holds `#1877 = 168` and block 3 (flags 0x8000000) is empty.] |

So **every init that executes after the guard costs one extra basic block**. It sits between the
guard block and the empty preheader. An init before the guard costs nothing.

A user init stays where it was written only while the variable survives the IV pass. If merge #1
(0x10746a2f) rewrites the variable in terms of another basic IV, SR rebuilds the value as a derived IV.
That IV has its own preheader init after the guard. The user's store before the guard becomes dead and
is deleted at the end of globopt. This is the Turnunder case (§4).

## 2. What the extra block does to global colouring

`score_live_ranges` 0x10724b25 walks the blocks in list order. For each block let P be the number of
distinct candidate live ranges referenced in it, and w = `1 << depth`. Each range referenced in the
block gains P·w·S_b, where S_b is its raw savings in the block. Each range that is only live through the
block loses P·w ([regalloc.md](regalloc.md) §3.5).

`priority_trace.py` hooks the block-start call at 0x10724b72 (`bitset_intersects`) and records the
running priority of every range there. The difference between two consecutive records is exactly one
block's contribution.

Moving an init behind the guard changes two terms:

- **The entry block loses one referenced range.** The cursor's def is no longer in it, so P(block 1)
  drops by 1. Every range referenced there loses S_b1 once.
- **A new block exists.** Every range live through it pays P(new block)·w.

Dip, constant 0's second-level split piece, which is the range that decides the colouring
[Verified, rescore after colouring #30]:

| source | block 1 | init block | loop and rest | piece priority | competitor (`vertices` piece, allowed {ebp}) |
|---|---|---|---|---|---|
| `tied_single` (init before the guard) | +182 = 14·13 | n/a | −34 | **148** | 144 |
| `iv_lead` (SR cursor) | +169 = 13·13 | −2 (P = 2: D and constant 168) | −34 | **133** | 144 |
| `tied_guarded` (explicit guard) | +169 | −2 | −34 | **133** | 144 |

The piece's allowed set is {ebp} in all three.

- **148 > 144.** Zero is coloured first and gets ebp. `vertices` then loses ebp and is split. The loop
  index gets ebx. This is native's allocation.
- **133 < 144.** `vertices` takes ebp first, which leaves the zero piece with an empty allowed set.
  0x107204d6 splits it at the markers. The new piece covers blocks 1..22 and has allowed {ebx}; after
  rescoring its priority is 187. It gets ebx, and the index then gets ebp.

  The snail report's "187 vs 148" compares this post-split piece with the tied piece. **187 is a
  consequence of losing ebp, not the cause.** The decision is 133 against 144.

Threshold check (intervention: add N once to every constant-0 range that starts in block 1, at every
scoring return; `priority_trace.py --bump-constant 0 --bonus N`) on `tied_guarded`:

| N | piece | result |
|---|---|---|
| 11 | 144, which ties `vertices`. On equal priority the higher tie key goes first, and a constant's tie key is 0. | unchanged object (86.18%) |
| 12 | 145 | **100% normalized**, 655/655, native allocation, with `mov edi,0xa8` after `jle` |
| 13, applied to `iv_lead` | 146 | native allocation and init placement; one receiver left (`mov edx,[esi+0x58]; mov ecx,edi; add ecx,edx`) |

**Rule (Dip):** with the init after the guard, the entry block needs one more referenced candidate
range (P 13→14, worth +13 here). Any other source difference worth at least +12 on that piece would also
do. This is a property of the rest of the function, not of the loop.

## 3. Predicting from source (checklist)

1. Find the inits that run once before the loop. A for-init, or a statement just before a top-tested
   loop, lands before the guard. An explicit `if` guard with the init inside, a strength-reduced cursor
   (`(i+1)*sizeof`, `&a[i+1]`), or a basic IV that merge #1 folds into another lands after the guard
   and adds a block.
2. Merge #1 survivor ([strength-reduction.md](strength-reduction.md) §3, the same champion rules): among
   basic IVs with the same step, the one with more uses, or the one live after the loop, survives. The
   others become `survivor + (init_other − init_survivor)` and are rebuilt by SR with preheader inits.
3. If step 1 adds or removes a block, recompute the priorities that matter with
   `priority_trace.py --constant V --symbol ID` rather than guessing. The effect is P(entry block)·S of
   every range referenced in the entry block, plus P(new block) on every range live across it.

## 4. Snail case walkthroughs

### Dip (`initialize_dip_path_template_pair`)

- `tied_single` (99.85%) is exact except for `mov edi, 0xa8`. Its cursor is a user variable initialised
  in the for-init, so by §1 that init is in the guard block. Native has it after `jle`, so native's
  cursor init is in its own block (SR-derived or explicitly guarded). That extra block costs the zero
  piece 15, which is why every "after the guard" shape tried by snail flips the colouring
  (`iv_lead` 85.80%, `tied_guarded` 86.18%, 60 probes in `RESULTS.md`).
- By §2, native's function must also have P(block 1) = 14 while the cursor is outside block 1. The
  +12 intervention shows that nothing else is missing: `tied_guarded` plus 12 is 655/655 normalized.
- **Source search done here, all neutral** (86.18% unchanged): guard spelled `width_cells_ > 0`,
  `curve_count > 0` or `i < width_cells_`; latch on `curve_count`; `while (++i < …)`; `sample_offset`
  declared outside the `if` or at the top of the function. `endpoint_z` computed early and a separate
  `endpoint_offset` variable (instead of `endpoint *= sizeof`) are worse. Declaring the tied cursor
  early (live through the endpoint code) steals edi from `endpoint` (91.3%).
- **Also present in `tied_single`, hidden behind its normalized mismatch:** 14 loop instructions have
  swapped SIB base and index. `tied_single` at +0x1af is `89 ac 07 90` = `[edi+eax+0x90]`; native is
  `89 ac 38 90` = `[eax+edi+0x90]`. The intervened `tied_guarded` object is 100% normalized but
  `body_byte_exact=false` for exactly these bytes. This is the address-order hash
  (snail `tools/match/c2/address-order.md`). The source that supplies the fourteenth block-1 range may
  also shift the temporary ids that decide it.

### Turnunder (`initialize_turnunder_path_template_pair`)

Native `mov [esp+0x6c], ebx` (`sample_step = 0`) is before `cmp eax,ebx; jle`. Ours is after the
branch, wherever the source puts it. Trace of the canonical source [Verified]:

- The curve loop `for (i = 6; sample_step < interior_count; ++sample_step) { …; ++i; }` has two step-1
  basic IVs. Merge #1 keeps `i`, which has many more uses (every `primary_samples[i]`), and rewrites
  every `sample_step` use as `#2021 = i + (−6)`.
- SR turns `i − 6` into derived IV `#2031`, with init 0 at the end of the preheader. That is the counter
  that is `fild`ed and stored to `[esp+0x6c]`.
- The user's `sample_step = 0` in the guard block becomes dead. It is still present at the last IV step
  and gone at `purge_unreferenced_temps` entry.

Same rule as Dip, seen from the other side: native's counter init is a surviving user init, so native's
curve loop has a single basic IV (`sample_step`), and the index is derived from it.

- **T1** (predicted before compiling): drop `++i` and write `i = sample_step + 6;` at the top of the body,
  so the loop has one basic IV. Result: `mov [esp+0x6c], ebx` moves before `cmp eax,ebx; jle` as native.
  `i = 6 + sample_step` and a body-local `int i = sample_step + 6` behave the same.
- The whole function drops 99.42% → 95.11% (684/687). The ebx cursor is now derived from `sample_step`,
  and the receivers (`mov ecx,ebx; …; add ecx,edx`) and the `rep movsd` setup flip to base-first. This
  is the same trade-off as the NOTES' "physical curve cursor" (94.67%): the receiver order is the
  address-order hash of the cursor temporary. A form that keeps one basic IV and restores the old
  cursor id is still open.

## 5. Tool

```sh
# Crimson scratch
uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> --constant 0 --symbol 549
# snail-mail scratch (run from the snail-mail checkout)
uv run python ../crimson/scripts/c2/priority_trace.py --snail <scratch> --out <new-dir> --constant 0
# re-render
uv run python scripts/c2/priority_trace.py --reuse <trace-dir> --constant 0 --range 39
# intervention (not a source form): +N to constant V's ranges that start in the first block
uv run python ../crimson/scripts/c2/priority_trace.py --snail <scratch> --out <new-dir> --bump-constant 0 --bonus 12
```

The report lists every chooser call in order: range, symbol or constant, priority, tie key, block
span, allowed set and chosen register, plus splits and ranges with benefit ≤ 0. For each selected
range it then prints the per-block priority and benefit contributions in every scoring run. The trace
itself is fully preserving (whole-COFF, replay and missing-stream checks).

## Open questions

- Which native-plausible Dip source puts one more candidate range into the entry block with the same
  instructions? Candidates are a multi-use CSE temporary, a second web of a local, or a constant with
  two eligible uses whose load lands in block 1. Every block-1 (header/endpoint) mutation family snail
  judged with the tied loop is worth rerunning with the guarded loop and this criterion. Under the tied
  loop the cursor supplied the fourteenth range.
- The exact membership of P: 0x10724c3b popcounts the referenced ranges, then adds the def list and the
  referenced entries of the live list. (Corrected in [invisible-ranges.md](invisible-ranges.md): P is not |block+0x48|, which holds ranges referenced or live of every class.) The count equalled |block+0x48| in every Dip block measured, but
  the def-list path was not isolated.
- The Turnunder form that keeps a single basic IV and the native receiver order.
