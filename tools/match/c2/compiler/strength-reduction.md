# Strength reduction, IV merging and exit-test replacement

This note covers the part of `optimize_loop_induction_variables` 0x10745d75 that turns indexed loops
into pointer walks. It explains where the new induction variables (IVs) are initialised, which field
offset a pointer IV is anchored to, when the exit test is rewritten, when the index survives, and how
these IL decisions show up in the final instruction order. The pass list is in
[optimizer.md](optimizer.md). This note corrects that section in a few places (see the end).

Everything here was checked two ways. The code was read in the Binary Ninja database. The rules were
then tested on real compiles with the preserving observer described below. Each claim says whether it
was traced, predicted and then compiled, or only read.

## Observing it: `scripts/c2/iv_trace.py`

```sh
uv run python scripts/c2/iv_trace.py <scratch-dir> --out <new-dir> --report [--passes] [--late]
uv run python scripts/c2/iv_trace.py --report-only <trace-dir>
```

The tool runs the scratch through `crimson match c2-trace`'s preserving harness. The whole-COFF,
replay and missing-stream checks are unchanged. It swaps in an observer that hooks each call made by
0x10745d75 and dumps the whole IL list after each step, with symbol ids, classes, parent/offset for
field symbols, and operand kinds. It also hooks the derived-IV constructor call at 0x1074781f, where
`esi` is the candidate tuple. `--passes` adds dumps at the 11 later stock pass boundaries, and `--late`
adds dumps at every post-allocation pass, including the /G5 scheduler 0x107374aa.

The report prints three things for each loop:
- each derived IV together with the tuple that created it;
- a before/after diff of the IL for each step;
- a summary: creation order, preheader assignments after SR, after `merge#2` and at the end, and the
  derived IVs still updated in the loop.

The anchor is the preheader initial value of the derived IV that survives (for example
`[3:#33c7^32+4]` is `&pool + 4`). Controls can be traced by building a scratch directory whose
function takes an existing native symbol name. Its match metrics do not matter.

## 1. Pipeline order for one loop

`optimize_loop_nest` 0x107450d7 handles child loops first. For each loop it hoists invariants, which
appends them to the preheader end. It then calls 0x10745d75, but only for loops of at most `-Loop#`
blocks. Inside 0x10745d75 the order is:

| step | address | effect relevant here |
|---|---|---|
| basic IVs | 0x10746521 | variables whose every in-loop def is `v = w` or `v = w ± inv` (`w` an IV). A named pointer assigned a derived IV every iteration becomes an IV this way. |
| exit analysis | 0x107468aa | **Returns 1 unless the trip count is the constant 0 or 1.** Checks the exit shape (one exit list entry, which must be the latch), the latch compare being IV-vs-invariant, and the trip count. A failed check only leaves `loop+0x28` (trip count) null. |
| merge #1 | 0x10746a2f | merges the basic IVs, before SR |
| SR | 0x1074775c | creates derived IVs (§2) |
| cleanup / DCE | 0x10747c9a, 0x10747dda | folds the preheader inits and deletes derived IVs that are no longer used |
| idiom | 0x10747ed0 | turns per-iteration stores/copies into 0x190 block intrinsics. Needs a trip count. |
| merge #2 | 0x10746a2f | merges parallel derived IVs, which picks the anchor (§3) |
| LTR | 0x107482cd | rewrites IV-vs-invariant compares onto a derived IV (§4) |
| DCE | 0x10747dda | deletes the index if nothing else uses it |
| address operands | 0x10748429 | rebuilds memory operands on IV temps |
| countdown | 0x107452db | `dec`/`jne` counter. Needs a trip count. |
| final value / empty loop | 0x1074542c, 0x1074572f | need a trip count |

Traced consequence: a `break`, or even a `return` to code after the loop (controls `m2`, `m3`, `m4`
below), does **not** stop SR, merging or LTR. It only removes the trip count, and with it the
countdown, the final-value rewrite, empty-loop deletion and idiom conversion. The inner duplicate
loop in `typo_word_pick_highscore_name` has a `break`. That is why it keeps `cmp edx, ebx; jl`
rather than a countdown.

## 2. Where SR puts the new IVs, and in what order

- **Insert point.** `set_preheader_insert_point` 0x10744cc6 sets `g_preheader_insert_point =
  preheader->+0x20`. That is the block's end sentinel: the mode-4 walk runs from `+0x1c` up to
  `+0x20`. Every initialisation is created with `tuple_insert_before(insert point)`, so it is
  **appended to the end of the preheader**. The preheader is the block after the loop entry code, so
  the IL order is always:
  1. user entry stores such as `accepted_count = 0` (in the block before the preheader);
  2. hoisted invariants;
  3. SR inits for round 1, then round 2, and so on;
  4. the limit temps that LTR adds.

  Traced in `typo_plain2`: block 2 holds `accepted_count = 0`, and preheader block 3 receives the IV
  inits.
- **Rounds.** 0x1074775c runs at most 32 rounds. Each round starts with `reset_iv_worklists`
  0x10746f93, which empties the derived list. It then collects candidates with mode 1 of
  `collect_iv_candidates` 0x10746fb7: `IV*inv`, `IV±inv`, and 4-byte IV conversions. After all the
  candidates are processed, it appends one init per derived IV. A round-1 result such as `D1 = i*72`
  makes `D1 + &table` a candidate in round 2. A named pointer that is assigned `&pool[i].f` also
  becomes an IV, so `p + 4` becomes a candidate in round 2.
- **Candidate order within a round.** The collector walks the loop's blocks from header to latch in
  physical order, and the tuples in order. It pushes each candidate with `iv_worklist_push` 0x10748e12,
  which prepends a node through 0x10710e22. `iv_worklist_pop` 0x10747720 → 0x1074773b pops the head.
  The worklist is therefore **LIFO**, and candidates are handled in reverse program order.
- **One D per expression.** `get_derived_iv` 0x10753def value-numbers `(op, a, b)` through
  `operand_new_cse_sym`. Equal expressions share one derived symbol D. That D is created when the
  *last* occurrence in the walk is popped. It is appended to `g_derived_iv_head/tail`, linked through
  the symbol's `+0x2c` field. Inits are emitted in that list order.
- **Rule S1 (traced).** Within a round, a derived IV's init comes earlier in the preheader the *later*
  its expression's last occurrence is in the forward walk. Rounds follow one another.
- **Numbering (traced).** Symbol ids are handed out when D is created, so their order matches
  creation order. In `typo_plain2` the ids are #232 and #234 in round 1, then #236 and #237 for the
  steps, then #245 and #247 in round 2. The init values and LTR limits get new temps after these.
- **Types.** `i*S + &pool` is built in the index's type (0x1004, int). Derived IVs are therefore int,
  not pointer, typed.

## 3. Which field offset the pointer IV is anchored to

Each distinct `i*S + &pool.f` becomes its own derived IV. The field offset `f` is carried in the
address operand, as a field sub-symbol of `pool` at `+f`. All of these IVs have the same step `S`.
Merge #2 (0x10746a2f, mode 4) then reduces them to one.

1. Mode 4 walks the **preheader** forward. It pushes every `IV = x` init whose IV has a single tagged
   update (tuple `+0x13 == 4`). The walk is LIFO, so the **last init in the preheader is popped first**.
2. The first IV popped is the champion. Each further IV popped is a challenger, so challengers come in
   reverse preheader order. They are compared only when the step operand, update opcode, update block
   and type match, and when they are not both live after the loop.
3. The champion stays if `uses(champion) > uses(challenger)`, or if the champion is live after the
   loop (or has the `+0x11` bit-4 flag). Otherwise the champion is rewritten as
   `challenger + (init_c − init_ch)`, and the challenger becomes the new champion.
4. The rewrite helper 0x10754627 **adds one to the survivor's count per use it redirects**, so the
   winner carries the loser's uses into the next comparison. A use is one tuple that reads D. Each
   candidate occurrence that survives phase-1 CSE counts once, so field reads that CSE merges count
   once, and reads separated by a call count separately.

**Rule A (anchor).** Let P be the derived IVs in preheader order (rule S1). The champion starts as
the last entry of P. Walk P backwards: the challenger wins ties, and the winner accumulates uses. The
survivor's offset is the anchor. The pointer register holds `&pool[i] + anchor`, and every other
field is addressed as `[reg + (f − anchor)]`.

Consequences:
- **Pure index loop, every field read once.** The anchor is the **second field address in IL order**.
  This is not the most-used field. The first field is the initial champion, and the second one beats
  it on the tie.
- **Unequal counts.** With two IVs, the field with strictly more reads wins. With more, the champion carries every count it absorbs, so a late challenger with the most reads of its own can still lose ([iv-anchor-examples.md](iv-anchor-examples.md)).
- **Field-address local** (`const vec2f_t *p = &pool[i].position;`). `p + 4` is a round-2 IV that
  sits last in P. It becomes the champion, and the earliest round-1 field beats it on the tie. The
  anchor is therefore the **first field accessed**, as long as the round-2 IV has few uses; with many uses it keeps the anchor at `local + k`. That is the struct base when the loop starts
  with `pool[i].active` at offset 0, which explains the "base-anchored" results in the audit.
- **User cursor with the same step** (for example `++entry`). The user cursor takes part in the same
  merge. In `quest_spawn_timeline_update` all the field IVs are rebuilt as `entry + k` in the end.

"IL order" here means the order the address tuples are evaluated in. For a commutative expression it
can differ from the source text: `pool[i].x * pool[i].y` evaluates `y` first. Check the order with the
trace (control `g3`).

### Anchor controls (struct `active@0 kind@4 x@8 y@12 hp@16 t@20`, size 24, `/O2 /GB`)

| control | body (IL order) | predicted | observed |
|---|---|---|---|
| `a` (calibration) | active, x (x·x CSE'd) | +8 | `mov eax, pool+8` |
| `b` (calibration) | x, y | +12 | +12 |
| `c` (calibration) | y, x | +8 | +8 |
| `d` (calibration, traced) | active, kind, hp (hp twice, CSE'd) | +4 | +4. Merge trace: active→kind (tie), then kind(2)>hp(1) |
| `e1` | `if (kind == 3) s += hp` | +16 | +16 |
| `e2` | x; y; t (separate statements) | +12 | +12 |
| `e3` | `sink(x); sink(y); sink(x)` | +8 | +8 |
| `e3b` | `sink(y); sink(y); sink(x)` (count beats tie) | +12 | +12 |
| `e5` | `sink(x); sink(x); sink(y)` (count beats tie) | +8 | +8 |
| `g1` | active, then `p = &pool[i].x; p[0]*p[1]` | +0 | +0 |
| `g2` | kind, then `p = &pool[i].x; p[0]*p[1]` | +4 | +4 |
| `g3` | `active ... x * y` | +8 | **+12**. The trace shows IL order active, y, x. Rule A holds on IL order |
| `g4` | `p = &pool[i].x` first, then active | (post hoc) +8 | +8 |

The loop tests are all `cmp reg, pool + 64*24 + anchor` followed by `jl`.

## 4. Exit-test and compare replacement (LTR), and when the index survives

- `replace_loop_exit_tests` 0x107482cd uses mode 2, which collects **every** IV-vs-invariant compare in
  the loop, not only the latch test. For each compare that feeds a branch,
  `rewrite_exit_test_with_derived_iv` 0x10752a50 rewrites `iv rel lim` as `D rel f(lim)`.
  - The compare's new type is `(old type & 0xf000) | (D type & 0xfff)`. The signedness class comes
    from the original compare and the size from D. **An `int` index therefore keeps `jl`/`jge`, and an
    `unsigned` index gives `jb`** (control `h3`).
  - For a negative int scale the branch condition is reversed.
  - Traced in `typo`: the inner loop guard `0 < accepted_count` sits in the outer loop body. It becomes
    `&cache < D_cache`, which is the hand-written `(int)cache_cursor > (int)&cache[0][0]` in the
    canonical source.
- **Constant limits only.** The chooser 0x10752e60 combines the limit with D's expression through
  0x10754157, and it accepts the result only if it folds to a single operand (`IL_ASSIGN`). A variable
  limit `n` gives `n*S + &pool`, which does not fold. So there is no LTR:
  - the index keeps `cmp i, n` if it has other uses (control `m1`);
  - otherwise the loop becomes a `test n; jle; ...; dec; jne` countdown when a trip count exists
    (`k1`, `k2`, `k3`).
- **The index survives when:**
  - it has a non-address use in the loop, such as `last = i`, a `switch (i)`, or `index != exclude`
    (`h1`, `player_update`, `controls_menu_update`);
  - it is live after the loop;
  - the limit is not a constant and no countdown applies (`m1`, the typo duplicate loop);
  - the element size is 1, so the derived pointer has the index's step and is folded back into
    `[base + index]` addressing. With a constant base, merge #2 folds it into the index (`h4`,
    traced; `h2`). With a loop-invariant variable base, `strength_reduce_address_operands` rebuilds
    the address from the index and drops the derived IV (typo's `player_name[char_index]` as
    `[esi+ebp]`, traced).

  Otherwise LTR moves the exit test onto the pointer, and the second 0x10747dda deletes the index
  update.

## 5. Stack homes for pointer counters

Derived IVs are ordinary class-3 expression temps. SR gives them no memory home. One only reaches the
stack when global colouring ([regalloc.md](regalloc.md) §3) leaves it uncoloured. Traced in
`typo_plain2`: at the local allocator's entry the cache IV #245 is a kind-2 memory symbol in every
block. It is loaded into a register only inside the `strcpy` block. Its competitors are:
- the record pointer (ebp);
- `accepted_count` (ebx, reloaded after the inline `strcmp` clobbers `bl`);
- esi, edi and ecx, which the inline string instructions tie up.

This note does not derive a priority formula that predicts the spill. See the open questions.

## 6. From IL order to machine order: why entry stores swap

The /G5 list scheduler 0x107374aa (see [layout.md](layout.md) §4) issues two instructions per cycle,
chosen by priority and then original order. The observed outcome is that the **first independent
instruction after the dependent home store** `mov [acc], ebx` moves up next to `xor ebx, ebx`, and
that instruction is the first preheader IV init. The mechanism is inferred from the pairing rules: a
dependent store cannot share a cycle with its producer. The outcome was traced at the scheduler's
entry and exit:

| source | scheduler input | output |
|---|---|---|
| canonical (hand cursor) | xor ebx; `[acc]=ebx`; ebp=&table; `[cursor]`=&cache | xor ebx; ebp=&table; `[acc]=ebx`; `[cursor]`=&cache |
| plain, `record` local | xor ebx; `[acc]=ebx`; `[D_cache]`=&cache; ebp=&table | xor ebx; `[D_cache]`=&cache; `[acc]=ebx`; ebp=&table |

## 7. Acceptance tests

### (a) `typo_word_pick_highscore_name`: passes, plain source byte-exact

- `typo_plain2` uses nested indexed loops, a `highscore_record_t *record = &highscore_table[i]` local
  and `strcpy(cache[accepted_count++], record->player_name)`. It gives **98.37%, and the only
  difference is the entry stores**, as the audit says.
  - The two table addresses are `i*72 + &table` (once, at the top of the body, ln7) and
    `acc*32 + &cache` (the `strcpy`, ln28).
  - LIFO order makes `D_cache` first and `D_table` second (traced ids #245, #247).
  - By §6, `[D_cache]` is pulled between `xor ebx` and `[acc]`.
- **Prediction:** native order needs `D_table` created first. So some `highscore_table[i]` address
  must occur *after* the cache address in the body. Dropping the `record` local and indexing
  `highscore_table[record_index].player_name` at every use puts the table address last, in the
  `console_printf` argument.
  - Result: `typo_plain3` is **100%, body_byte_exact=True**. Trace: `D_table` #276 comes before
    `D_cache` #278. Scheduler output: xor; ebp; `[acc]`; `[D_cache]`.
- Further predictions, all byte-exact:
  - keep `record` but use `highscore_table[record_index]` only in `console_printf` (`typo_plain4`);
  - keep `record` but use it only in the `strcpy` source (`typo_plain6`).
- Negative control: `typo_plain2` itself.
- The canonical `(int)cache_cursor > (int)&cache` guard is the LTR form of the inner loop's
  `0 < accepted_count` guard (§4).

`typo_plain3` is now the canonical source of
[`typo_word_pick_highscore_name`](../../scratches/typo_word_pick_highscore_name/scratch.cpp).

### (b) Field anchoring: passes after correcting the audit's "most-used field" wording

See §3. There were 8 predictions made before compiling. 7 were correct. The miss (`g3`) is explained
by IL evaluation order, which the trace shows. The audit's "most-used field" is right only when
counts differ. With equal counts the anchor is the second address in IL order, or the first field
accessed when a field-address local is present.

### (c) `quest_spawn_timeline_update` dead pointer store: not an SR/LTR artefact

- **The canonical source goes through SR (traced).** `&entry->template_id` is derived IV #301
  (`entry + 12`) in the group loop. Creation order is +16, +40, +20, +8, +4, +12. Merge #2 runs:
  +12 loses to +4 on the tie, +4 absorbs +8, and +4 then loses to the count field +20 (3
  occurrences).
  `template_id` becomes `(#295 − 16) + 8`. `strength_reduce_address_operands` then rebuilds the
  fields on `entry` (the preheader has no derived init left). So the pointer reaches the late passes
  as an `entry + 12` address definition, which `0x306c1` folds away (see the scratch NOTES).
- **The native store is not an SR/LTR product.**
  - Native reads the pointer from `edi` (`[edi-4]`, `[edi]`), not from `[esp+0x10]`. The slot write
    is dead the moment it is made. A spilled derived IV would be read back from its home, as the
    typo cache IV is.
  - SR, merge and LTR create only promoted temps and never a memory write to a user local.
- **The only IV-pipeline route to such a store is the idiom converter** 0x10747ed0. Traced on the
  four-byte witness (`evidence/timeline-four-byte-home-2026-09-13/witness.cpp`): the byte-copy loop
  becomes the 0x190 copy intrinsic right after `convert_loop_stores_to_block_op`. The intrinsic
  lowers to the unpromoted store, as recorded in that evidence.
- So the witness store comes from a different step of the same driver, one that needs a
  trip-counted copy loop. Native's `[edi-4]` heading address, relative to the template pointer,
  stays unexplained.

### Remaining int-cast holdouts

| scratch | current source | prediction from these rules | status |
|---|---|---|---|
| `typo_word_pick_highscore_name` | hand cursor with int casts | nested indexed loops with direct `highscore_table[record_index]` use (typo_plain3) | **verified byte-exact** |
| `player_update` (auto-target scan) | `do {...} while ((int)candidate < (int)&creature_pool[384])` | `for (creature_index < 384)`, `creature_pool[i].active/health`, `const vec2f_t *position = &creature_pool[i].position` | Loop region **verified** equal to native: base anchor `cmp byte [ecx],0`, `[ecx+0x24]`, `[ecx+0x18]`, `[ecx+0x14]`, `add ecx,0x98; inc edx; cmp ecx; jl`. The current int-cast cursor gives the wrong anchor (+24, with `lea eax,[ecx-24]` for the compare). The whole function drops 64.50→62.66% because the `distance` spill slot moves (`[esp+0x24]` vs `[esp+0x28]`) and there is drift elsewhere. Not a drop-in rewrite. |
| `controls_menu_update` (axis peaks) | `while ((int)peaks < (int)(&peak_13f + 7))` | with an array owner `float peak[7]`: `for (axis_index < 7) if (peak[axis_index] > 0.5f) {... switch (axis_index) ... break;}`. The index survives (switch), and the pointer compare is `&peak+28` with `jl`. | Shape **verified** on a control (`n1`). It needs a header change: the globals are separate scalar symbols. |

## 8. Predicting from source (checklist)

1. Is the loop at most 100 blocks and not a trip-0/1 loop? Then SR/merge/LTR run. Breaks and returns
   do not matter.
2. List every address expression `i*S + &arr.f` in IL order (header to latch, as evaluated). Keep only
   the last occurrence of each distinct expression.
3. Derived IV creation, and so preheader init order, is that list reversed. Round-2 IVs come after it:
   `p + k` where `p = &arr[i].f` is a named pointer, or a `+base` on top of a round-1 `i*S`.
4. Merge each group with the same step using rule A. The survivor's offset is the anchor.
5. Constant limit: the exit test becomes `cmp ptr, &arr + N*S + anchor` with the original signedness,
   and the index dies unless it is used elsewhere. Variable limit: no LTR; the index stays, or the
   loop becomes a countdown if the index is otherwise unused and there is a single exit.
6. Machine order of the entry code: the /G5 scheduler pairs `xor reg, reg` with the first following
   independent instruction, which is usually the first IV init.

## Open questions

- The global-colouring priority that leaves a derived IV in memory (§5) was not measured. The stock
  `c2-trace` allocation hooks record the descriptors needed.
- `0x10752e60` scores competing derived IVs for LTR through 0x1075408c. With several surviving pointer
  IVs of one basic IV, the one chosen was not tested.
- The mode-4 merge flag (`+0x11` bit 4 of the update's destination) and `sub_107543f6` (the "new
  common IV" branch) were not decoded.
- Why `strength_reduce_address_operands` rebuilt the timeline's field IVs on `entry` was observed, not
  derived.

## Corrections to [optimizer.md](optimizer.md)

- Cross-cutting item 7 and the loop matching-implications bullet: "an extra `break` or a second exit
  disables all of it" is wrong. 0x107468aa returns 1 unless the trip count is the constant 0/1. The exit-shape checks
  only gate the trip count, and with it countdown, final value, empty-loop deletion and idiom
  conversion. Controls `m2`, `m3` and `m4` keep pointer IVs and LTR.
- The merge tie-break is more precise than "more uses survives; equal counts eliminate the
  first-listed". The champion is the last preheader init. Challengers come in reverse preheader order
  and win ties. The survivor accumulates the redirected uses (0x10754627 `*arg5 += 1`).
- LTR rewrites every IV-vs-invariant compare that feeds a branch, not only the exit test. It applies
  only when the new limit folds to one operand, which means a constant limit.
