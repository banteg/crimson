# x87 register allocation: which float values stay on the stack (C2.DLL 8966)

This note explains when VC6 keeps a float or double variable on the x87 stack (`fld st(i)`, a
final `fstp st(0)`) and when it gives the variable a stack home instead (`fstp [m]` / `fst [m]` …
`fld [m]`). The home may be a dead parameter's slot. Addresses are virtual addresses in the pinned
C2.DLL (image base 0x10700000), and all rules are for `/O2` (`/Ot`) without `/Op`.

"Verified" means confirmed with the preserving observer
([`scripts/c2/x87_alloc_trace.py`](../../../../scripts/c2/x87_alloc_trace.py), see [Tool](#tool)) on
real compiles. "Read" means static reading only.

Short version:

1. Every named float local, parameter and multi-use CSE temporary is an x87 candidate. Values used
   exactly once never get this far: forward propagation replaces them with an expression temporary
   and a FROUND ([x87-scheduling.md](x87-scheduling.md) §3).
2. `allocate_x87_live_ranges` 0x107645d8 is a stack allocator, not a colouring allocator. It scores
   each candidate, drops the ones that score 0 or less to memory, and then walks the rest in priority
   order. Each range is kept on the stack only if it nests LIFO with the ranges already placed there.
3. The float score counts **definitions, not uses**. A float scores +2 per definition, +1 if its last
   use is an `fld` feeding a store or compare, and −1 per edge on which it dies without a use. A reload
   costs −1 and a spill store −2. Every term is multiplied by 2^loop depth.
4. A range that crosses a range already on the stack (it is born under the other's lifetime and dies
   after it, or the other is born inside it and outlives it) is split at the crossing. The pieces are
   re-scored. A reload piece of a float scores at most 0, so after a split the variable normally lives
   in memory. The only exception is a definition piece whose last use is an `fld` feeding a compare
   or store.
5. A variable left in memory is laid out like any other local. The `fstp m; fld m → fst m` peephole
   produces the `fst [m]` … `fld [m]` shape, and the frame packer may put `m` in a dead parameter's
   home ([frame-model.md](frame-model.md) §4).

## 1. Where it runs

`global_color_registers` 0x1072fb58 calls `allocate_x87_live_ranges` (call at 0x1072fd24) when
`g_class_candidates[1]` (float candidates) is non-empty, or when the function uses FP, has
`g_fp_loop_list` entries and `/Op` is off. It runs after copy coalescing and
`forward_substitute_single_def_ranges`, and before the integer colouring. The candidates are
the class-1 live ranges built by `build_live_ranges`. Under `/Op` floats are never candidates, so
every float variable lives in memory. [Read]

```
ebx = x87_tag_depths_and_split_at_calls(fn, cands)      // 0x10764745
x87_score_ranges(fn, cands)                              // 0x107649da
queue = x87_prune(fn, x87_queue(cands, 0), ebx)          // 0x10764f67, 0x1076504d
while queue:
    if ebx: remove ebx from queue (0x107666d4); split_live_ranges_at_markers(fn, ebx, 1) (0x107204d6)
            x87_score_ranges(fn, new pieces); queue = x87_prune(fn, x87_queue(pieces, queue), NULL)
    lr = pop(queue)
    if x87_range_fits_stack(fn, lr, on_stack):          // 0x1076590f
        lr->reg = &g_reg_symbols[0x1f]  (ST0); on_stack |= lr
        ebx = x87_commit_range(fn, lr, on_stack, all)    // 0x10765d51
    else: push lr back; ebx = {lr}                       // split it next iteration
0x1076520a(); 0x10765225(fn, ...); fold_x87_copy_sequences(fn)   // 0x1072fef2
```

A candidate that `x87_prune` drops has its operands turned back into plain symbol operands
(`operand_make_sym`), so it becomes a memory variable. [Verified: dropped ranges show up as `sNNN`
memory operands in the post-allocation IL.]

## 2. Depth tags and forced splits (0x10764745) [read; the tags are verified in traces]

The pass walks each block backward, tracking the depth of expression temporaries on the x87 stack
(`x87_stack_effect` 0x10730253). It writes the depth after each tuple into tuple +0x12 and +0x13,
where 0 marks a statement boundary. The same walk splits candidates in three cases:

- **Calls.** A candidate live across a non-intrinsic call is split at the call. The x87 stack
  cannot hold a value across a call.
- **A float call inside an expression.** The live candidates are split at the start of that
  expression, and candidates referenced in the rest of it are split around each reference.
- **Depth 8.** Candidates live where the temporary depth reaches 8 are split there.

It also computes last-use flags (operand +0x11 bit 0x10) for the float candidates.

## 3. Score (0x107649da) [verified]

For each reference of a candidate range, multiplied by `w = 1 << loop_depth` under `/Ot` (1 without it):

| Reference | float (size 4) | double (size 8) | Helper |
|---|---|---|---|
| definition (`fstp v`) | +2 | +4 | 0x10764ed6 |
| use that is not the last use | 0 | +1 | 0x107658a0 |
| last use that is an `fld v` whose result goes straight into `fcom`/`fcomp`/`fst`/`fstp` | +1 | +2 | 0x107658d6, test 0x10764f18 |
| any other last use | 0 | 0 (the test fails) | |
| reload `0x163` (piece start, parameter entry, candidate constant) | −1 | −2 | 0x107658d6 |
| spill store `0x164` | −2 | −4 | 0x10764ed6 |
| block exit edge where the range is still live but not live into the successor (it must be popped) | −1 | −1 | tail of 0x107649da |

A double scores like a float in two cases (0x107658a0, 0x107658d6, 0x10764ed6): when its symbol
has class 7 or 8, or when it is not a parameter and the frame is 8-byte aligned (fn flag
0x600000). [read]

priority = benefit = the sum. The queue (0x10764f67) is sorted by priority, highest first. Ties go to
the higher `tie_key`, which means the def in the latest block, and within a block the **earliest**
def ([regalloc.md](regalloc.md) §2). A range with benefit ≤ 0 is dropped to memory. The first prune
spares ranges that are about to be split.

Traced values:

| Case | Terms | Observed |
|---|---|---|
| micro `float h = a*0.5f; g[0]=h+b; g[1]=h*h; g[2]=h;` | def 2 + last `fld h` → `fstp` 1 | 3 |
| same with `double` | 4 + 1 + 1 + 1 + 2 | 9 |
| float `h` defined and used inside a loop, last use `fmul` | 2 × 2 | 4 |
| draw_textured_quad `half_width`, `half_height`, `cos_radius` (several uses each) | def only | 2 |
| update_subgoldy `window` (3 defs, dies on one edge) | 6 − 1 | 5 |
| update_subgoldy `speed` (1 def, dies on one edge) | 2 − 1 | 1 |
| update_backdrop CSE temp in a 2-deep loop | (2 − 1) × 4 | 4 |
| parameters, candidate constants (reload only) | −1 or −2 | dropped |

So for floats **the number of uses does not matter**. What matters is the number of definitions,
whether the last use is an `fld` into a store or compare, and edge pops.

## 4. The LIFO test (0x1076590f) [verified]

Each range has a list of def points (lr +0x34) and end points (lr +0x38). An end point is the tuple
that closes the expression containing the last use, meaning the first tuple after the last use with
depth tag 0. Where the range dies on a CFG edge, the end point is that block's start.
`0x10765be8(t, on_stack)` gives the placed ranges that are live just before tuple `t`. The test
fails, and inserts a split marker for the candidate at the conflict point, in these cases:

| Tracer label | Call site | Rule |
|---|---|---|
| `below-dies-inside` | 0x10765b68 | A placed range is live at our def and dead at our end, and its end list lacks our end: it dies while we are above it |
| `below-ends-inside` | 0x10765ba7 | Any placed range live at our def has an end point where we are live |
| `born-inside-outlives` | 0x1077860e | A placed range is born inside our range and outlives it. First the allocator tries to extend our end to its end with a `0x19e` REGUSE (`0x1077999d`); that fails if another candidate is defined in between |
| `last-use-expression-defines` | 0x10765aff (0x10765cc4) | The expression containing our last use defines another candidate before the use |
| `def-depth-mismatch` | 0x10778675 (0x1077869b, 0x10778756) | Our defs sit at different expression depths or stack positions [read only] |

Ranges ending at the **same** tuple nest fine. That is why `half_width` and `half_height`, both last
used in the radius expression, both stay on the stack.

After a failure the range is split at the markers (`split_live_ranges_at_markers` 0x107204d6, class
1). The pieces are re-scored and pruned with no protection:

- **Def piece:** +2 for the def, −2 for the spill store placed right after it, so 0 and memory.
  With a last `fld` into `fcom`/`fst`/`fstp` it scores +1 and stays on the stack.
- **Reload piece:** −1 for the reload, 0 for the uses, so it is dropped. With a last `fld` into
  `fcom`/`fst`/`fstp` it scores 0, which is also dropped. A float reload piece can never stay on the
  stack.

## 5. Commit (0x10765d51) [partly verified]

The committed range gets storage ST0. For each end point the allocator inserts an explicit pop,
`fstp st(0) <- lr` (0x63), after the end of the expression. These are the trailing `fstp st(0)`s in
listings [verified in the post-allocation IL]. It then simulates the stack through the range's blocks
and raises the tuples' depth tags. At depth 8 the not-yet-placed candidates are split at the next
statement boundary [read]. The later `x87_block_fxch_scheduling` 0x107392c7 and
`x87_rewrite_stack_operands` 0x10766381 only renumber st(i) and place `fxch`
([frame.md](frame.md) §5). They never spill. Lowering's own spill (`x87_spill_stack_entries`
0x1076ea17) happens only when 8 expression temporaries are live.

## 6. From memory variable to listing

A dropped or split-away variable is a normal memory local:

- its def is `fstp [m]`;
- a use in the next statement starts with `fld [m]`;
- `final_lowering_peepholes` turns `fstp m; fld m` into `fst m` when `/Op` is off (0x10735f14);
- the result is `fst [m]; fadd …; …; fld [m]`.

Its frame slot comes from the reference-count sort and the slot packer. The packer puts it in a
dead parameter's home when the two do not interfere ([frame-model.md](frame-model.md) §4). In the
S4 variant below, `half_height` lands in `width`'s home `[esp+0x3c]`, which is where native keeps
it too.

## 7. Worked cases

### update_backdrop (snail, exact): a CSE temp in memory

`phase = phase_step + phase; if (phase > 2π) phase -= 2π;` inside a doubly nested loop. There are
two candidates: the store temporary `t539` (score 12 = (2 + 1) × 4) and the CSE temporary `t240` of
the sum (score 4 = (2 − 1) × 4).

- `t539` is placed first.
- `t240` is born while `t539` is live and outlives it, so it fails `below-dies-inside` and is split.
  Its pieces score 0 and −8.
- The sum therefore lives at `[esp+0x10]`: `fadd; fst [esp+0x10]; fstp [esi]; fld [esp+0x10]; fcomp`.

This matches native byte for byte.

### update_subgoldy completion clamp (snail Q1a): confirmed

In the source, `float window = rate*0.17f; float speed = velocity.z; if (speed >= window) { window = rate*0.5f; if (speed <= window) window = speed; } velocity.z = window;`

- `speed` has three reaching uses, so it is not forward-propagated and becomes a candidate
  scoring 1 (2 − 1).
- `window` scores 5 and is placed first.
- `speed` fails `below-dies-inside` and `below-ends-inside`, because `window` is redefined and dies
  on an edge inside `speed`'s range.
- Split pieces:
  - the def piece, whose last use is `fld speed` into the first `fcomp`, scores 2 − 2 + 1 = 1 and
    stays on the stack;
  - the reload pieces at the inner compare and at `window = speed` score 0 and go to memory.
- That is the candidate's `fld [ebp+0x418]; fst [esp+0x10]; fcomp st(1)` … `fld [esp+0x10]`.

Native has no `speed` variable. Each read is a single-use value: forward-propagated, with a FROUND,
and loaded right at its use, as in `fld [ebp+0x418]; fcomp st(1)`. The compare needs a stack
temporary as its left operand. A plain member read is a memory operand, so it gives
`fcom [ebp+0x418]` instead.

- Verified: an inline float accessor `Speed(velocity)` at each use gives `fld [0x418]; FROUND; fcomp`
  at both compares and `fld [0x418]; fstp window` for the assignment. The first clamp then matches
  native (99.28% → 99.40% with only that clamp changed).
- An inline `ClampWindow(velocity.z, rate)` helper does not reproduce it (91.83%).

### draw_textured_quad_immediate `height*0.5` (snail Q1b)

Ours: `half_width` and `half_height` both score 2. Both end at the radius argument store, so they
nest and both stay on the stack. That gives `fld st(0); fadd [y0]` for `half_height`.

Native: `fmul [0.5]; fst [esp+0x3c]; fadd [y0]; fstp [cy]; fld [esp+0x3c]; fld st(0); fmul st(1);
fld st(2); fmul st(3); faddp; fstp [esp]; fstp st(0); fstp st(0)`. That means:

- the half-height value defined at `fmul` is a memory variable in `width`'s dead home;
- **another** stack range starts at `fld [esp+0x3c]` and is popped by the second `fstp st(0)`.

By §4 that second range cannot be a reload piece of `half_height`, because a float reload piece
scores at most 0. It must be a separate candidate whose **definition** is the load from `m`: a
copy or a CSE temporary of a memory-resident value. It must also be placed before the variable
defined at `fmul`.

Variants compiled on a copy (98.34% baseline):

| Variant | Result |
|---|---|
| Reordered declarations, radius spelled via temps, `+=` accumulation, inline `hypot`/`Square` helpers (by value or `const&`), struct/array half extents, `double` copies, parameter reuse (`width = …`, `height *= …`, `float& = width`) | 96.83–98.34%; the half-height stays on the stack or everything changes order |
| **S4:** `center_y = y0 + height * 0.5f` while keeping `half_height = height * 0.5f` for the radius | 97.58%. The CSE temp of `height*0.5` (placed first, ends at `center_y`) crosses `half_height` (`below-dies-inside`, `below-ends-inside`). `half_height` becomes memory in `width`'s home, and native's first half appears exactly: `fst [esp+0x3c]; fadd [esp+0x20]; fstp [esp+0x20]; fld [esp+0x3c]`. The radius then reads `fmul [esp+0x3c]` instead of `fld st(0); fmul st(1)`, and one `fstp st(0)` is missing |
| `keep_address(&half_height)` (escape) | `half_height` is memory everywhere, and the radius is `fld [m]; fmul [m]`. Symbol reads are not CSE'd |

So native needs:

- a value computed at `height*0.5`, used by `center_y` directly from the stack, and stored to a
  memory variable `m`;
- `m` read again after `center_y` into a distinct stack candidate.

No spelling tried produces the second candidate. Scalar copies are coalesced or propagated, and
inline by-value parameters are replaced by their argument symbol.

## Tool

```sh
uv run python scripts/c2/x87_alloc_trace.py <scratch-dir> --out <new-dir> [--lines A-B]
```

It hooks, through the preserving `c2-trace` observer:

- the allocator after depth tagging (0x10764617);
- both prunes;
- every `x87_range_fits_stack` call and its return;
- the five conflict checks of §4;
- the allocator tail (0x10764660).

The whole COFF object must stay identical. For each function with float candidates it prints:

- the IL with depth tags and `tNNN=lrK` annotations, where `*` marks a last use;
- every candidate's priority, benefit, tie key, def points and end points;
- the queue after splits;
- each verdict with the check that failed and where;
- the IL after allocation, in which dropped ranges appear as `sNNN` memory operands.

It runs in about 3 s for draw_textured_quad_immediate and 7 s for update_subgoldy. `run(scratch,
out, c2=module)` accepts another `match_c2` module. That is how Snail scratches were traced: through
snail-mail's `tools/match/c2/trace.py` adapter, with a stub `crimson` package that points at the
adapter's `c2` and `replay`.

## Open questions

- A natural source for native draw_textured_quad's second stack range (§7).
- `0x10765225`, which runs after the loop, was not read. The traces show its effect only through the
  final IL.
- `def-depth-mismatch` (0x10778756) and REGUSE end extension (0x1077999d) never fired in the traced
  functions. Their rules are from reading.
- The class-1 colouring loop that `global_color_registers` runs after this allocator was not
  traced for float candidates.
- Crimson projectile_render's clamped `fade` ([x87-scheduling.md](x87-scheduling.md), open
  questions) is now a tracer question: a clamp gives `fade` two defs, so the trace will show whether
  it fails the LIFO test or scores ≤ 0.
