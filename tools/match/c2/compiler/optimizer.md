# C2.DLL machine-independent optimizer (/Og pre-lowering path): deep notes

Everything here comes from static reading of HLIL and disassembly in the read-only database. Nothing was verified dynamically. Annotations are in [`analysis/binary_ninja/c2`](../../../../analysis/binary_ninja/c2).

Naming conventions:
- `dense_set_*` (0x107042f7 family) are fixed-size bit vectors.
- `sparse_set_*` (0x107017ba family) are the chunked sets used by the dataflow.

## Pass map (per-function driver 0x10757fc2)

| order | addr | name | what it does |
|---|---|---|---|
| 1 | 0x1070592f | cfg_rebuild | labels are merged/pruned, basic blocks built, edges added (fg.c) |
| 2 | 0x10718eaf | compute_alias_classes | symbol/field alias classes and per-block points-to. **More than 10000 tuples turns /Oa off.** |
| 3 | 0x10712b1a | eliminate_tail_recursion | a self tail call becomes parameter copies plus a jump to the entry |
| 4 | 0x107053de(ctx,1) | optimize_flow_graph_initial | unreachable code removed (C4702), **RPO block order**, dominators, loops, loop compaction, **loop inversion**, preheaders |
| 5 | 0x1070fc45(ctx,1) | optimize_expression_trees | optimize.c simplifier, constant folding, **operand cost sort** |
| 6 | 0x1070fcda | purge_unreferenced_temps | frees dead compiler temps, whose ids are then reused LIFO |
| 7 | 0x1070448f | cfg_dfs_rpo | reachability (diagnostics) |
| 8 | 0x10712dcb | mark_constant_branch_dead_edges | diagnostics only |
| 9 | 0x10712f4e | warn_missing_return_value | C4715/C4716 |
| 10 | 0x10712faa | warn_uninitialized_locals | C4700/C4701 (skipped for -basic) |
| 11 | 0x107130cb | globopt_run | global optimizer: coalescing, DCE, forward substitution, value numbering, CSE, loop invariant motion, strength reduction, IVs, LFTR |
| 12 | 0x1070fcda, 0x1070fc45(ctx,2) | | temps purged again, then the simplifier re-runs (mode 2 only adds the C4756 warning) |

**Without /Og** the driver runs these instead:
- 0x10704de1 coalesce_label_runs
- 0x1070513a cfg_rebuild_basic_eh
- 0x1070448f
- 0x10712dcb
- 0x10712f4e
- 0x10712faa
- 0x10704d75 cfg_reset_single_block

That means no block reordering, no loop passes, no simplifier and no global optimizer. Source block order is kept.

Other notes:
- /GZ, -ZI and -dlp force /Og (and /Oy) off per function (0x1071bc73).
- -dlp (0x10796112) and -cap/-fastcap (0x10796591) insert profiling code after the optimizer. They were looked at only briefly.
- The VB-only pass 0x10794e0f was not analysed.

## Cross-cutting matching implications (summary)
1. **Block layout.** With /Og, physical block order is the reverse postorder of a DFS that visits the most recently created successor edge first. This keeps structured source order, but code reached only from later code (backward gotos, retry labels) moves.
2. **Loop inversion.** Top-tested `for`/`while` loops are rotated: the test goes into the preheader and a bottom copy is made with an inverted condition, followed by `jmp exit`. The whole header block is duplicated, with no size limit. `do/while` is not rotated.
3. **Loop compaction.** It moves exit-only arms out of the loop body to after the latch. Together with jump-to-next removal and jcc/jmp inversion, branch polarity follows physical adjacency, not the way the source condition is written.
4. **Commutative operand order.** It is a stable descending sort on the packed cost `need<<24 | size<<16 | hash16`.
   - Constants always go last.
   - On a tie, the operand whose symbol id gives the higher hash goes first: about `id<<5` for user symbols and `id<<6` for temps. Declaration order and temp numbering therefore matter.
   - Integer `a-b` is canonicalized as `a+(-b)`, and add/mul/and/or/xor chains are flattened, sorted and re-emitted left-deep. Parenthesization and operand order of these ops are largely irrelevant.
5. **Temporaries and direct expressions.**
   - A `t = e; v = t` copy is coalesced.
   - A single-def/single-last-use temp is forward-substituted only within the same innermost loop, when its def dominates the use, and with no call or aliased memory access in between.
   - So splitting an expression into a named local usually vanishes, but not across calls, aliasing stores or loop boundaries.
6. **CSE runs in two sweeps.** The final sweep kills everything at a call.
   - Loops of more than `-Loop#` (default 100) blocks get only conservative availability and **no IV or strength-reduction work**.
7. **Induction variables.**
   - The IV, strength-reduction and pointer-conversion pipeline needs a bottom-tested loop (usually produced by inversion) whose only exit is the latch.
   - `a[i]` is turned into pointer IVs, and when two IVs have the same step, one is merged away (the survivor is picked by use count or by being live after the loop).
   - An extra `break` or a second exit disables all of it.

---
## A. Flow graph, block order and loop layout (fg.c side)

### 0x1070592f cfg_rebuild (first /Og pass; also re-run by 0x10743190 and after lowering)
1. `0x10704d75 cfg_reset_single_block`: deletes all block-boundary tuples (kind 0x19), resets arenas 0xc/0xf and creates a one-block graph.
2. `0x10704de1 coalesce_label_runs`: a run of consecutive mergeable labels becomes one label. References are retargeted by 0x1070ff26/0x10705208. "Mergeable" is decided by 0x10704114: label symbol +0x3e bit0 clear, and the class at +0x30 looked up in table 0x10704b6c.
3. `0x10704ea7 remove_dead_labels` (per label, 0x10704144): if the only reference is a `jmp next` (opcode 0x186) just before the label, that jump is deleted. The label is then removed if nothing references it.
4. `0x10704ed6 cfg_build_blocks`: a new block starts at a label (0x1a) or kind 0x18 (exit), and after kinds 0x11 (branch), 0x13 (switch) and 0x17 (entry). Kind-0x14 ops 0x192/0x1a4 (+1) and 0x194/0x196/0x1a5 (-1) keep a nesting counter in block+0x70; this is probably the __try depth (low confidence).
5. `0x10705161 cfg_build_edges`: walks blocks in physical order. For each block it first adds the fall-through edge prev->this, then one edge for every reference to this block's label. A block falls through unless it ends in an unconditional `0x11` (cond==0 and opcode != 0x18b) or in a switch `0x13`. `cfg_add_edge` (0x10704249, fastcall ecx=fn, edx=src, stack=dst) **prepends** the edge to the source's successor list.
6. Switch tables and EH edges are fixed up last (0x107059b7, 0x1074f935).

On the non-/Og path, `0x1070513a -> 0x10705145` does the same build without label merging (g_fg_keep_markers 0x1079bc88 = 1). It then runs DFS, the diagnostics passes, and `0x10704d75`, which tears the graph down again. So **without /Og the block order is the source order**: no RPO rebuild, no loop passes.

### 0x107053de optimize_flow_graph_initial(ctx, 1)
Steps: `insert_prolog_epilog_markers 0x107054a4` (0x1b4 after the entry tuple, 0x1b5 before the exit, plus 0x1b6/0x1b7 under -Zi) → `cfg_remove_unreachable_blocks 0x1070440d` → `cfg_relayout_rpo 0x10712d16` → `cfg_number_blocks 0x1070451b` → `cfg_compute_dominators 0x1070453f` → `optimize_loops_and_layout 0x1070540b(ctx, 1)`.

- `cfg_remove_unreachable_blocks 0x1070440d` runs the DFS and deletes blocks that were not visited. It warns C4702 (level 4) at the first real tuple that is not a branch.
- `0x1070448f cfg_dfs_rpo` is an iterative DFS from the entry block. Successors are visited **in succ-list order, list head first**, so the most recently added edge is visited first. Visited blocks get flag bit0. The finish order is linked through +0x10/+0x14.
- `0x10712d16` rebuilds the physical list in **reverse postorder**, and the exit block is forced last (0x10712d51).
- The edge order decides where each successor lands:
  - Forward `jcc T`: the edge list is [T, fallthrough]. T is explored first, so the fall-through block is placed right after the branch.
  - Backward branch: the edge list is [fallthrough, T].
  - Switch cases keep their physical order.
  - RPO differs from source order when a block is first reached by DFS from a *later* block, for example code reachable only through a backward goto or a retry label. The crimson note also applies: a loop header that dominates a region forces that region before the latch.

### 0x1070540b optimize_loops_and_layout(ctx, allow_inversion)
1. If there is a back edge (`0x107055d7`: a pred whose index is >= the block's index):
   - `cfg_compute_reach_sets 0x1070471c` (block+0x64 = blocks that can reach this block).
   - `cfg_find_loops 0x107047d7`:
     - A natural loop exists when a pred is dominated by the header and has index >= the header's. The latch (loop+0x18) is the back-edge pred with the highest index. The body is collected by `0x107015e3`.
     - Irreducible regions (the header reaches a later pred it does not dominate) become loops flagged bit0. Every block in the physical range gets the loop pointer.
     - Preheader (new label + block before the header, non-back-edge preds redirected): always created when `arg2`. Otherwise only when the previous physical block belongs to a different loop, or when some non-back-edge pred *jumps* to the header.
2. `compact_loops_recursive 0x1070560f -> compact_loop_body 0x10743b90` (inner loops first; loops with flag bit3 are skipped). Walking header..latch in physical order, each maximal run of non-member blocks is unlinked and re-inserted **after the latch**, before the first later block with a higher index. `cfg_link_block_after 0x10710e7c` relinks the blocks:
   - `cfg_repair_fallthrough 0x1071dc8f` adds a `jmp old_next` block when fall-through was lost.
   - If that jump would leave the loop, `invert_branch_over_jump 0x1071105c` turns `jcc T; jmp F` into `jncc F; jmp T`. This gives the known "jge exit; jmp head" shape of do-while latches.
   - If a body is still scattered (`0x10744753`), dominators and loops are recomputed and compaction runs again.
3. `make_distinct_outer_latches 0x10743cb6`: when an inner loop ends at or after the outer latch, a new outer latch block holding the back jump is split off.
4. When `allow_inversion` is set: `invert_loops_recursive 0x10712d99 -> invert_loop 0x107447ad`.
5. `simplify_flow_graph 0x10705641`. Loop headers are never touched. Per block it tries, in order:
   - Delete a branch or switch whose every edge goes to the next block (`0x1070573c`).
   - Invert `jcc L1; jmp L2; L1:` into `jncc L2` (`0x1070577f`). This is not done when the jmp block is a loop latch or pinned (flag 8), or when both jumps target the same label.
   - Collapse blocks that hold only labels and markers (`0x10705845`).
   - Delete an unreferenced label (`0x10704144`).
   - Delete an empty block, or merge a block whose single successor is the next block, when that block is only entered from it (`0x1070535d`).
6. `set_loop_depths 0x10743d22` (block+0x6e = depth; exit lists at loop+0x20).
7. `create_preheaders_recursive 0x10743dc5 -> 0x10743df7`: an empty previous block that belongs to the parent loop is reused as the preheader. Otherwise a new empty block is inserted. loop+0x10 = preheader and block flag 0x8000000 is set.
8. When `allow_inversion` is set, unreachable blocks are removed again. If anything changed, the blocks are renumbered and dominators rebuilt.

`0x10706210 cfg_reanalyze(ctx, dup)` is the same pipeline **without** the RPO rebuild and without inversion (`0x1070540b(ctx,0)`). It is used by the globopt re-build (`0x10743190`) and after lowering. With `dup`, parallel duplicate edges are also removed (`0x107276eb`).

### 0x107447ad invert_loop (loop rotation)
Conditions:
- g_loop_inversion_enabled (0x107ac08c) is set. 0x1071bc73 sets it for every function; it is cleared only for -ehopt functions whose symbol has flag +0x73 bit8.
- The loop is not irreducible.
- The header's last tuple is a conditional branch (kind 0x11, cond != 0 or opcode 0x18b) that is not pinned (+9 bit3).
- The branch target is outside the loop, and it is either at top level or directly in the parent loop.
- The latch ends in an unconditional `jmp` that has an edge to the header.
- The header has no kind-0x15 tuple and no kind-0x12 op 0xde (`0x10744ae2`).

Transformation:
- The *entire* header block (everything before the test, not just the compare) is spliced into the preceding block/preheader. The header becomes a bare label.
- A clone (`0x10714605`) of the test replaces the latch's `jmp`. The clone's condition is inverted and it branches to the old header label. If the latch had other code, the clone goes into its own new block.
- A new block `jmp exit` follows the bottom test.
- All other back edges into the header (`continue`) are redirected to the bottom test.
- There is **no size limit** on the duplicated header.

### Other early passes
- `0x10718eaf compute_alias_classes`: computes alias classes for symbols and fields and a points-to solution per block. The /Oa-only refinements are 0x1074df1d and 0x1074e18f. `0x107190b8` counts real tuples: **> 10000 (0x2710) disables /Oa for the function** and switches to the coarse fallback 0x1078b887. The field-class budget (0x1071afd0, 0x400 ids) is described in crimson's `tools/match/evidence/spawn-exact-2026-09-13`.
- `0x10712b1a eliminate_tail_recursion` (only with /Og):
  - Walks back from the exit block through label-only/jmp-only blocks (`0x10712ca3`).
  - A block qualifies when it ends in a call to the current function. The call may be followed by `tmp = call; ret tmp`, where the returned temp (class 3) is the call's result, and by a trailing jmp.
  - `0x1076a023` rewrites it: the arguments go through new temps into the parameters, then a jump goes to the entry.
  - Blocked by: ctx+4 set, ctx+0x34 bit 0x40, an EH frame without -EH, symbol flag 0x1000, or address-taken/aggregate parameters (the checks inside 0x1076a023).
- `0x1070448f` (as a pass), `0x10712dcb`, `0x10712f4e`, `0x10712faa` are diagnostics only:
  - DFS reachability.
  - Constant-branch dead-edge marking (edge bit0), so that `while(1)` does not trigger warnings.
  - C4715/C4716.
  - C4700/C4701 reaching-definitions.
  - They do not change the code (0x10712dcb only sets flags).

### Matching implications (A)
- **/Og decides layout:** without it, blocks stay in source order and there is no loop rotation.
- **RPO layout:** with /Og, physical order is the RPO of a DFS that explores the *later-created* edge first. Source order survives for structured if/else/switch. Blocks reached only from later code, such as backward gotos or retry labels, move up behind the block from which DFS first reaches them.
- **`while` and `for` become the same code:** any top-tested `while`/`for` whose test ends the header block is rotated to `test; jcc exit` in the preheader, the body, then `jncc body; jmp exit`. `do { } while` has no exit test in the header and is not rotated. Put side-effecting code in the condition (`while ((c=*p++))`) and that code is duplicated at the bottom.
- **`continue` targets the bottom test copy after rotation;** `break` targets the exit.
- **Rarely executed code leaves the loop:** `if` bodies inside a loop that leave it (`return`, `break` to shared code, `goto` out) are moved by compaction to after the latch. Their fall-through is repaired with a `jmp` and, where needed, the branch is inverted. So `if (x) { return; }` inside a loop becomes a forward `jcc` to code placed after the loop.
- **Nested latch sharing:** nested loops ending at the same point (e.g. `for(..){ for(..){ } }` with no statement after the inner loop) get a separate outer latch block.
- **Branch polarity:** jump-to-next removal and `jcc`-over-`jmp` inversion mean the emitted polarity depends on which arm is physically next, not on how the source condition is written.
- **Self tail calls become jumps** under /Og, unless the function has EH, address-taken parameters, etc.
- **Functions with more than 10000 IL tuples** get /Oa-free, coarse aliasing, which gives more conservative code in huge functions.


## Part B: expression tree pass (optimize.c simplifier, cost/sort, temp purge)

This covers the pass driver calls `0x1070fc45(ctx,1)` (before globopt) and `0x1070fc45(ctx,2)` (after globopt), and `0x1070fcda` (purge, called twice). Addresses are VAs. I read all of this from HLIL and disassembly, and did no dynamic verification.

### Data model used by this pass
- The tuple list is linear, and expression trees are implicit. A src operand of kind 1 or 2 (temp/symbol) whose `symbol+0x14` points to a defining tuple is a forward-substitutable subtree.
- Memory operands (kinds 5/6) carry trees in their base (+0x28) and index (+0x2c).
- `tuple+0x12` is 1 for a materialized root and 2 for a substitutable subtree.
- Tuples detached during simplification reuse `+0x0c` to hold the packed cost.
- IL opcodes decoded from the simplifier tables:
  - `0x15f` conv, `0x160` NOT, `0x161` NEG.
  - `0x16d` add, `0x16e` sub, `0x16f` mul.
  - `0x171` shl (likely), `0x177` shr.
  - `0x172` and, `0x173` or, `0x174` xor. Confirmed by the identity/absorbing constant tables at 0x1070ef52 and 0x1070f037.
  - `0x175` div, `0x176` mod (likely).
  - `0x17d` compare, `0x185` conditional branch, `0x18f` select/boolean value (low confidence).

### 0x1070fc45 optimize_expression_trees(ctx, mode) (high confidence)
- Walks every tuple. It sets `g_cur_line` (0x107ac360) to `tuple+0x10` when that is nonzero, and `g_current_line_abs` (0x107ac354) to `ctx+0x24 + line`. These are used for warnings only.
- Dispatches on tuple kind (table 0x1070fe40):
  - Kinds 0xc/0xd/0xe/0x10/0x12/0x14: skipped if the dst is a temp/symbol that has a def tree (it is simplified from its use). Otherwise processed.
  - Kinds 0xf/0x11/0x13 (branch-like): always processed.
  - Kinds 0x15-0x1b: ignored.
- **mode** (`g_expr_pass_mode` 0x1079f1ac) is only read by `fold_float_constants` 0x10708733. It emits C4756 "overflow in constant arithmetic" only in mode 2, once per tuple (0x107ae238). So runs 1 and 2 are the same algorithm; they differ only in their input (post-globopt IL).
- `0x10710fef resimplify_tuple` is the same per-tuple body. Global forward propagation `0x10711afa` and the globlopt code re-run it after substituting. The pre-lowering pass `0x1072906a` also reaches `0x1070bb78`, through 0x1072d139.

### 0x1070bb78 simplify_tuple_tree -> 0x1070bc39 -> 0x1070bf4c -> 0x1070bbb7
- **Root selection:**
  - `0x16c`: only the address subtree of the first src operand.
  - `0x185`: the condition's def tree. `g_simplify_context_tuple` (0x1079f1a4) is set to the branch so compare folding can read its condition code (the reverse table is at 0x107a01fc).
  - `0x1ab`: recurses into the `0x1ac` tuple of its sublist.
  - `g_simplify_insert_before` (0x1079f1a0) is set to the next tuple; re-emitted tuples go before it.
- **`0x1070bc39` prepare:**
  - Tuple kinds 0xd-0xf and 0x11-0x14 are forced roots (+0x12=1). Their operand subtrees are simplified independently; the root operator itself is never algebraically simplified.
  - Kinds 0xc/0x10 go through `0x1070bd4e`. Substitutable roots then go through `0x1070be21` and `0x1070bf4c`.
- **`0x1070bd4e decide_tree_substitution(def, use)`** keeps a def as a separate statement (returns 1, or sets +0x12=1) when:
  - it has side effects (`0x10702f99`: volatile flags, opcode 0x19e, side-effect machine ops, intrinsic table 0x1079bdc4, 0x1a8 under EH); or
  - its kind is 0x12; or
  - its dst is a class-3 temp whose piece mismatches its symbol (0x1070fa4c); or
  - its type class is 0x5000 (aggregate) or it has multiple dsts; or
  - the dst is a piece symbol that has a def and the use is wider than the piece; or
  - **its opcode is 0x15b (copy), 0x162 (x87 round marker), 0x178 or 0x190 (intrinsic)** (table 0x1070e648).

  `g_disable_tree_substitution` (0x107ae234) is never written, so it is always 0. Copies (0x15b) are not substituted here; they are propagated later by `0x10743352` inside `0x1070d234`.

### 0x1070bf4c simplify_expression_tree (optimize.c fixed point) (high confidence)
1. Swaps the root dst for a fresh temp.
2. **`0x1070c148 build_nary_expression_tree`**:
   - Recursively substitutes single-def temps whose defs are substitutable. If the use type differs, it inserts `0x15f` (except for a 0x17d child).
   - **Rewrites integer `a-b` as `a+NEG(b)`.** Float and 0x4000-class subtraction are left alone.
   - **Flattens a child with the same commutative opcode into its parent** (`0x107016e1`). The child's operands are appended in source order. So `(a+b)+c`, `a+(b+c)` and `a-(-b)+c` all become `add(a,b,c)`.
3. Loop A (at most 100 iterations; otherwise ICE optimize.c line 0x1c9): `0x1070c2d5(tree,0,0)` then `0x1070d234`, until `g_simplify_changed` (0x1079f1a8) stays 0 or the tree collapses to a leaf.
   - `0x1070c2d5` works bottom-up: it calls `0x1070c389 simplify_node_algebraic` then `0x1070cff9 fold_constant_operands`.
   - For `0x17d` compares it also calls `0x1070d47f factor_common_terms` and `0x1070d7dd`.
4. Loop B (line 0x1dc): `0x1070c2d5(tree,0,1)`, with factoring enabled on every node and `0x1071e6ba` pushing narrowing conversions into operators.
5. Loop C (line 0x1ee): `0x1070cfaf`, which runs `0x1070dce4` (widening conversion pushdown, e.g. `(int)(s1+s2)` becomes `(int)s1+(int)s2`, never producing 16-bit ops), then `0x1070df28`, `0x1070c389` and `0x1070cff9`.
6. `0x1070df74 rebuild_subtractions`: an add with negatable terms becomes 0x16e. `0x1070f721` negates constants when the negated value is smaller unsigned, e.g. `x + 0xFFFFFFFF` becomes `x - 1`. If the first term is negated, the first non-negated term is moved to the front (`-a+b` becomes `b-a`).
7. A leaf result becomes an `0x15b` copy (`x = y*1` becomes `x = y`). Otherwise the temp is released and the original dst restored.

#### Algebraic rules in 0x1070c389 (medium confidence; each rule sets g_simplify_changed)
- **Identity and absorbing constants** (0x1070ef52 / 0x1070f037):
  - Identity: `+0`, `-0`, `<<0`, `|0`, `^0`, `>>0`, `*1`, `/1`, `&~0` are removed.
  - Absorbing: `*0` and `&0` become 0; `|~0` becomes ~0.
  - Floats use the 80-bit constants 0.0 (0x10799440) and 1.0 (0x10799450) with an exact compare.
- A nested same commutative op with the same type is flattened again.
- add: `x + NEG(x)` becomes 0 (`0x1070e8ba` tree compare), and `&a + NEG(&b)` for the same base becomes a constant difference.
- sub: `x-x` becomes 0, `x-0` becomes x, and `&a-&b` becomes a constant.
- NOT: `~~x` becomes x, and `~NEG(x)` becomes `x + (-1)`.
- NEG is pushed into its operand (`0x1070f721`, level 3).
- xor: `x ^ -1` becomes NOT.
- **div (0x175):**
  - float `x/c` with nonzero constant c becomes `x*(1/c)` when **/Op is off** (0x107ac0a4).
  - int `x/2^k` becomes shr `0x177` when the type is unsigned or `0x1075a3a9 is_known_nonnegative(x)`.
- mod (0x176): `x%1` becomes 0; unsigned `x%2^k` becomes `x&(2^k-1)`.
- Shift chains: `(x>>a)>>b` becomes `x>>(a+b)`.
- mul/shl interplay: a mul containing shl is merged (`0x1074cf39` / `0x1076a24e`). NEG operands are hoisted out of a mul.
- Compare/select (0x17d with 0x18f): conditions are folded using the enclosing branch polarity. **Low confidence** on the details.

#### 0x1070cff9 fold_constant_operands
- In a commutative int node, all int constants are folded pairwise (`0x1070693c`, 64-bit, normalized to the type). Float constants are folded through `0x10708733`.
- **`&sym + c` becomes a direct symbol piece** (`0x10703ba0`) when not -dlp (0x107ac12c) and `0 <= off+c < sizeof(sym)` (or the symbol is an aggregate). Unary nodes with constant operands are folded too.

#### 0x1070d234 distribute_and_propagate
- A temp defined by an `0x15b` copy is replaced by its source (`0x10743352`). This includes turning a `&x` base into a direct symbol reference, if the size and offset are in bounds.
- **Distribution by a constant** (`0x10710053`, table 0x1070e798):
  - mul over add: `(a+b)*c` becomes `a*c+b*c`.
  - shl over add.
  - and over or/xor, and or over and.
  - shr over and/or/xor.
  - NEG over add: `-(a+b)` becomes `-a + -b`.
  - `0x15f` goes through `0x1071e2c5 simplify_conversion`.
- **Implication:** `p[i+1]`, `*(p+i+1)` and `(i+1)*4 + base` all become `i*4 + (base+4)`, and the constant is then absorbed into the displacement.

#### 0x1070d47f factor_common_terms (factor.c-like; low-medium confidence)
- Reverses distribution: `a*c+b*c` becomes `(a+b)*c` (`0x1070f0c7` / `0x1074a914`), with common and/or/xor terms factored the same way.
- `0x1070f3c7` rewrites the bitfield-insert idiom `(a&m)|(b&~m)` as `((a^b)&m)^b`.
- Compare with shifted or masked operands is rewritten as an and-mask compare.
- It runs only in loop B, or on 0x17d nodes in loop A. Distribution and factoring can therefore undo each other; the loop converges because of the per-stage 100-iteration limit and the change flags.

### Cost and ordering: 0x1070d90c / 0x1070da9a / 0x1070db59 / 0x1070e114 (high confidence; confirms and refines the snail-mail notes)
- **Packed cost at +0x0c** = `need<<24 | size<<16 | hash16`.
  - Leaf: size 1 (0 for constants of kinds 7-9), need 0.
  - Node:
    - size = 1 + the sum of the children's sizes.
    - need starts at child0's need. For each later child c: if c > need, need = c+1; if c == need, need += 1. **This depends on operand order**, and it is computed after sorting for commutative nodes.
    - Adds +7 for call kind 0xe and +5 for kind 0x12.
  - An operand that is a substituted temp, or a memory operand whose base or index is substituted, takes the cost of that def tree.
- **Sort:** only for commutative opcodes {0x16d, 0x16f, 0x172, 0x173, 0x174, 0x17e, 0x17f} (0x107062ef). It is a stable bottom-up merge sort (0x1070f584 / 0x1070f65c) in **unsigned descending** order (0x1070f6ae). The effective keys are need, then size, then hash. **Ties keep flattened source order.** Constants always sort last.
- **hash16** (0x1070db59, dispatched by operand kind through tables 0x1070e800 / 0x1070e7e0):
  - User symbol or param (kind 1/2): about `id<<5` for ids below 0x800. **The higher symbol id comes first** among equal-cost leaves.
  - Class-3 compiler temp: `id<<6`.
  - Substituted temp: the hash of its def tree.
  - `&sym` (kind 3): the folded id, unshifted.
  - Memory: `fold(disp) + (addrform-0x145) + hash(base)<<8`.
  - Constant: a fold of its value.
  - Tuple: `sum(child_hash << (i&7)) + opcode-0x145`.
- **Emission** (0x1070e114): each n-ary node becomes a **left-deep chain in sorted order**, `((x0 op x1) op x2) op x3`, and each step gets a fresh temp from `0x10702add`.
  - For "reorderable" binary ops (0x1070e560: 0x16d-0x16f, 0x171-0x178, 0x17d-0x183), when the second operand costs more than the first and the type is **not float**, the second operand's subtree is emitted first; operand order itself is kept (Sethi-Ullman evaluation order).
  - The operand lists of call-kind tuples 0xe/0x12 are reversed during emission, so argument trees are evaluated right to left.
  - `0x15f` over a temp or memory operand is folded into a narrower load (0x10710180).

### 0x1070fcda purge_unreferenced_temps (high confidence)
- `0x1070fd5a` sets `symbol+6 |= 2` for every referenced symbol, memory base/index and sublist.
- Every class-3 temp chain (entry with `head==self`) where no piece is marked is released through `0x10706247`. That function pushes it onto `g_temp_symbol_free` (0x1079bc60); the flags are cleared again for the next run.
- `0x107017eb symbol_alloc(3)` pops from that list first and keeps the old id. **Temp ids are therefore recycled LIFO.** Because temp hashes are `id<<6`, which temps are freed, and in what order, can change the sort order of equal-cost temp operands later on.

### Matching implications (source rewrites that do or do not change output)
- **No effect** on integer expressions:
  - Parenthesization of `+ * & | ^`, and `a-b` versus `a+(-b)`, versus `-b+a` (these become `a-b` again).
  - Constant placement (`4+i` versus `i+4`).
  - Splitting an expression through single-use temps (`t=a+b; x=t*c;`), when t is a compiler temp or a single-def expression owner.
- **Does matter:** a **named local that is a real variable** (its dst is not a substitutable temp) or a plain copy (`t = a`, 0x15b). A copy is never tree-substituted here; it only goes through the copy-propagation rules (`0x10743352`, and globopt `0x10711afa`).
- **Operand order of `a+b`, where both are simple locals, params or globals, is decided by symbol id (higher id first)**, not by source order. Reordering declarations, or anything else that changes symbol numbering, flips the order. Source order only breaks exact hash ties, which is rare.
- Deeper subtrees come before leaves, and memory operands with computed addresses carry their address tree's cost. So `x + p->f` versus `x + y` sort differently. Among equal-cost subtrees, the tree hash (opcodes and symbol ids) decides.
- For non-commutative int ops (sub, div, shift, compare), the costlier operand is **evaluated** first, but operand order is kept. Floats are always evaluated left to right. That is why swapping `a-b` to `-(b-a)` in float code changes the output, but not in int code.
- Float `x / c` becomes `x * (1/c)` (no /Op). Writing `x*0.5f` versus `x/2.0f` gives the same code, while `x/3.0f` versus `x*(1/3.0f)` may differ in the rounding of the constant. **Int** `x/2^k` becomes a shift only for unsigned or provably nonnegative operands; signed values keep the idiv or sar sequence produced later.
- `(i+1)*k` versus `i*k+k`: the same code after distribution. Address constants fold into `&sym` pieces within object bounds.
- `(int)(short+short)` is widened before the add, and 16-bit ops are avoided.
- Bitfield assignments produce the xor/and/xor idiom through `0x1070f3c7`, whatever the source shape.
- Call arguments are evaluated last to first. The temp numbering this produces feeds later tie-breaks.
- The pass-1 versus pass-2 difference is diagnostics only (C4756); any codegen difference comes from globopt rewriting the IL in between.

### Uncertainties
- The exact semantics of 0x170, 0x178 and 0x179-0x17c (0x179/0x17a and 0x17b/0x17c are inverse pairs per 0x10753f2e, possibly inc/dec-style ops).
- The compare/select folding in 0x1070c389 case 0xd, and the 0x18f handlers 0x107501c1 / 0x107502d2, were only skimmed.
- The factoring helpers (0x1070f0c7, 0x1071e998, 0x1071ea54, 0x1074a914) were only skimmed.
- 0x1070fa4c semantics.
- Whether kind 0x12 is an intrinsic call.


## Part C1: global optimizer driver 0x107130cb and its non-loop sub-passes

The source is HLIL from the read-only database. Confidence levels are given inline. The loop passes (0x10743ead, 0x1070aad7 as a loop solver, 0x10744003/0x10744042/0x107444e2/0x107446bc/0x107450d7/0x10743f40) are covered in the loop optimization section.

### Driver `globopt_run` 0x107130cb (globopt.c), phase by phase

Setup:
- `globopt_init_expr_tables` 0x10713735: resets arena 0xe, clears the 101-bucket expression hash 0x1079947c and allocates per-alias-class kill sets. The alias class count is 0x107adfd8, produced by 0x10718eaf.
- `globopt_reset_symbol_state` 0x107138d0.
- `globopt_fold_all_blocks` 0x1071395c runs `simplify_tuple` 0x107081d7 on every assignment tuple.

**Phase 0** (`g_globopt_phase` 0x1079f114 = 0). It canonicalizes, coalesces, propagates and removes dead code.
1. `globopt_canonicalize_tuples` 0x10713989:
   - A memory displacement becomes an explicit address computation (0x15d).
   - A block copy (0x16b) of 1, 2 or 4 bytes becomes a scalar assign (0x15b).
   - Every non-assign computation whose destination is a class-3 symbol gets a **fresh single-def temp**. The temp's symbol +0x14 points at the defining tuple, which is the "def-tree" form, and a copy `dst = temp` follows (tuple flag +9 |= 0x40).
   - Records the def list (+0x4c), use list (+0x50) and copy partners (+0x48) of each temp. Collects the variables assigned by 0x15b into `g_fwdprop_candidate_syms` 0x1079f0f4.
2. `coalesce_temp_copies` 0x107117d0: `t = e; v = t` becomes `v = e` when all of these hold:
   - t has exactly one use and that use is the copy.
   - v is a plain variable (kind 2, not a def-tree temp) with no side effects.
   - Every def of t reaches the copy in straight-line code (0x10748f93).
   - v and the copy's source are not referenced between the def and the copy (0x10748ffc).
   - The types are compatible (0x10703278), including the sign/size rules at 0x10711970.

   It then removes the canonicalization copies that turned out to be useless.
3. `alloc_block_dataflow_sets`(1) 0x1070789c, then `globopt_dead_code_elim` 0x10706bd0 (see DCE below).
4. `forward_propagate_definitions` 0x10711afa (see forward propagation below).
5. If `g_flowgraph_dirty` 0x1079f0e0 is set, `rebuild_flow_graph` 0x10743190 runs. Then data-flow sets are allocated with (5) and DCE runs again.
6. If loops exist (fn+0x0c non-null), the loop set-up passes run: 0x10744003, 0x10744042, 0x107444e2, 0x10744003.
7. `assign_expression_owners` 0x10711209 does value numbering (see value numbering below).
8. `insert_branch_value_facts` 0x1071072b.

**Phase 1** is the first CSE sweep. Flags: `g_cse_full_mode` 0x1079f0e8 = 0, 0x1079f0fc = 0, 0x1079f118 = 1, 0x1079f120 = 1, `g_jump_threading_enabled` 0x1079f104 = 1.
- Blocks are visited in physical (RPO) order. At a loop header, a conservative "available on entry" set is built: the header's +4 block's avail-out, restricted to 0x15b/relational expressions whose symbol operands are not in the loop's modified set (+0x34). That set is ORed into the avail-out of the header's predecessors.
- Then `cse_block` 0x10708f28 runs on each block.

The iterative path (`solve_avail_dataflow_range` 0x1070aad7) needs full mode, so phase 1 never takes it.

**Between phases 1 and 2:**
- `delete_status1_fact_tuples` 0x1070a547 removes the branch facts.
- The flow graph is rebuilt if dirty, and DCE runs.
- If there are loops: `g_need_extra_dce` 0x1079f10c = 1, `globopt_restore_temp_destinations` 0x107061c8, then the loop passes again plus 0x107446bc.
- The facts are reinserted, and 0x1070aad7 runs over the whole function.

**Phase 2** (= 2): `globopt_loop_phase_init` 0x10710c43, then 0x107450d7 on each loop. This is loop-invariant motion and strength reduction, see the loop optimization section. `globopt_loop_phase_free` 0x1070b4f8 cleans up.

**Phase 3** (= 3):
- `insert_branch_value_facts_late` 0x1070b571 inserts status-2 facts.
- `lower_copy_intrinsics` 0x1070b471 handles the 0x1ab/0x1ac markers.
- The whole function is solved again.
- The second CSE sweep runs with `g_cse_full_mode` = 1 and jump threading on. At a loop header it uses the **iterative loop dataflow only when (tail RPO - head RPO + 1) <= `-Loop#`** (0x107ae1e0, default **100**, comment at 0x10713537). Otherwise it uses the conservative entry set.
- 0x10743f40 runs at each loop tail.

**Cleanup:**
- The graph is rebuilt, and the status-1 and status-2 facts are deleted.
- The sets are reallocated and DCE runs. If `g_need_extra_dce` is set, DCE runs twice.
- `globopt_restore_temp_destinations` 0x107061c8.
- `globopt_fold_adjacent_copies` 0x10726654.
- `globopt_finalize_tuples` 0x107266ff: 0x169 becomes 0x15b, `x = x` is deleted, aggregate assigns go back to 0x16b, and constant operand types are normalized.
- `globopt_free_expr_tables` 0x10726aa7.

### Dead code / liveness `globopt_dead_code_elim` 0x10706bd0 → 0x10706bf3 → `liveness_transfer_tuple` 0x10706feb (globdf.c)

It is one backward pass over the blocks in reverse physical order:
- Block live-out is the union of the successors' live-in (+0x2c into +0x30). The per-tuple transfer runs backwards.
- Loops are handled by seeding at back edges (`block_has_back_edge` 0x10706fa6, which compares the RPO index at +0x6c).

An assignment is deleted when **its destination (or any overlapping field of the same aggregate) is not live and it has no side effects** (`node_has_side_effects` 0x10702f99).
- A self-assignment `x = x` is also deleted (0x107034bc returns 0 when the operands are equal).
- A store to memory is deleted if a later store in the same straight line hits the same location with no read in between. This uses the pending-store list 0x1079f0a4 and 0x107436a0.
- A dead destination with a side-effecting source keeps the computation and swaps in a fresh temp (0x107072b5).

It also marks the **last use of each operand** (+0x11 |= 0x10). Forward propagation depends on that mark. Symbols that partially overlap their aggregate (0x10706ef8) are always treated as live. If a block's last assignment is removed, the flow graph is marked dirty.

### Forward substitution `forward_propagate_definitions` 0x10711afa

For each candidate variable (assigned by 0x15b, symbol flag +0x32 bit 3) it tracks reaching defs (+0x4c) and uses (+0x50) as it walks the blocks in RPO. Cross-block state goes through block +0x74/+0x78. A (def, use) pair is registered, and the def gets status 0xa, only when **all** of these hold:
- Exactly one def reaches and there is exactly one use (a second use sets 0xb).
- The use operand matches the def destination (0x1071d500) at the same offset.
- Neither type is aggregate (0x5000).
- A float (0x4000) def or use is rejected under **/Op or -basic** (0x1078ff9f).
- If the types differ, both must be integral-like and **the use must be no wider than the def** (0x10711f82). Narrowing is allowed; widening is not.
- Neither tuple has side effects.
- `propagation_def_use_eligible` 0x10711786: in the same block the def precedes the use. Across blocks, **the def block must dominate the use block (bitset +0x60) and both must be in the same innermost loop (+0x68)**.

These events kill a pending def (status 0xb):
- Any call (kind 0x14 or opcode 0x187) (0x10712164).
- A memory reference through an alias class that contains the variable.
- The variable being live out of the block (live-out set +0x30, 0x107123bb).
- The variable being in the aliased set 0x1079d694 (symbol bit 0x10).
- An overlapping field live into a back-edge successor.

Commit step:
- A pair fires only if the use operand is a last use (+0x11 & 0x10).
- `range_free_of_conflicts` 0x10742ad4 must find no overlapping write or read between the def and the use.
- The def's expression tree is **moved to just before the use** (`move_expression_tree_before` 0x1071d548). The operand is replaced, with a conversion added when the widths differ (0x15f, or 0x162 for float), and the original def is deleted.
- Touched tuples are re-simplified (0x10710fef, and 0x107081d7 for branches).

### Value numbering `assign_expression_owners` 0x10711209 and the expression hash

- Memory operands get their address as an `0x14c(base, disp)` expression.
- Pure computations, meaning no side effects and operands not flagged 0x20, including pure intrinsics (table 0x1079bdc4 bit 0x20), are rewritten to compute into a hashed **expression symbol** through `operand_new_cse_sym` 0x1070817c and `replace_dst_with_expression` 0x10710d69.
- Hash: `(op + (type & 0xfff)) mod 101`, plus each operand's hash mod 101 (0x10707bc0). There are at most 9 operands; 10 or more raises an ICE (0x10707b80).
- Lookup (0x10707c3d) matches opcode, compatible type, and operands in order, **or swapped for commutative ops** (0x107062ef). So `a+b` and `b+a` are the same expression. With -QIfist, 0x15f requires an exact type.
- **Signed int `x - c` is rewritten to `x + (-c)`** (0x1071158f).
- Assignments get ids through `number_assignment` 0x10708c14. Each id is added to the source's and destination's kill sets (+0x44). A copy `x = y` is also recorded in x's +0x3c list, which feeds copy propagation.

### CSE `cse_block` 0x10708f28 / `cse_tuple` 0x10709690

- avail-in is the AND of the predecessors' avail-out (+0x54). Blocks with flag 0x2000000 are skipped.
- `avail_transfer_tuple` 0x1070a0d8 handles kills:
  - Writing a symbol kills its +0x44 expressions and those of overlapping fields.
  - A memory write or a class-7/8 symbol kills the alias-class sets.
  - **A call kills the temp-sourced expressions (0x10799618) in phase 1, and everything in full mode.**
- In **phase 1** each tuple gets:
  - Operand replacement (`cse_replace_operands` 0x107098ea / `find_available_copy_source` 0x10709b5a): a use of x becomes y if `x = y` is available. A constant is not propagated if it is a double (float wider than 4 bytes) or an aggregate. Temp-to-temp copies are gated by 0x1079f118.
  - Folding (0x107081d7).
- In **full mode (phase 3)** it also:
  - deletes an assignment whose expression is already available, unless the tuple is status 3 "materialize";
  - deletes `*p = t` when t was loaded from `*p` and is still available (0x1070a479);
  - folds conditional branches whose compare is known from the available facts (`evaluate_compare_from_available` 0x1070b9da → 0x1074c282).
- Jump threading (`thread_jumps_at_block_end` 0x10708fa7, low confidence) follows chains of trivial blocks for **up to 10 hops** (0x1070968c). **Threading through a fall-through successor happens only with /Ot** (0x10709064).

### Branch facts

- `insert_branch_value_facts` 0x1071072b → 0x10710779: after an equality compare (0x17d), or in a switch (0x18d) case with lo == hi, it inserts `x = const` tuples (status 1) in the implied successor. CSE then turns later uses of x in that region into the constant. The fact tuples are removed by 0x1070a547.
- The phase-3 variant 0x1070b571/0x1070b0e5 uses status 2, removed by 0x1070b9ab.

### Other

- `globopt_restore_temp_destinations` 0x107061c8 → 0x10705b30/0x10705c00: a class-3 destination that is copied only once into a surviving local is renamed back to a fresh temp. This matches the crimson observation that expression owners get restored to temps.
- `globopt_fold_adjacent_copies` 0x10726654: `t = e` immediately followed by `x = t` (next real tuple) becomes `x = e`. Handled by 0x10726b1b and 0x10726bfe.
- 0x10712f4e, outside my scope: it is gated by `-nowarn4715` (0x107ae254), so it is the "not all control paths return a value" check (C4715).

### Matching implications (source rewrites that flip decisions)

1. **A temp local versus a direct expression** gives identical code when forward substitution fires: one def, one use at the last use, dominating, same loop, no call or aliased memory access in between, not float under /Op, and not widening. It breaks, keeping the store to the local, when:
   - a call sits between the def and the use;
   - the local is used twice;
   - the use is in a different loop nest level (for example, hoisting `t = f(x)` out of a loop and using it inside keeps it);
   - the local is float and /Op is on;
   - the local is narrower than the use (for example, a `short t` used as an int);
   - the local's address is taken.
2. **Statement order:** the def tree is moved to the use point, so for single-use temps the order in the source does not matter. Re-using a local, or an intervening call, pins the original order.
3. **`t = expr; var = t;`** always collapses to `var = expr` (0x107117d0) when nothing between them references `var`.
4. **Commutative operands:** `a+b` and `b+a` are CSE'd together. Which one is emitted first is decided elsewhere (the cost sort 0x1070d90c).
5. **`x - 5`** is internally `x + (-5)` for signed ints. It is value-numbered identically to `x + (-5)`, not to `5 - x`.
6. **Calls kill CSE:** in the final sweep a call invalidates every available expression, so recomputing `p->a + 1` after a call is not reused. Caching it in a local before the call is still subject to rule 1.
7. **Inside `if (x == C)` or `case C:`**, uses of x may become the literal C (branch facts).
8. **Loops larger than 100 blocks** (-Loop#) get only conservative CSE availability at their headers.
9. **Dead stores** are removed only when the variable (and every overlapping field) is dead and the store has no side effects. A store to memory is removed only if it is overwritten later in the same block with no read in between.
10. **Jump threading through fall-throughs is /Ot-only**, so /Os and /Ot can produce different branch layouts.

### Uncertainty

- The meaning of symbol class byte 3 (temp versus user local) is unresolved, so the "call kills temp-sourced expressions" rule is described structurally.
- The exact roles of 0x1079f118, 0x1079f120 and 0x1079f0fc are only partly understood.
- The internals of `thread_jumps_at_block_end` 0x10708fa7 and `simplify_tuple` 0x107081d7 were only skimmed.
- The 0x1ab/0x1ac marker semantics (lowered by 0x1070b471) are unknown.
- The aliased-set meaning of 0x1079d694 is inferred from how it is used.


## C2 loop optimizations inside global_optimize (0x107130cb), globlopt.c

Scope: loop-invariant code motion, reassociation, induction variables (IVs), strength reduction (SR), exit-test replacement (LFTR), count-down conversion, trip count, empty-loop deletion. All addresses are VAs. Confidence is noted per claim; "low" means structure seen, semantics inferred.

### Loop structure (from detect_natural_loops 0x107047d7, ensure_loop_preheader 0x10743df7)

- `ctx+0xc` holds the loop tree. Loop record is 0x40 bytes:
  - +0 sibling, +4 first child, +8 parent
  - +0xc block before the preheader, +0x10 preheader, +0x14 header
  - +0x18 latch: the highest-numbered in-loop block with a back edge. Loop blocks are header..latch in physical order.
  - +0x20 exit blocks, +0x24 flags, +0x28 trip count, +0x2c exit compare, +0x34 invariant-symbol set
- Block fields:
  - +0x68 innermost loop, +0x6c physical number (0x1070451b), +0x6e depth
  - +0x60 dominators (0x1070453f, intersection over preds)
  - +0x64 transient reach set (0x1070471c)
- Loop size, used by every threshold below, is `latch.num - header.num + 1` in blocks.
- **`-Loop#` option → `g_loop_opt_max_blocks` 0x107ae1e0, default 100.** The `-loopopt` flag 0x107ac0c0 has no code references (dead).
- `check_loop_optimizable` 0x10743ead sets loop+0x24 bit0 ("don't optimize") in two cases:
  - the latch has no edge to the header;
  - the block physically before the preheader ends in an unconditional `jmp`.
- The detector also sets bit0 for irreducible or multiple-entry regions.

### Where loop code runs inside 0x107130cb

1. **Early.** If loops exist (0x10713181): `clear_invariant_operand_marks` 0x10744003, `compute_loop_invariants` 0x10744042, `reassociate_invariant_adds` 0x107444e2, then clear again. This runs before the value-numbering step 0x10711209.
2. **Phase 1** (`g_globopt_phase`=1, `0x1079f0e8`=0). For each loop header with bit0 clear (0x10713236..0x1071334c):
   - It collects expressions available at the preheader exit (`preheader+0x54`) whose defining tuple is an assign 0x15b or a compare 0x17e..0x183.
   - Operand check uses table 0x10714208 by operand kind:
     - kinds 1/2: the symbol must be in loop+0x34 (not killed in the loop);
     - kinds 3/4/5/7/8/9: always OK;
     - kind 6 (indirect memory through a pointer): rejects the candidate.
   - Qualifying expressions are ORed into the OUT set of every header predecessor, including the latch. Availability then says the expression is valid throughout the loop, so in-loop recomputations are CSE'd against the pre-loop value. This is invariant motion by availability, not by moving code.
   - Then `0x10708f28` runs per block (CSE area, outside this part).
3. Invariant, reassociation and coalescing again: 0x107061c8, 0x10744042, 0x107444e2, then `rehash_after_reassociation` 0x107446bc.
4. **Phase 2.** `init_loop_opt_sets` 0x10710c43, then `optimize_loop_nest` 0x107450d7 for each top-level loop.
5. **Phase 3.** The same header walk as phase 1, but with `0x1079f0e8`=1. Loops of ≤ -Loop# blocks get exact loop-local availability (`solve_available_expressions` 0x1070aad7 over header..latch). Larger loops get the phase-1 injection.
   - Afterwards `limit_loop_exit_availability` 0x10743f40 runs on latch blocks.

### Invariant analysis: compute_loop_invariants 0x10744042 / mark_loop_invariants 0x107440f9

- Loops are processed inner first. The kill set is not reset between a child and its parent, so outer loops include inner-loop kills.
- **Kill set** (0x1079f0ac) comes from every dst operand in the loop:
  - variable dst: the symbol plus all overlapping fields of the same aggregate (offset/size overlap);
  - indirect store (kind 6) or kind 0xb: the whole alias class of the pointer (0x10703686 list, walked through 0xc sub-lists).
- **loop+0x34** = trackable symbols (0x1079bc80 ∪ 0x1079bc48) minus the kill set.
- **Operand invariant mark** (+0x11 bit7) is set on:
  - constants;
  - variables not killed;
  - memory operands whose base, and whose whole alias class, is unkilled.
- A tuple's result is marked invariant only if all its sources are invariant. This is one forward pass in block order, not iterated, so an invariant chain is recognised only when each definition physically precedes its use.

### Reassociation: reassociate_invariant_adds 0x107444e2

- Rewrites `t1 = a + b; t2 = t1 + c` when c is invariant, exactly one of a/b is invariant, and the variant one is a named variable (kind 2).
- The result is `t1 = inv + c; t2 = t1 + var`. t1 then sinks to just before t2, so t1 can be hoisted.
- Only int `add` 0x16d is handled; tag 0x11 is excluded. `x - c` is canonicalised to `x + (-c)` elsewhere (`enter_tuple_in_expression_table` 0x1070a576), so it also qualifies.

### Hoisting: optimize_loop_nest 0x107450d7, hoist_invariants_in_block 0x10744cd3, try_hoist_invariant_tuple 0x10744e61

- Children are processed first. Skipped if flags & 9.
- For loops of ≤ -Loop# blocks, it first runs:
  - `propagate_temp_copies_in_loop` 0x10748ae3: `t=y; z=t` becomes `z=y`;
  - `recompute_loop_liveness` 0x10745d31.
- `prepare_loop_hoisting_sets` 0x10744b4c computes:
  - loop-local availability;
  - preheader live-out (+0x30) and must-set (+0x3c);
  - the loop live-out symbol set 0x107ae1c8 (live-in of exit successors outside the loop);
  - the loop kill set 0x107ae1bc.
- It then walks blocks header..latch, skipping dead blocks (flag 0x2000000). A tuple is tried for hoisting only if its block dominates every loop exit (`block_dominates_loop_exits` 0x10744e30). Otherwise it goes through normal CSE (0x1070a0d8).
- **Hoist conditions**:
  1. The tuple's value number is available on the loop-local path (`g_cur_block_avail`), and it has no side effects (`node_has_side_effects` 0x10702f99 covers volatile operands, opcode 0x19e and intrinsic attributes).
  2. A store to memory is never hoisted.
  3. Assigning to a named variable is blocked by `hoist_target_live_on_entry` 0x10748c40 in these cases:
     - the variable is live-out of the preheader;
     - an overlapping field is live and the parent aggregate is larger than 0x100 bytes;
     - the byte coverage of the must-set is incomplete.
  4. An add/sub that feeds `x = x op y` (an IV update) is not hoisted.
  5. Every source that is itself an expression temp must already be available at the preheader (0x107ae1cc). Hoisting is transitive only in program order.
- **Placement.** The tuple moves to the preheader end (0x1079f0ec). If its tag is +0x13==3 it is cloned instead of moved. The hoisted value number is added to header IN, preheader-available and hoisted sets.

### IV / SR pipeline: optimize_loop_induction_variables 0x10745d75 (loops of ≤ -Loop# blocks only)

1. **`canonicalize_loop_neg_sub` 0x10745e9a.** Int `-x` becomes `x*-1`. Int `a-b` (b not a constant) becomes `a + b*-1`.
2. **`collect_iv_excluded_symbols` 0x1074609f.** Excluded symbols:
   - anything in the alias class of an indirect access;
   - volatile variables;
   - variables written in an inner-loop block;
   - struct copies (type 0x5000);
   - fields of 8-byte aggregates (0x1008/0x2008);
   - partially overlapping or type-punned fields.
3. **`find_basic_induction_variables` 0x10746521.**
   - Candidates are variables (kind 2) of type class 1..3 assigned by 0x15b or add/sub in blocks directly in this loop. Assign tags 1 and 0xe don't count.
   - Pruning repeats until stable. Every in-loop def must be `iv = iv2` or `iv = iv2 ± inv` (for sub, the IV must be on the left). Any other def, such as a mul or a call result, removes the candidate.
4. **Exit-test analysis: `analyze_loop_exit_test` 0x107468aa.** All of the following must hold:
   - exactly one exit block, and it is the latch (a bottom-tested loop);
   - the header's only preds are the preheader and the latch;
   - the latch branch tests `IV rel invariant`; the operands are swapped (and the condition reversed) if needed.
   - Then `compute_loop_trip_count` 0x10753637 (globlopt.c:4365) requires:
     - exactly one IV update in a block that dominates the latch;
     - a constant step whose sign matches the relation (codes 2..6);
     - the init value found by 0x10753131;
     - all sizes ≤ 4 bytes.
   - A trip count of constant 0 or 1 removes the back edge (0x10743213). Otherwise it is stored in loop+0x28, the compare in loop+0x2c, and a narrow IV (size < 4) is recorded in 0x107ae1f4.
5. If the analysis succeeds:
   - **`strength_reduce_loop` 0x1074775c** (globlopt.c:3305/3346) runs at most 32 rounds (0x10747bbc). Candidates (`collect_iv_candidates` mode 1) are `IV ± inv`, `IV * inv` and IV int conversions (0x15f, size 4).
   - Each candidate becomes `dst = D`, where D = `get_derived_iv` 0x10753def(op, a, b). D is a value-numbered expression symbol, so equal expressions such as two `i*4` share one D.
   - D is initialised at the preheader end. After every update of the base IV, `D = D ± step·inv` is inserted.
   - **`merge_parallel_induction_variables` 0x10746a2f** (mode 4). Two IVs with the same update opcode, step operand, update block and compatible type are merged as `j = i + (init_j - init_i)` (0x10754157 / 0x10754542 / 0x10754627).
     - **Tie-break**: the IV with more in-loop uses, or one that is live after the loop, survives. On equal counts the first-listed IV is eliminated.
   - `remove_dead_iv_code` 0x10747dda runs liveness with dead-store deletion until stable, which removes IV updates that became unused.
   - `convert_loop_stores_to_block_op` 0x10747ed0 (mode 3, low confidence) handles IV-pointer stores/copies and per-iteration memset/memcpy (intrinsic 0xad/0xac) when a trip count exists.
   - **`replace_loop_exit_tests` 0x107482cd → `rewrite_exit_test_with_derived_iv` 0x10752a50** (globlopt.c:3975). `iv rel lim` becomes `D rel f(lim)`; the relation flips for a negative int scale.
   - **`strength_reduce_address_operands` 0x10748429** (globlopt.c:8467):
     - Memory operands `[base+idx<<s+disp]` whose base or index is an IV are rebuilt as an explicit address temp by `materialize_memory_address` 0x107547f2 (globlopt.c:7862), and become `[temp]`.
     - The shift/scale-derived IVs from mode 6 (0x179..0x17b, with a power-of-two check) are also handled here.
   - **`convert_exit_test_to_countdown` 0x107452db.** Applies if the IV's only in-loop use is its exit compare plus its own update. A 32-bit counter (type 0x2004, 0x1074ce51) is initialised to the trip count; the loop does `counter - 1` and tests `!= 0` (op 0x181).
   - **`replace_iv_with_final_value` 0x1074542c.** Applies to an IV used only by its own update (plus the compare). The update leaves the loop and `iv += step * tripcount` is emitted in the preheader.
   - Then 0x10745600, `fold_child_loop_iv_reinit` 0x107456d6 (low confidence), and **`delete_empty_loop` 0x1074572f**. The latter removes a single-block loop that contains only IV bookkeeping and an IV-vs-invariant test, when no IV is live after the loop.
   - Finally `recse_preheader` 0x10708efe and `rewrite_loop_guard_compare` 0x10745921 (low confidence).
6. `finish_loop_iv_optimization` 0x10745b7d clears the sets and symbol fields.

### Matching implications (source rewrites that flip decisions)

- **Loop form matters.** IV, SR, LFTR, count-down and final-value work only on loops whose single exit is the latch.
  - A `for` or `while` loop reaches that shape through loop inversion (0x10712d99). Any `break`, `return` or `goto` out of the body adds an exit, and then only invariant hoisting runs.
  - An exit test in the middle of the loop, such as `for(;;){ if(..) break; ...}`, has the same effect.
- **Loop size.** Loops over 100 blocks (including inlined code, switch arms and `?:`) get no IV/SR at all, and in phase 3 only coarse invariant availability.
- **Index vs pointer.** An `a[i]` memory operand with IV i is turned into an address temp and a pointer IV, as long as i is a clean basic IV. Hand-written pointer loops and index loops can therefore converge, or diverge if either form fails the IV rules:
  - volatile, address-taken or aliased i;
  - i written through a pointer;
  - i modified in an inner loop;
  - i a field of a union or of an 8-byte struct;
  - a mul/call def of i;
  - `i = c - i`.
- **Several IVs with the same step** (`p++` and `i++`) are merged. The survivor is the one with more uses, or the one live after the loop. Adding a use after the loop, or reordering uses, flips which register variable remains.
- **A counter used only for the trip** (`for(i=0;i<n;i++) body-not-using-i`) becomes a down-counting 32-bit counter, `dec` then `jnz`. Using i anywhere in the body prevents that.
- **Shared scaled indexes.** Identical scaled index expressions in one loop (`a[i]`, `b[i]` with the same element size) share one derived IV. Different element sizes create separate derived IVs, which means more registers.
- **Hoisting of `x = inv`.** It needs x not live on loop entry and the defining block to dominate all exits.
  - Assigning x before the loop, or reading x before its assignment in the body, blocks the hoist.
  - Code under an `if` in the body is never hoisted (it does not dominate the exits).
- **Invariant chains.** They are recognised only when definitions precede uses physically. Reordering statements in the body can stop the second link from being hoisted.
- **Stores through pointers.** A store through a pointer anywhere in the loop kills everything in that pointer's alias class. Loads from such memory stay in the loop, while copying into a local before the loop allows hoisting.
- **Add reassociation.** `(var + c1) + c2` and `var + (c1 + c2)` converge only when var is a named variable (kind 2), not a compiler temp. A subexpression that is itself a temp (for example a cast result) is not reassociated.
- **Trip count 0/1.** A constant trip count of 0 or 1 removes the back edge.
- **Single-block empty loops.** A loop with only IV updates and nothing live afterwards disappears entirely.

### Uncertainties

- The meaning of tuple tag values +0x13 (1, 2, 3, 0xe, 0x11, 9) is inferred from use, not from a definition.
- The exact trip-count formula (0x107538e4) and the init-value lookup (0x10753131) were not read.
- These are only partly read (medium/low confidence): 0x10747ed0 (loop idiom), 0x10745921 (guard compare), 0x107456d6 (child reinit), 0x10746785/0x10746818 (narrow-field IV uses).
- Block +0x30/+0x3c are read as liveness sets (live-out and an intersect set) from 0x10706bf3, which belongs to another area. The must-set semantics in 0x10748c40 are unverified.
- The dag.c anchors 0x10748ec6 and 0x10752210 are not reachable from this pipeline (callers 0x1073a684, 0x10751ea0).
