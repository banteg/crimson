# x87 instruction order under /O2 (C2.DLL 8966)

This note explains where the order of x87 instructions in VC6 `/O2 /GB` output comes from, and how to
predict it from source. Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000).
"Verified" means read in Binary Ninja and confirmed with a preserving compiler trace
([`scripts/c2/sched_trace.py`](../../../../scripts/c2/sched_trace.py), see [Tool](#tool)). "Read" means
static reading only.

Short version:

1. The list scheduler never reorders two x87 instructions that write the stack. Every x87 value is
   allocated to one register symbol, ST(0), so they form a single dependency chain. The x87 sequence
   is fixed before scheduling, by expression order, the commutative operand sort, forward propagation
   and lowering.
2. The scheduler only moves integer instructions and `0x162` round markers (FROUND) around that chain.
   It can also swap x87 instructions that only read ST(0), such as `fst m` and `fcom m`.
3. The chain is cut into windows. A window ends at a branch, switch or label, or after 81 nodes, and
   every FROUND counts as a node. Adding or removing a FROUND moves every later 81-node boundary in the
   block by one node. That changes which integer instructions can move across the x87 code.
4. In a commutative `fadd`/`fmul` with two memory leaves, the operand with the larger sort key is
   loaded with `fld`. For leaves that share a cost class the key comes from symbol slot ids.
   Inline-copy locals compare by id mod 8, so adding or removing one named local anywhere in the
   function can swap the operands.

## 1. What orders x87 code

| Stage | Where | Effect on x87 order |
|---|---|---|
| Expression sort | `compute_tree_cost_and_sort` 0x1070d90c, `merge_sort_operand_list` 0x1070f584, `compare_operand_cost_desc` 0x1070f6ae | Orders the operands of commutative nodes (fadd/fmul are IL 0x16d/0x16f) by packed cost, descending and stable. The first operand is evaluated first. [optimizer.md](optimizer.md), and snail-mail's `tools/match/c2/x87-order.md` for the cost table |
| Forward propagation | `forward_propagate_definitions` 0x10711afa | Moves the expression tree of a single-use variable to its use, and inserts FROUND before the use for float-class types (§3) |
| x87 lowering | `lower_x87_tuple` 0x10762fc3, `lower_x87_binary_op` 0x10763d93 | Emits `fld` for the first sorted operand unless an operand is already on the stack (§5). Binds every x87 value to `g_reg_symbols[0x1f]` (ST(0)), with `[0x20]` for ST(1) when both operands are on the stack |
| fxch rewriting | `x87_block_fxch_scheduling` 0x107392c7, called from `local_color_registers` (0x10733756), under /Ot and only when fn+0x34 bit 3 (function uses FP) is set | Per block: deletes every fxch, recomputes st(i), and inserts fxch only where an operation needs its operand in st(0) ([frame.md](frame.md) §5). Arithmetic is not reordered |
| List scheduler | `schedule_instructions` 0x107374aa, fp_mode 0 | Keeps the x87 chain. Interleaves integer tuples and FROUND markers (§2, §4) |

**Scheduler fp_mode.** The only call to `schedule_instructions` is at 0x10758526, and it passes
`xor edx,edx`, so fp_mode is always 0. The fp_mode=1 pieces (`sched_fp_prepare_window` 0x1077ac93,
`sched_fp_assign_stack` 0x1077ae14, the x87-balanced window end at 0x10794d5e) are dead. [Read]

One fp piece does run in integer mode. `sched_init_cpu_model` sets 0x10799254 from fn+0x34 bit 3
(0x10737634), and `sched_fp_adjust_edges` 0x1073a91f runs when that flag is set. It calls 0x107657b0
for each FROUND node (§4). [Read + verified]

**Why x87 order survives the scheduler.** After lowering, every x87 temp has storage ST(0), address
`g_reg_symbols + 31*0x54`. `sched_build_dependency_graph` 0x107396f6 adds RAW, WAR and WAW edges on
register storage. `fld`, arithmetic ops, `fstp`, `fcomp`, `fxch` and `fild` all write ST(0), so they
chain in their original order.

- Instructions that only read ST(0), such as `fst m` and `fcom m`, can still be reordered among
  themselves. In player_update, windows 100 and 125 emit `fcom` before `fst`, because the compare
  feeds the branch and has the greater height. Native has the same order (0x413fdf, 0x41423d).
- `sched_trace.py` checks this on every window. Across ui_element_render (76 ST-writing x87 tuples),
  highscore_screen_update (235), player_update (1632) and projectile_render (1179), no ST-writing pair
  changed order. [Verified]

## 2. Windows (`sched_find_window_end` 0x10737a43)

Verified from the disassembly and in the traces:

- A window starts at the tuple after the previous window's last node. If that tuple is the epilogue
  marker 0x1b5, it is skipped for counting but stays in the window.
- The window then walks at most 81 tuples. Every tuple counts: machine tuples, `_epush`/`_epop`,
  FROUND 0x162, `0x1bc` dead-label marks, and EH or pseudo tuples.
- It stops at the first tuple of kind 0x11 (branch), 0x13 (switch) or 0x1a (label). That tuple is the
  window's last node.
- It stops before a kind-0x16 tuple with opcode 0x1b5, and before a kind-0x18 function-exit tuple.
- With 81 nodes seen and none of those, the window ends at the 81st node.
- Calls do not end a window. Calls are DAG barriers inside it.
- `sched_window_worth_scheduling` 0x10737a97 schedules a window only if it has at least 2 tuples with
  operands (flags bit 0) **not counting the last node**, and does not start at 0x1b5. A plain
  `cmp; jcc` window is therefore left as is. This corrects [layout.md](layout.md), which says
  "≥ 2 real tuples".
- The window is always cut in pre-schedule order, so boundaries depend only on the IL list after
  register allocation and the late passes.

**Counting from a native listing.** Each scheduled window is emitted as one contiguous run, so a
window's machine tuples are a contiguous range of the native function. In highscore window 4, the 75
machine tuples are exactly native instructions #1-#75 after label L95.

To predict a boundary, add these to the native instructions: FROUND markers (§3), and tuples that
passes after the scheduler delete. `post_schedule_merge_moves` (/Ot) and `late_stack_temp_forwarding`
removed 6 `mov`s in ui_element_render, for example (161 `mov` tuples scheduled, 155 in native). The
tool gives the exact count.

## 3. Where FROUND (0x162) comes from

FROUND emits no instruction. It is a pseudo tuple `st0 <- st0` that stands for rounding to the
declared type. There are two sources.

**Forward propagation, the common source.** [Verified by reading 0x107125f3..0x10712655 and by the
micro tests in the work dir.] `forward_propagate_definitions` 0x10711afa handles a variable def with
exactly one reaching use. It moves the def's tree to just before the use
(`move_expression_tree_before`), then:

1. if the use's type differs, it inserts 0x15f;
2. if the operand needs it, it inserts a 0x15b copy;
3. **if the type class is 0x4000 (float, double), it always inserts 0x162** (0x10712643). The marker
   takes the use's line.

This corrects [optimizer.md](optimizer.md), which says the marker is added only when widths differ.

Which source constructs produce a FROUND:

| Source | FROUND? |
|---|---|
| Inline function or constructor parameter initialised with an arithmetic expression and used once, e.g. `vec2(x + o.x, y + o.y)` with `: x(x_value), y(y_value)` or with body assignments | yes, one per parameter |
| Local assigned once from an expression and read once, e.g. `float c = b*b; g = c + b;` | yes |
| `double d = int_value;` read once, e.g. highscore's `double center_offset = 128 - half` | yes (double class) |
| Local read more than once (`float b = x - 3` read three times; highscore `double x_value` read twice) | no |
| Variable with more than one def (`position.x = ...; position.x -= 32;`) | no |
| Local whose address is taken (`sink(&a)`) | no; it is stored with `fst` |
| Direct store to a member, global or argument (`s->f = a + b`, `f(a + b)`) | no |
| `(float)int_value` inside an expression | no |
| A propagation blocked by a possibly-aliasing store between def and use (`v->x = x` in an inline setter blocks propagating `y`) | no. The value stays on the x87 stack instead (§6) |

**C1 explicit casts.** C1 emits 0x162 itself (`il_read_tree`, 0x10714d98) for an explicit narrowing of
a double expression, e.g. `(float)(d * 2.0)`. In `micro1` this was the only 0x162 in the phase-0 IL.

**Where it lands.** In the pre-schedule list the marker sits right after the x87 instruction that
produces the value and before its consumer. It shifts every later window boundary in the same block
by one node.

## 4. Priorities and edges as applied to x87 tuples

`sched_compute_priorities` 0x1073a684 computes, for /G5 and /GB (weights 0x107a0d98, index 2):

```
priority = height<<13 + reads_mem<<16 + out_degree>>5
         + (tuple type class 0x4000 ? writes_mem<<16 : 0)
```

The critical-path and feeds-jcc terms have weight −1. `feeds-jcc` has weight 23 only on /G6. Every
priority in the traces fits this formula. Examples:

- `fld [esi+0x18]` at h 37 → 368640;
- `fstp s784` at h 27 → 286720 (the float store bonus);
- FROUND at h 1 → 8192;
- `push reg` at h 14 → 114688 (an integer store gets no bonus).

Ties go to the ready node with the lower `seq`, which is original order.

P5 latency table 0x107a0dd8 {latency, busy, class | pairing<<8} for the x87 ops. Read, and consistent
with the heights in the traces:

| op | lat | class | pairing |
|---|---|---|---|
| fld 0x60, fxch 0x5f | 1 | 2 (FP) | fld: first slot only (1); fxch: second slot only (2) |
| fadd/fsub/fsubr/fmul 0x45-0x48, faddp/fmulp | 3 | 2 | first slot only (1) |
| fdiv 0x49 | 39 (busy 39) | 2 | 1 |
| fcom/fcomp 0x5c/0x5d | 4 | 2 | 1 |
| fild 0x56 | 3 | 2 | not pairable (3) |
| fst/fstp 0x62/0x63 | 1 | 2 | 3 |
| fistp 0x5b | 6 (busy 6) | 2 | 3 |
| fnstsw 0x6e | 2 | 2 | 3 |

An x87 op pairs only with a following fxch. Opcodes ≥ 0x144 get only `sched_latency_adjust` (0x10739b58),
and `sched_set_edge_latency` 0x1073a261 gives edges out of a 0x162 latency 0. An edge into a FROUND
carries the producer's latency, 3 after fadd.

**FROUND edges** [verified]. `sched_fp_adjust_edges` → 0x107657b0 removes each FROUND out-edge whose
target is a float tuple that does not read the FROUND's value symbol (0x10752183 removes the edge). It
then re-adds the FROUND's in-edges from its predecessors to that target. This is why a traced
`fadd → fld` edge has kind 7 including RAW. After this pass a FROUND keeps:

- its in-edge from the producer;
- an out-edge only to a consumer that reads it directly as the next ST(0) reader (`FROUND → fstp`);
- the order edge to the window tail.

A FROUND whose value is consumed later has height 1 and priority 8192. It drifts toward the end of
the window. When it is picked it takes an issue slot: it was alone in its cycle in every window
inspected.

## 5. Commutative fadd/fmul operand order, end to end

1. **Sort.** The final pre-lowering sort leaves commutative operands in descending packed-key order.
   It is stable, so equal keys keep source order (for `x + other.x`, `this` first).
   - **Two memory leaves with a symbol base and displacement 0:** key
     `0x10000 | ((base_hash << 8) + 7) & 0xffff`, where 7 is `IL_AM_BASE_DISP − 0x145`. A local or
     inline-copy base has hash `id << 5`, so only **id mod 8** survives. A CSE temp base has
     `id << 6`, so only id mod 4 survives.
   - **Memory with a nonzero displacement** (the Y lane, `+4`): the address is still an expression,
     so the whole `id << 5` hash compares and the larger id wins.
   - **A float local:** `0x10000 | id << 5`.
   - **Constants** sort last. **Expressions** sort before leaves.
   - Sources: snail-mail `x87-order.md` and `address-order.md`. The `sched_trace.py` float-op report
     confirms each key.
2. **Lowering** (`lower_x87_binary_op` 0x10763d93) [read]. A "stack temp" is a class-3 temp with a def,
   meaning its value is on the x87 stack.
   - Neither operand is a stack temp: `emit_x87_load_operand` loads the **first** operand, and the
     second becomes the memory operand (`fld a; fadd b`).
   - Only the second is a stack temp: it is already st(0). The op uses the first as memory and swaps
     the sources, taking the reversed form for fsub/fdiv (`select_x87_arith_form` with reverse=1). For
     fadd/fmul **the sort order then has no visible effect**. At L136 in ui_element_render the sort put
     `[ro]` first, and the code is still `fadd [ro]`.
   - Only the first is a stack temp: `fop st0, second`.
   - Both are stack temps: whichever is on top of the model stack (`g_fp_lower_stack_syms[depth]`) is
     st(0), and the other is st(1). This gives the pop forms (`faddp st(1)`), which the x87 peepholes
     fold ([frame.md](frame.md) §4).
3. **fxch.** Under /Ot the fppeeps pass re-inserts fxch only where needed, and
   `x87_fold_fxch_into_load_order` 0x107772a5 turns `fld a; fld b; fxch` into swapped loads.
4. **Scheduler.** Keeps the pair (§1).

So a residual of the form `fld [A]; fadd [B]` against native `fld [B]; fadd [A]` is always a sort-key
decision between two leaves.

**Slot ids.** Pool-B ids hold locals, parameters and inline copies (snail-mail `address-order.md`).
IL locals get their ids before the inline copies made for inlined operators and constructors.

- A named local anywhere in the body, even after the site, shifts every later inline-copy id by one.
- An unused local declaration allocates no id.
- A dead-stored local (`int pad = 0;`) does allocate one.

Blocks are 32 slots, so a shift of s moves every residue by s mod 8.

## 6. Other pre-scheduling x87 shapes seen in the survey

- **Two lanes held on the stack.** Native computes Y first, keeps it in st(0) while it computes X, then
  stores X and Y: `fld mi.y; fadd [p+4]; fld mi.x; fadd [p]; fstp x; fstp y`.
  - This is an inline function taking both lane values by value, e.g.
    `pu_vec2_set(&v, mi.x + p->x, mi.y + p->y)`.
  - C1 evaluates the arguments right to left. The Y parameter's forward propagation is blocked by the
    store through `v` before its use, so Y stays on the stack. X is propagated and gets a FROUND.
  - Two scalar assignments give `fld; fadd; fstp` per lane instead.
- **Value kept on the stack vs stored and reloaded:** decided by the x87 allocator
  `allocate_x87_live_ranges` 0x107645d8 (scores, nesting test, splits); see [x87-spills.md](x87-spills.md).
  `x87_keep_float_temp_on_stack` 0x10763c4e only turns a float memory-to-memory copy into integer moves.

## 7. Acceptance tests

Each round of predictions was written down before its compile. The variant sources and traces are not
kept in the repo; `scripts/c2/sched_trace.py` regenerates the traces for any scratch.

### (a) ui_element_render (canonical byte-exact)

Canonical trace, lowering-entry float ops. Four `(pos + render_offset)` X lanes compare two memory
leaves through the inline copies of `this` (pos) and `other` (render_offset). `other` must sort first
to give native's `fld [esi+0x8]; fadd [esi+0x18]`.

| line | site | this, other ids | residues | swaps when the shift s ≡ |
|---|---|---|---|---|
| L154 | offset panel, quad 0 | 0x2e9, 0x2f2 | 1, 2 | 6 (mod 8) |
| L160 | offset panel, quad 2 | 0x2f6, 0x2f7 | 6, 7 | 1 |
| L165 | offset panel, quad 4 | 0x2fb, 0x2fc | 3, 4 | 4 |
| L184 | counter `render_pos = pos + ro` | 0x300, 0x301 | 0, 1 | 7 |

The shadow lanes `(pos + vec2(7,7) + ro)` cannot swap, because one operand is already in st(0).

| variant | prediction (written first) | observed |
|---|---|---|
| V1: loop 1 plain (`overlay_vertices[i].color_a = 200`) | s=−1 → one swap at L184 | 99.6161%, one swap at the counter X lane (ids 0x2ff/0x300) ✓ |
| V2: loop 2 plain | s=−1 → L184 | 99.6161%, L184 ✓ |
| V3: loop 3 plain (after L184 in source) | no swap: first-reference model | 99.6161%, L184 swaps ✗. **Correction:** IL locals are numbered before all inline copies wherever they sit |
| V12 | s=−2 → one swap at L154 | 99.6161%, L154 ✓ |
| V123: all three loops plain | none written (compiled in the same batch as V3). The corrected rule gives s=−3 ≡ 5 → exact | **100%, byte-exact** |
| dead1, dead2, dead4, dead6, dead7, dead8 (N dead-stored `int pad_k = k;`) | L160 / exact / L165 / L154 / L184 / exact | all six as predicted ✓ |
| pad1..pad8 (unused `float pad_k;`) | exact if unused locals take no id | exact, ids unchanged (negative control) |
| NOTES control "scalar shadow constructor" (99.23%) | shadow lanes cannot swap | Two swaps, neither in the shadow sums. L154: ids 0x2c1/0x2c9 are both ≡ 1, so the tie keeps `this` first. L184: 0x2d7 ≡ 7 against 0x2d8 ≡ 0 |
| NOTES control "staged shadow owner" (97.70%) | – | x87 and instruction text identical. The loss is frame/stack-slot layout, not x87 |

**Why the canonical form matches.** The SDK expression form puts the pool-B count before the operator
inline copies on residues where none of the four pairs wraps.

- "A plain vertex loop reaches 99.62%" is a loss of one pool-B slot (s = −1 wraps the counter pair).
- It is not a property of the loop. Making all three loops plain (s = −3) is byte-exact with the
  canonical vector expressions.
- NOTES' reading that "the native lifetime boundary depends on the combined expression form" is
  therefore too strong. The x87 part depends only on the slot count modulo 8.

### (b) highscore_screen_update

The block after label L95 (native 0x442465) runs to the `jne` at 0x4425eb: 93 native instructions.
The separator's Y `fadd [14.0]` is native #75.

| | FROUND before the Y fadd | Window 4 ends at | Window 5 starts with | Native order |
|---|---|---|---|---|
| canonical, `double center_offset` | 6: 2 per inlined `operator+` ctor (×2), `center_offset`, separator X param | node 81 = Y fadd (75 machine + 6) | Y FROUND (pri 163840), interface load `mov ecx` (212992) ready, fstp Y waits on the FROUND | `mov ecx; push 1.0; fstp Y` ✓ exact |
| plain, `(float)(128 - half)` | 5 | node 81 = Y FROUND | fstp Y (221184) beats `mov ecx` (212992) | fstp first, 99.9501% |

- **Prediction** (written before the traces): the double version's window ends exactly one node
  earlier. ✓
- **Absolute count** was off by one: I also counted a FROUND for `position.x = ... ; position.x -= 32`.
  That symbol has two defs, so it is never forward-propagated. The rule in §3 now lists this.

### Survey of the WIPs

- **player_update** (work copy 64.50%). The dominant x87 residue is the two-lane hold shape (§6):
  native has 71 `fld; fop; fld; fop; fstp; fstp` sites, ours 3.
  - Replacing the scalar pair at source lines 1264-1265 (`scratch_pos.x/.y = movement_input + *player_position`,
    native 0x416c25) with an inline two-argument setter reproduces native's exact x87 shape at that
    site (prediction written first).
  - The whole-function score fell to 63.97% when only that site changed. Converting every site of
    the kind raises it (66.31%); the hold also needs a function-scope destination and lanes read
    through a computed pointer ([x87-held-lanes.md](x87-held-lanes.md)).
  - The scheduler-only differences (fst/fcom order) already match native.
- **projectile_render** (65.40%). No two-lane sites, and fxch and st(i) counts match native closely.
  - The x87 residue is value lifetime. At native 0x4247fb the clamped `fade` is a memory variable:
    `fst [fade]; fcomp [1.0]; ...; mov [fade],1.0; fld [fade]; fcomp [0.0]`. Ours keeps the helper's
    result in st(0): `fcom; fstp st(0); fld const`.
  - An in-place clamp of a local compiles to the identical object (negative control). Native's `fade`
    is an x87 candidate that either scores 0 or less or fails the nesting test
    ([x87-spills.md](x87-spills.md)); `scripts/c2/x87_alloc_trace.py` shows which. Open.

## Tool

```sh
uv run python scripts/c2/sched_trace.py <scratch-dir> --out <new-dir> [--lines A-B] [--json]
```

The tool runs the preserving `c2-trace` observer: the whole COFF must be unchanged, and a missing
stream must be rejected. It adds hooks at:

- `sched_find_window_end` (return);
- `sched_compute_priorities` (return);
- `sched_emit_tuple`;
- lowering entry.

It prints every window with its node, machine and FROUND counts and why it ended. For each scheduled
node it prints seq, height, priority, cycle and emitted position. It also prints the pre-lowering
float add/sub/mul/div operands in sorted order with their slot ids and keys, and a check that no x87
write order changed. `--json` writes `sched.json` (windows, DAG edges, emits). A trace takes about
3 s for ui_element_render and 9 s for player_update.

## Open questions

- Why native projectile_render's clamped `fade` is not an x87 register candidate.
- `sched_fp_adjust_edges` also adds edges for x87 value symbols with the same parent (loop at
  0x1073a9ed). No trace exercised it visibly.
- The exact unit and pairing handling of FROUND. Its latency-table index is past the 0x144 table
  bound. It was alone in its cycle in the windows inspected, but the pick path for it was not read.
- The emission rule for C1's own 0x162 beyond explicit `(float)(double expr)` casts was not mapped.
