# C2.DLL (VC6 8966): IL branch opcodes 0x185..0x18c and the block mover's skip jump

This note decodes the IL branch opcodes 0x185..0x18c and tuple flag bit 3 (byte +9, value 8). It maps which
source constructs produce each opcode, and explains which source-level jump becomes the skip jump J that
`block_mover` loop 1 needs. The acceptance test is `bonus_pick_random_type`. Addresses are absolute VAs in
the pinned C2.DLL. The notes use two evidence labels:

- **Verified** means observed in a preserving trace with `scripts/c2/branch_trace.py`, or read in disassembly
  and then confirmed in a trace.
- **Static** means read in Binary Ninja only.

See also [core.md](core.md) (node layout), [optimizer.md](optimizer.md) (RPO, CSE threading) and
[layout.md](layout.md) (jump optimizer, mover).

## 1. Summary

- Ordinary C and C++ control flow uses only **0x185 CJUMP** and **0x186 JUMP**. This covers goto, break,
  continue, return, switch cases, `&&`/`||`, `?:`, loops, do/while, if/else and `__leave`. None of these tuples
  has bit 3 set. Lowering rewrites them in place to machine `jcc` (0xf) and `jmp` (0x10).
- The optimizer also creates jumps. CSE threading and fall-through repair build machine `jmp` tuples
  (op 0x10) directly with `tuple_new_jmp_before` 0x10704c60. **These never pass through 0x186, and bit 3 is
  clear.**
- Opcodes 0x187..0x18c come only from exception handling and no-return code. `tuple_new_branch` 0x10703aa7
  sets bit 3 on exactly these opcodes (0x10703b84). Nothing else sets or clears bit 3. Bit 3 means "this edge
  is not an ordinary jump": the jump optimizer, the mover, if-conversion, threading and branch inversion all
  leave such branches alone.
- By the time the mover runs, only **0x18c NORETURN_EXIT** can still exist. 0x18b is deleted, 0x187 and
  0x188/0x189 are lowered, and 0x18a is never created. 0x18c can never be J (bit 3), but it **does** satisfy
  the mover's "target's previous tuple is an unconditional jump" test.
- **Bonus picker:** J is a machine `jmp` (op 0x10, flags 0x01) that CSE jump threading
  (`thread_jumps_at_block_end` 0x10708fa7) creates in globopt. It materializes the not-taken exit of the
  stage-4 Nuke rule (`quest_stage_major == 4 && quest_stage_minor == 10 && bonus_id == BONUS_ID_NUKE`).
  On that path the facts `major == 4` and `minor == 10` are known, so the jmp skips the stage-5 rule and
  lands on the stage-4 Freeze rule's `bonus_id == BONUS_ID_FREEZE` test.

## 2. The opcodes

| op | name used here | created by | meaning | fate |
|---|---|---|---|---|
| 0x185 | CJUMP | reader case 0x29 (0x10714f8c); CSE threading (0x1070913b); switch lowering; `__int64` compares | conditional branch, condition in +0xa | `lower_int_tuple` 0x10729c3c → `jcc` (op 0xf) in place |
| 0x186 | JUMP | reader case 0x2a (0x10714fdb); `simplify_tuple` rewrites a CJUMP in place (0x107086f1, static: constant condition); switch lowering; SEH lowering | unconditional branch | → `jmp` (op 0x10) in place (0x1072a372) |
| 0x187 | CATCH_RETURN | `ehexcept_10761233` 0x107887b7 (C++ EH, from `cxx_eh_lower_scopes`) | end of a catch block. The label operand is the continuation after the try/catch | lowered before jump_optimize #2. Emitted as `mov eax, OFFSET continuation; ret` in the catch funclet (verified) |
| 0x188 | FINALLY_CALL | SEH lowering `sub_10766dd7` 0x10787b97 | normal-flow entry into a `__finally` block | `seh_lower_local_unwinds` 0x10767d4e (called at 0x1075872e, after finlower) → `call $finally` (verified) |
| 0x189 | FINALLY_RET | `sub_10766dd7` 0x10787c34 | end of a `__finally` block | same pass → `ret` (verified) |
| 0x18a | – | no `tuple_new_branch` site passes it | unused in this build | – |
| 0x18b | EH_EDGE | `cxx_eh_lower_state_transitions` 0x10788f9f/0x10789006/0x1078909d; `seh_mark_try_region_memory_ops` 0x107623c3; `sub_10766dd7` 0x10766fc5; `sub_10795a89` 0x10795ad3; reader case 0x37 sub-op 0xc 0x10785411 (not reached by any probe) | flow-graph-only edge from a possibly throwing point to a handler. It also falls through (`cfg_build_edges` 0x10705124) | deleted by `final_lowering_peepholes` (0x10735f9d `tuple_unlink_free`), before jump_optimize #2 (verified) |
| 0x18c | NORETURN_EXIT | reader call handler `sub_1071be88` 0x1071c369 (callee fe symbol +0x14 bit 0x80, i.e. `__declspec(noreturn)`); same function 0x10785a25 (intrinsic id 0x151, not identified); reader case 0x4c 0x107163b1 (`__assume(0)`); `jump_opt_target_is_18c` 0x1073cd15 | pseudo jump to the return label after a call that never returns | survives to the mover. Deleted by `emit_prepare_branches` 0x1073ee62. Emits no bytes (verified) |

### Consumers of the opcodes and of bit 3

- **Bit 3 tests** (static; complete list from a scan of `test byte [r+9], 8`):
  - `delete_jump_to_next` 0x10723da6
  - `jump_optimize_sweep` 0x1073516d, 0x1073517d, 0x107351c4. A branch must have bit 3 clear to be optimized, and label jump-to-jump threading is blocked when any referrer has bit 3.
  - `block_mover` 0x1073673d (loop 1 J) and 0x10736816 (loop 2)
  - `follow_trivial_branch_chain` 0x1070967b (CSE threading never passes through such a branch)
  - `invert_jcc_over_jmp` 0x107057fd/0x1070581b
  - `invert_branch_over_jump` 0x10723e86
  - `remove_jump_to_next_block` 0x1070576e
  - `remove_redundant_branches_once` 0x10728f8e/9e, 0x1072901f
  - `pass_if_convert` 0x1072908e
  - `duplicate_exit_block_into_predecessors` 0x10727817
  - `sizeopt_forward_scan` 0x107286d0
  - `mark_constant_branch_dead_edges` 0x10712e4c
  - `find_available_copy_source` 0x10709b8d
  - `invert_loop` 0x10744823
  - `rewrite_loop_guard_compare` 0x1074595e
  - `mark_abnormal_edges` 0x10714afe
- **0x187:**
  - `cfg_build_blocks` sets block flag 0x1000000 on a block ending in CATCH_RETURN (0x10704f75).
  - `sub_10724689` (called by the allocator's `build_split_pieces` and `insert_upward_exposed_reloads`) then forces edge splitting out of that block (0x10724712, static).
  - `forward_propagate_definitions` treats it like a call and kills pending single-use defs (0x10712164).
- **0x188/0x189:**
  - The SEH try records (list at 0x1079bc90, record type 2 = try/finally) keep a list of FINALLY_CALL tuples at record word 0x11 and the single FINALLY_RET at word 0x12.
  - `node_free` unregisters them: at 0x10701b5f, 0x188 → `sub_10787dae` and 0x189 → `sub_10787e1c`.
  - `node_clone` registers a cloned 0x188 through `sub_10787dd8` (0x10701fb5 → 0x1077e562).
  - `seh_lower_local_unwinds` inserts a `jmp` to the FINALLY_RET target after each FINALLY_CALL, then lowers both with `seh_lower_pseudo_op`.
- **0x18b:**
  - Counts as conditional wherever conditions are tested (`cfg_build_edges`, `jump_optimize_sweep` 0x107351fd, `block_mover` 0x10736715/0x1073678d, `remove_unreachable_after_terminators` 0x10736b0e, `cross_jump_pair`, `sink_common_tails_of_label`, and others).
  - `mark_abnormal_edges` 0x10714b38 sets edge flag 0x40 on its target edge.
- **0x18c:**
  - `mark_abnormal_edges` also sets edge flag 0x40 on its target edge.
  - `delete_jump_to_next` looks through 0x18c tuples when deciding "jump to next" and deletes them along with the jump (0x10723dc1/0x10723e22).
  - `jump_opt_target_is_18c` 0x1073ccb9 handles branches to a label followed by 0x18c: a conditional branch is deleted, an unconditional one is replaced by an 0x18c.
  - `final_lowering_peepholes` has a call → `jmp` rewrite that checks the callee's noreturn flag and removes a following 0x18c (0x10735cc4..0x10735d9f, 0x1077cc6d). This is static reading and its conditions are not decoded. It was not observed in the probes: `die` and `throw` stay `call`.
  - `remove_unreachable_after_terminators` → `mark_label_refs_for_18c` 0x1074da73.
  - `emit_prepare_branches` deletes it.

## 3. What each source construct emits (verified)

The probes were compiled with `/O2 /GB /W3 /GR-`, and with `/GX` for the C++ EH probes. Each was traced with
`branch_trace.py`. "read" is the IL right after `read_function_il`, and "cfg" is the IL at `cfg_rebuild` entry,
after SEH and C++ EH lowering.

| construct | read | added by EH lowering (cfg) | at block_mover entry |
|---|---|---|---|
| `goto` forward/backward | JUMP | – | jmp, or deleted |
| `break`, `continue` | JUMP | – | jmp, or deleted by inversion/threading |
| `return x` (early or final) | RETVAL 0x16c + JUMP to the exit label | – | jmp, or deleted as jump-to-next |
| `if` / `if-else` | CJUMP on the false edge; JUMP over the else arm | – | jcc/jmp |
| `&&`, `\|\|` | one CJUMP per operand | – | jcc |
| `?:` | CJUMP + JUMP to the join | – | jcc/jmp |
| `for`/`while` | JUMP to the test + CJUMP | – (the `optimize_flow_graph_initial` relayout later adds machine jmps through `cfg_repair_fallthrough`, e.g. the bonus picker's retry backedge) | jcc/jmp backedge |
| `do/while` | CJUMP backedge | – | jcc |
| `switch` | SWITCH 0x18d + JUMP per `break`/`return` | – | small switches: jcc chain from lowering (`lower_switch_chain`); large ones: SWITCH (table) + jmp |
| call to `__declspec(noreturn)` function, `throw` | CALL + NORETURN_EXIT 0x18c (bit 3) | – | 0x18c still present |
| call to a function declared without noreturn (`exit` redeclared) | CALL only | – | – |
| `__assume(0)` | pseudo 0x1ab + NORETURN_EXIT | – | removed before jo1 in the probe (unreachable default) |
| `__try/__except` | pseudo 0x192/0x193/0x198/0x199 | EH_EDGE ×5 | none left |
| `__try/__finally` with `return` or `__leave` | CJUMP/JUMP + pseudo 0x192..0x194 | FINALLY_CALL, FINALLY_RET, EH_EDGE ×2 | none left (`call $finally`, `ret`, `__local_unwind2`) |
| C++ `try/catch` (`/GX`, throwing callee) | JUMP + pseudo 0x1a0..0x1a6 | CATCH_RETURN, EH_EDGE | none left |
| `/GX` with only `extern "C"` callees | – | – | EH removed entirely (`/GX` assumes C functions do not throw) |

Every C/C++ jump that can become the mover's J therefore enters the pipeline as 0x185 or 0x186 with bit 3
clear, or is created later as a machine `jmp`. The flag-8 and "not 0x18b" terms of the mover gate matter only
in EH and no-return code.

## 4. How the mover's J arises

Loop 1 of `block_mover` 0x1073663c ([layout.md](layout.md) §2) runs on the list left by jump_optimize #2. It
fires when all of these hold:

1. J is an unconditional jmp to label L. Its kind is 0x11, its condition is 0, its op is not 0x18b, and bit 3 is clear.
2. `J->next` is a label, and that label is not L.
3. L lies after J.
4. The tuple immediately before L is an unconditional jump or a ret. **A bit-3 NORETURN_EXIT qualifies** (0x10736787; verified, probe m4).

When the gate passes, the mover moves `[J->next .. L->prev]` to after the first jmp or ret following L and
deletes J. Scanning resumes at the moved range's head, so a jump at the end of the moved range can trigger a
second move (verified, sandwich2 below). The code between J's old position and the insertion point is not
rescanned.

jump_optimize #1 and #2 always delete a jump to the next tuple. So the range R = `[J->next .. L->prev]` must
end in an unconditional transfer that goes somewhere other than L. The source shapes that produce this:

- **An explicit jump that is not adjacent to its target.** Examples: `return` into an exit label that does not
  follow R, `continue`/`break` to a latch that does not follow R, or `goto`.
- **A no-return call.** It ends in 0x18c, which jump-to-next deletion never removes.
- **A threaded exit.** CSE threading replaced R's fall-through with a machine jmp past the following code.

J itself comes from one of these:

- the else-skip JUMP of an if/else;
- a `return` JUMP to the exit label;
- a jmp that threading creates on a fall-through edge (`tuple_new_jmp_before` at 0x10709567 inside
  `thread_jumps_at_block_end`).

Threading follows chains of trivial compare+branch blocks (up to 10 hops, `follow_trivial_branch_chain`) and
works only within one loop. It bypasses a fall-through successor only with /Ot. **A threaded jmp carries the
C2 line of the first tuple of the block it bypasses**, not the line of the rule it leaves. At creation, all 30
thread-created jmps observed (25 in the bonus variants, 5 in the probes) sit before a block whose first tuple has
the jmp's line.

Early layout decides J and L before any of this. In the traces, `optimize_flow_graph_initial` does three
things (observed at its return, mechanism not traced):

- keeps source order;
- merges a join block that has a single predecessor into that predecessor;
- inverts `jcc L1; jmp L2; L1:` into one jcc.

So an if/else whose join is reached only from the then-arm loses its else-skip jump. The then-arm and the join
become one block, which jumps to wherever the join went (probes m1 and m3).

## 5. Acceptance test: bonus_pick_random_type

In the canonical scratch, C2 lines are the scratch line minus 3. The rules are:

| rule | C2 line | scratch line |
|---|---|---|
| hc3N | 50–51 | 53–54 |
| 2N | 54 | 57 |
| hc2F | 57–58 | 60–61 |
| 4N | 61 | 64 |
| 5N | 64 | 67 |
| 4F | 67 | 70 |
| common filters | 72 onwards | 75 onwards |

### J through the pipeline (canonical, verified)

| boundary | what J is |
|---|---|
| read | Not yet a jump. 4N ends with CJUMP `bonus_id != NUKE` → start of 5N (0x185, flags 0x01, line 61), then the `continue` JUMP (line 62). |
| `optimize_flow_graph_initial` return | Branch inversion folds the CJUMP and the continue JUMP into `CJUMP bonus_id == NUKE → latch`. The not-taken exit is now the fall-through into 5N. |
| globopt (`cse_block` → `thread_jumps_at_block_end`) | On that fall-through `major == 4` and `minor == 10` are known. So 5N's `major == 5` test is false, and 4F's `major == 4` and `minor == 10` tests are true. The edge is threaded to 4F's `bonus_id == FREEZE` test, and `tuple_new_jmp_before` creates **J = machine jmp, op 0x10, flags 0x01, C2 line 64**. In the same pass 5N's own fall-out becomes a jmp to the common filters (line 67), and 4F's first two tests lose every predecessor. |
| postglob, lower, jo1, fin, jo2 | Same tuple address and line throughout: op 0x10, flags 0x01. jo1 deletes the leftover jump-to-jump chain around 4F. |
| block_mover entry | `jmp@111 line 64 → L120`. `J->next` = L112 (the 5N label), `L120->prev` = `jmp@119` (5N's threaded exit). Gate: **PASS**. |
| `tuple_move_range` at 0x107367ce | range [L112 .. jmp@119] = the whole 5N rule, inserted after `jmp@180` (the retry backedge, line 93). J is deleted. |

Every other forward jmp fails the gate with `target-prev-cond-jcc`:

- the hc3N exit (line 54);
- the hc2F exit (line 61), which jumps to the common label whose predecessor is 4F's conditional rejection;
- the 5N exit (line 67).

### Why the other orders fail (predicted, then traced)

| variant | rule order | prediction | observed |
|---|---|---|---|
| canon | hc3N, 2N, hc2F, 4N, 5N, 4F | one move: 5N after the backedge | one move, 5N after the line-93 backedge; exact, 162 instructions |
| adj | …, 4N, 4F, 5N | no move: 4N's exit threads into 4F's bonus test, which is the next block, so there is no jump. 4F's exit jmp over 5N lands on the common label, preceded by 5N's jcc. | no move (`jmp@113 → L121: target-prev-cond-jcc`); 75.93%, 162 instructions |
| nukefirst | …, 4N, 5N, hc2F, 4F | no move: hc2F's leading `hardcore` test is not decided on 4N's exit, so 5N falls into hc2F | no move; 157 instructions |
| nested (old else-if form) | nested | no move: the reader's else-skip JUMP (0x186, line 73) over the `major == 5` arm lands on the join, preceded by the arm's jcc | no move; J is born in the reader as 0x186; 75.93% |

The other orders fail for these reasons:

- In the adjacent order the jump that skips 5N belongs to the rule after 4F and targets the shared join.
- In the nukefirst order 5N falls into the next rule.
- In the nested form J is a source `else` jump whose target is the join, which the 5N arm falls into.

### The predictive rule: key sandwich in flat rule chains

Take three consecutive flat rules A, B, C. Each is a chain of `&&` tests ending in `continue` (or any shared
rejection). Suppose:

1. the facts on A's not-taken exit decide B's leading test false and C's leading tests true;
2. every path into B carries a fact that decides C's leading test false (normally B is entered only through A's
   first exit, "A's key test failed");
3. all tests involved are trivial compare+branch blocks inside the same loop.

Then threading turns A's fall-out into J, which lands on C's first undecided test. C's decided head loses all
predecessors. B's fall-out becomes a jmp over C, and the mover relocates B after the first jmp or ret following
C's remainder. With a shared discriminant (`quest_stage_major`), this is the key pattern k, k′, k with k′ ≠ k,
where C's leading tests are key tests. If C starts with a test that A's facts do not decide (for example
`config_blob.hardcore`), nothing moves.

These orders had never been compiled. Their outcomes were predicted from this rule and written down before the trace ran:

| variant | order | prediction | observed |
|---|---|---|---|
| hcfirst | hc3N, hc2F, 2N, 4N, 5N, 4F | one move: 5N | one move: 5N after the backedge |
| sandwich2 | hc3N, 2N, 4N, hc2Fk, 5N, 4F, where hc2Fk = `major == 2 && hardcore && minor == 10 && bonus == FREEZE` | two moves: 4N after hc2Fk's threaded exit, then 5N after the backedge | move 1: J = 2N's threaded exit (line 57), range 4N, inserted after the line-64 jmp. Move 2: J = 4N's threaded exit (line 61), range 5N, inserted after the line-93 backedge |
| sandwich2h | same, with hc2F (hardcore first) | no move | no move |

## 6. Generic probes (if/else, return, no-return)

Probe scratch `p-mover`/`p-mover2`: `/O2`, callee `extern "C" int sink(int)`, `die` declared
`__declspec(noreturn)`.

| probe | source shape | prediction | observed |
|---|---|---|---|
| m1 | `if (c) {T} else {E; continue;} S;` in a loop | move (**wrong**) | no move. The single-predecessor join S merges into T, so both arms jump to the latch and E's continue becomes jump-to-next |
| m2 | if/else, both arms fall into S | no move | no move |
| m3 | `if (c) {T} else {E; return -1;} return f(r);` | move (**wrong**) | no move. S merges into T, E is laid out before the exit label, and its return JUMP is deleted as jump-to-next |
| m4 | `if (c) {T} else die(2); return f(r);` | move | E (`call die` + 0x18c) moved after the final ret. J = T's `return` JUMP (born in the reader as 0x186) |
| m5 | else arm ends in an ordinary call | no move | no move |
| m6 | `if (c) {T; return -1;} return …` | no move | no move |
| m7 | three `k == 4 / k == 5 / k == 4` rules in a loop | move of the middle rule | moved after the final ret |
| m8 | `4, 4, 5` | no move | no move |
| m9 | `4, 5, h && 4` | no move | no move |
| m10 | `if (a) {T} else if (b) {E; continue;} S;` (S has two predecessors) | move (made after m1/m3) | else-if arm moved after the loop backedge |
| m11 | `if (x < 0) die(x); return …` | no move (J would need to be unconditional) | no move |
| m12 | `if (a) {T} else if (b) {E; return -1;} return f(r);` | move (hedged) | else-if arm moved after the final ret |

Source-level rule for if/else: an arm E is moved out of line when both of these hold after early layout:

1. The code physically before E ends with an unconditional jump J whose target L is the first label after E.
   J is an else-skip to the join, or a `return` to the exit label.
2. E itself ends with an unconditional transfer that is not a jump to L. That is a jump elsewhere, a ret, or a
   NORETURN_EXIT.

In practice:

- Early layout merges a single-predecessor join into the arm that jumps to it. So in a plain if/else whose arms
  both leave through the same target (both `continue` in m1, both `return` in m3), E's last jump becomes
  jump-to-next and nothing moves.
- An else-if chain keeps the join alive (m10, m12).
- A no-return arm never ends in a deletable jump (m4).

## 7. Using this on other layout residuals

1. Trace the WIP scratch:

   ```sh
   uv run python scripts/c2/branch_trace.py <scratch> --out /private/tmp/<new-dir> [--phases read,ofg.ret,postglob,mover]
   ```

   Re-render with `--reuse`. For every forward unconditional jump at mover entry, the report prints:
   - the loop-1 verdict (`PASS`, `target-prev-…`, `jump-to-next`, `flag8`, …);
   - its lineage: the pass where it was born (reader, `thread_jumps_at_block_end`, `cfg_repair_fallthrough`, or
     "a pass between X and Y") and its opcode/flags at each boundary;
   - every observed `tuple_move_range` range.

   The mover-entry verdict is static. Moves happen in list order and rescan the moved range, so a later jump
   can pass only after an earlier move (sandwich2).
2. If native has a block after a backedge or return and the candidate does not, find the jump that would have
   to skip it, and read its verdict:
   - `target-prev-cond-jcc`: the skipped code falls into the target. Make the skipped code's last test decided
     by a dominating key test (flat rule order), or give it an unconditional exit elsewhere.
   - `jump-to-next`, or no jump at all: the target was merged or the skipped code is not between J and L.
     Look for a second predecessor of the join (else-if) or a threaded exit.
3. Threading is keyed on equality facts from dominating compares on the same variable. Reordering
   semantically independent flat rules changes which exits are threaded. That is why rule order, not syntax,
   moved the bonus picker.

The tool's hooks are:

| hook | call site | notes |
|---|---|---|
| `set_current_scope` | 0x107580a2 | |
| `cfg_rebuild` | 0x10758147 | |
| `optimize_flow_graph_initial` | 0x1075818f | entry and return |
| `globopt_run` | 0x107581ee | |
| `purge_unreferenced_temps` | 0x107581fc | |
| `tuple_new_jmp_before` | 0x10709567 and 0x1071dd26 | return; records the neighbourhood only |
| `pass_lower_function` | 0x10758310 | |
| `jump_optimize` | 0x10758466 and 0x107584a9 | |
| `final_lowering_peepholes` | 0x10758479 | |
| `block_mover` | 0x107584bc | entry and return |
| `tuple_move_range` | 0x107367ce (mover) and 0x1074d985 (tail sinking) | |
| `emit_function` | 0x107585b1 | |

Every trace passes the standard preservation checks (whole-COFF equality, missing-stream rejection).

## 8. Evidence and reproduction

The raw traces were kept outside the repository. To reproduce:

- **Bonus variants:** copy `tools/match/scratches/bonus_pick_random_type` (source and `scratch.conf`) and
  replace the six quest rules with the orders in §5. Keep each rule's text exactly as in the canonical source;
  hc2Fk moves `quest_stage_major == 2` to the front.
- **Construct probes:** use `FUNCTION=bonus_pick_random_type`, and set `SYMBOL` to the first probe function
  (metrics are meaningless).

The tracer confirmed these facts from §2:

- `/GX` catch funclets end with `mov eax, OFFSET $Lcontinuation; ret`;
- `__finally` bodies are entered by `call` and end in `ret`;
- 0x18c emits nothing.

Scratch validation rejects inline `__asm`, so asm probes were not run. Static reading of `inasm_10772f52`
shows that asm branches use machine ops (0xf/0x10/0x113..0x117) directly, never 0x187..0x18c.

## 9. Open questions

- **0x18a:** no creator found. It is probably reserved.
- **Reader case 0x37 sub-op 0xc** creates 0x18b to a label whose fe symbol has +0x3e bit 0. It is reached by
  no C/C++ probe, and is possibly `-basic` (VB) error handling.
- **Intrinsic id 0x151** is followed by 0x18c at 0x10785a25. It is not identified.
- **CATCH_RETURN lowering:** the exact routine that lowers 0x187 into `mov eax, OFFSET; ret` was not
  located. It runs between `final_lowering_peepholes` entry and jump_optimize #2.
- **Edge flag 0x40:** its use by `analyze_return_paths` (missing-return warnings) is static reading only.
- **Early merging:** the precise rule (single-predecessor join merge, branch inversion) that removes else-skip
  jumps is inferred from m1/m3/m10/m12 and [optimizer.md](optimizer.md), not traced pass by pass.
