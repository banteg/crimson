# C2.DLL (VC6 8966): control flow cleanup, block layout, scheduling, emission

This covers everything after register allocation in the pass driver 0x10757fc2. All addresses are absolute VAs.
"Verified" means I read the disassembly or HLIL. Hypotheses are marked as such.

## 0. Late pipeline and its gates (driver disassembly 0x10758446..0x107585c2)

| call | function | gate |
|---|---|---|
| 0x10758450 | cfg_reset_single_block 0x10704d75 | /Og |
| 0x10758466 | jump_optimize 0x10735042 (#1) | skipped if fn+0x34 & 0x800 |
| 0x10758479 | 0x1073536c (finlower, see [frame.md](frame.md)) | always |
| 0x10758487 | `g_jumpopt_no_crossjump` (0x107ac348) = 0 | always |
| 0x107584a9 | jump_optimize (#2) | /Og. Everything from here through 0x10758554 is skipped without /Og |
| 0x107584bc | block_mover 0x1073663c | /Og |
| 0x107584cf/d6/dd | coalesce_label_runs 0x10704de1, remove_dead_labels 0x10704ea7, remove_unreachable_after_terminators 0x10736ab0 | /Og |
| 0x107584f9 | late_register_value_cse 0x10736b27 | /Og |
| 0x10758526 | schedule_instructions(fn, 0) 0x107374aa | /Og. Skipped if the function symbol has flag 0x1000 (0x10758507), unless 0x107ac11c is set. Skipped if fn+0x34 & 0x10000, unless /GX (0x107ac070) or 0x107ac11c is set |
| 0x10758541 | post_schedule_merge_moves 0x1073e113 | /Og and /Ot |
| 0x10758554 | late_stack_temp_forwarding 0x1073e591 | /Og |
| 0x1075857e | compute_esp_depth_adjustments 0x1073e945 | fn+0x34 & 0x10 or & 0x600000. Otherwise, with /Og, 0x10766770 runs |
| 0x10758591 | lower_switch_pseudo_ops 0x1073eb93 | always |
| 0x1077d910 | insert_penter_call 0x1076ac20 | /Gh |
| 0x107585b1 | emit_function 0x1073ebea | always |
| 0x107585c2 | function_cleanup 0x1073fbdd | always |

`g_jumpopt_no_crossjump` is set to 1 by the per-function init 0x1071b95b (called at 0x10758075, write at 0x1071b974). It is cleared only just before jump_optimize #2. As a result:
- **jump_optimize #1** does only: dead code removal, jump threading, deleting jumps to the next instruction, branch inversion, and threading by condition implication.
- **jump_optimize #2** does all of that plus cross-jumping, tail sinking, head hoisting and compare threading.
- Both /O1 and /O2 include /Og, so both run the mover and the scheduler. Their behaviour differs through /Ot (0x107ac0b4) thresholds.

## 1. Jump optimizer 0x10735042 → 0x10735067

`jump_optimize` repeats `jump_optimize_sweep` until a sweep makes no change, with at most 17 sweeps (0x10735058). A sweep walks the tuple list forward and dispatches on the tuple kind (table 0x1073b848):
- **ret (kind 0xf) and switch (kind 0x13):** `delete_unreachable_after` 0x10723996 deletes following tuples up to the next label, kind 0x15 or kind 0x18.
- **Branch (kind 0x11)** (0x1073519e):
  1. For an unconditional jump, `delete_unreachable_after` runs first.
  2. The branch must target a label and must not have byte+9 bit 3 set (IL branch opcodes 0x187..0x18c set that bit).
  3. Then these run in order, and the first one that succeeds wins:
     1. `delete_jump_to_next` 0x10723d95
     2. `jump_opt_target_is_18c` 0x1073ccb9
     3. The rest requires /Og (0x107351f0).
  4. **Conditional branch** (+0x20 != 0 or opcode 0x18b), in order:
     1. `delete_redundant_cond_branch` 0x1073cd28: `jcc L; jmp L` drops the jcc. `jcc a; jcc b` where b implies a drops the second jcc.
     2. `invert_branch_over_jump` 0x10723e43: `jcc L1; jmp L2; L1:` becomes `j!cc L2; L1:`.
     3. `thread_cond_branch_by_implication` 0x1073cdf8. Let jcc(c1) target L, and let the first real instruction at L be jcc(c2). If `g_cond_implies_not[c1]` has bit c2, the jcc is retargeted to a label placed after the second jcc. If `g_cond_implies[c1]` has bit c2, the jcc follows the chain, up to 4 hops. A (branch, target) memo at 0x107ac728/72c prevents ping-pong.
     4. Only when `g_jumpopt_no_crossjump` is 0:
        - `hoist_common_successor_heads` 0x1073cf09
        - `cross_jump_complementary_branches` 0x1073d024 (/Os only)
        - `eliminate_redundant_compare_across_branch` 0x1073d04c, only when the previous real instruction is cmp/test/or.
  5. **Unconditional jump**, only when the flag is 0:
     - `cross_jump_into_fallthrough` 0x1073d701
     - then `hoist_join_instruction` 0x1073d7fe (low confidence)
- **Label (kind 0x1a)** (0x107350c6):
  1. If `label_try_remove` succeeds, it is a change. Adjacent labels are merged with `label_redirect_and_delete` 0x10705208.
  2. With /Og, if the first real tuple after L is `jmp L2`, all references to L are retargeted to L2 (0x10735146). This is jump-to-jump threading. It is blocked by bit 3 on the jmp or on any reference.
  3. Otherwise, when the flag is 0: `cross_jump_label_refs` 0x1073d211 runs, and if it does nothing, `sink_common_tails_of_label` 0x1073d2c5 runs.

After a change the sweep resumes at `jump_opt_restart_point` 0x1073c2e4, the nearest preceding branch or label.

### Cross-jumping and tail merging (all of these match backward with `tuples_equal` 0x1073d365)

- **`cross_jump_pair` 0x1071dfc6** (driven by 0x1073d211 over every pair of unconditional jumps to the same label L, in L's reference-list order).
  - It matches the code before J1 against the code before J2, skipping labels and 0x1bc tuples.
  - It deletes J1's copy and retargets J1 to a label created before J2's copy (`label_after_or_create` 0x1073db2a). Alias annotations are merged by 0x1073db6b.
  - If J2's matched run is bounded by a jmp or ret, the roles are swapped: the side that is fully covered gets deleted.
  - **Profitability:**
    - /Os merges always (0x1071e163).
    - /Ot merges only if the encoded bytes of the matched code, plus max(jmp+0x12 counters), exceed **20 bytes** (0x1071e1c2/0x1071e1ef). The running sum stops at the first point ≥ 20 and must be strictly greater, so a tail of exactly 20 bytes never merges; J2's counter becomes max(20, total + J2's counter). An identical whole block always merges. Otherwise it truncates the match at the last jmp or switch boundary seen inside the match, if there was one ([aggregate-temporaries.md](aggregate-temporaries.md)).
- **`sink_common_tail_pair` 0x1074d84f** (driven by 0x1073d2c5, only when L's previous real tuple is ret or jmp, so nothing falls into L). This is the **tail sinking** mechanism.
  - For two jumps J1 and J2 to L with a common tail, J2's copy of the tail is **moved to just before L** with `tuple_move_range`, so it falls through into L.
  - J1's copy is deleted.
  - Both jumps are retargeted to the label at the head of the moved tail.
  - Pairs are tried in the order i<j over the label reference list, and the first success wins. There is **no size threshold**.
  - Matching continues across calls and conditional branches. These only set a flag that triggers label fix-ups in 0x1071deda.
- **`cross_jump_into_fallthrough` 0x1073d701** (no size threshold; this is what merges per-arm calls in an if/else whose last arm falls through, see [arm-local-builds.md](arm-local-builds.md)): takes `...X; jmp L` where L's fall-in path also ends in `...X`. The copy before the jmp is deleted and the jmp is retargeted above X at L. Conditional branches inside the match are allowed only under /Os (0x1073d746).
- **`hoist_common_successor_heads` 0x1073cf09:** applies to `jcc L` where L has one reference and no fall-in (`label_single_ref_no_fallthrough` 0x1073cfca). The identical leading instructions of the fall-through path and of L are kept once: the jcc is moved below them (0x10702bf8) and L's copy is deleted. Instructions that touch the branch's operand stop the match (0x10733683).

## 2. Block mover 0x1073663c (/Og, after jump_optimize #2)

### Loop 1 (0x1073665b), which confirms and refines the documented gate

For each tuple J:
1. J must be `jmp L`: kind 0x11, condition 0, opcode not 0x18b, label operand, byte+9 bit 3 clear.
2. J->next must be a label (0x10736749) and must not be L itself.
3. L must lie after J (forward scan 0x10736777).
4. L->prev must be an unconditional jmp (not 0x18b), a **ret (kind 0xf)** (0x10736787), or a no-return exit (op 0x18c).
5. The first jmp or ret **after L** is then found. Conditional branches and labels are skipped. If there is none, the anchor is the function end.
6. `[J->next .. L->prev]` is moved right after that terminator (0x107367ce), and J is deleted.
7. Scanning resumes at the moved range's head, so the moved code is processed again.

### Loop 2 (0x10736692), which the existing notes did not describe. It is about jump targets.

1. For each `jmp L` meeting the same conditions, first delete it if it is a jump to the next instruction.
2. Walk from L to the target block's terminator:
   - **Allowed terminators:** unconditional jmp (not back to L) or ret.
   - **Failures:** a conditional branch, a switch, kind 0x18, a pseudo real tuple, or reaching J itself.
   - **Flag:** another label inside the block sets the "multi-entry" flag.
3. **Move** (0x1073691a): if the block is single-entry and L's previous real tuple is `jmp` to somewhere else (not a ret), the whole block `L..term` is spliced in place of J (0x107369cc).
4. **Duplicate** (0x10736920; the copy is a `node_clone` deep copy, call at 0x1073695f, made after register allocation, so it keeps the original's registers and takes no rotation slot, see [tail-merge-rotation.md](tail-merge-rotation.md)): otherwise, if the encoded size of `L->next..term` (terminator included) is ≤ **2 bytes under /Os** or ≤ **20 bytes under /Ot** (0x10736935), the block is cloned after J and J is deleted.
   - Label references of cloned branches are added.
   - If the tuple before J was a call, a tail-call conversion is attempted.
   - If the last clone is a jmp, scanning continues from it (0x10736a5a), which allows chained duplication.
5. **At the end:** if the last real tuple (skipping kind 0x16, unreferenced labels and _epop) is a call, `convert_tail_call_to_jmp` 0x10742830 runs. It requires call byte+0x24 == 4, only _epop tuples before the ret, and ret with 0 bytes. The epops are hoisted and the call becomes a jmp.

## 3. Initial block order (reference; the early passes belong to another area)

- **DFS:** `cfg_dfs_rpo` 0x1070448f is an iterative DFS from the entry block over **out-edge lists**.
  - These lists are LIFO: `cfg_edge_new` 0x10704260 prepends, so successors are visited in reverse edge-creation order.
- **RPO list:** `cfg_relayout_rpo` 0x10712d16 prepends blocks in postorder, which gives RPO. The successor visited **last** ends up placed right after its predecessor.
- **Fall-through repair:** lost fall-throughs get a new `jmp` block (`cfg_repair_fallthrough` 0x1071dc8f).
- **Late collapse:** `cfg_reset_single_block` 0x10704d75 later deletes every kind-0x19 boundary and turns the function into one block.

## 4. Scheduler 0x107374aa (schedmd.c/dag.c)

### Scope
- The driver always calls it with fp_mode=0, so the x87 path (0x1077ac93/0x1077ae14) is dead. In FP functions `sched_fp_adjust_edges` still runs and rewires FROUND (0x162) edges; see [x87-scheduling.md](x87-scheduling.md).
- The CPU model comes from /G# (0x107ac0b0, **default 5**).
  - Index = max(G-3, 0).
  - Issue width: 2/1/2/3 for G3/G4/G5/G6.
  - Unit count: 4/2/4/4.
  - **/G5 and /G6 share the P5 latency table 0x107a0dd8.** It has 12-byte records {latency, busy, class|pairing<<8}.
  - Sample entries: mov/add/cmp/lea/push/pop 1, movzx/movsx 3, imul 10 (class 4 = non-pairable), fadd/fmul 3, fdiv 39, fistp 6, jmp 2, ret 3, cdq 2.

### Prologue and epilogue release (`sched_release_prologue_epilogue` 0x10737743)
- The prologue-end marker 0x1b4 is moved up to just after the last frame-setup instruction:
  - `and esp,-8`
  - `mov ebp,esp`
  - `enter`
  - `push ecx`, used as a 4-byte allocation
  - `sub esp,N`, conditional on flags
- At most 10 tuples are released (0x107377bd). Callee-saved `_epush` tuples therefore become schedulable together with the first body window.
- The epilogue-begin marker 0x1b5 is moved the same way, before the first frame-teardown instruction (`pop ecx`, `leave`, `mov esp,ebp`, `add esp`).
- `sched_restore_prologue_markers` 0x1073e027 puts the markers back after scheduling. If the originally-last prologue tuple ended up **≥ 40 tuples** from the function start (0x1073e078), the released tuples are moved back into the prologue. This keeps the FPO prolog size under 256; emit_fpo_record raises an ICE otherwise.

### Windows (`sched_find_window_end` 0x10737a43)
- A window runs from the node after the previous window.
- It ends at the first branch, switch or label, which is **included** as the last node.
- It also ends before the epilogue marker 0x1b5 or the function-end marker, or after **81 nodes**. All nodes count toward the 81, including pseudo-ops such as 0x162.
- A window is only scheduled if it has ≥ 2 tuples with operands, not counting its last node (0x10737a97); a `cmp; jcc` window is never scheduled.

### DAG (`sched_build_dependency_graph` 0x107396f6)
- **Nodes:** one per tuple. `seq` (+0x36) is the creation index.
- **Barriers** (0x1073a59a) are created for: ret, branch, switch, 0x14, 0x15, 0x17, 0x18, 0x19, label, 0x16 (except 0x1bc), calls, opcodes 0x166/cli/sti, and any operand with the volatile bit (operand byte+0x10 & 0x40). Every sink node before a barrier gets an order edge (0x80000) to it.
- **Register edges:** RAW = 1, WAR = 2, WAW = 4.
  - `fxch` and `xor r,r` read no sources (0x10739c44).
- **Memory edges:** two memory operands are compared only by alias class id (`operands_may_alias` → `alias_classes_intersect`), never by base or displacement. Field classes come from 0x1071afd0/0x1075d788; 0x1071d788 serves symbol-versus-memory checks. Edge kinds are 0x20 store→load, 0x40 load→store, 0x80 store→store ([small-aggregate-copies.md](small-aggregate-copies.md)).
- **Latency:** RAW edge latency = producer latency plus a CPU-specific penalty (0x1073a261; AGI on P5). A producer that is a 0x162 round marker contributes 0.
- **Dependence breaking** (`sched_break_dep_by_displacement` 0x1073a9fb):
  - Consider a RAW or WAR edge between an add/sub/inc/dec/lea/push/pop of a base register (esp included) and a memory operand based on that register.
  - Such an edge is marked bypassable (edge+0x16), and the consumer counts it in +0x24.
  - The consumer becomes ready while that predecessor is still unscheduled. When it is picked, 0x10751ea0 rewrites its displacement.
  - This is how an argument load `mov eax,[esp+N]` gets hoisted above `push esi` with an adjusted offset.

### Priority (`sched_compute_priorities` 0x1073a684)
- `height = max(succ.height + edge.latency) + 1`.
- `priority = Σ shift_signed(term, w)`, where a negative w means a right shift (0x1073af80). The terms and weights (0x107a0d98) are:

  | term | G5 weight | G6 weight |
  |---|---|---|
  | feeds-final-jcc bit (+0x39 bit7) | −1 (off) | 23 |
  | height | 13 | 10 |
  | out-degree | −5 (≈off) | 10 |
  | critical-path bit | −1 (off) | −1 (off) |
  | reads-memory bit | 16 | 15 |
  | writes-memory bit, float results only | 16 | 0 → adds 1 |

- So on /G5: `priority ≈ height·8192 + 65536·is_load + 65536·is_float_store`.
- The dynamic priority update 0x1073b368 is **inactive**: weight[4] = −2 on all CPUs.

### List scheduling (`sched_list_schedule` 0x1073af90, `sched_select_cycle` 0x1073b176)
- The scheduler is top-down and cycle-driven.
- **Ready-list order** (0x1073b147): priority descending, then **seq ascending** (original order) on ties (0x1073b0b5/0x1073b0e2).
- **Each cycle:** walk the ready list and take the first nodes whose unit is free (`g_sched_pick_unit_fn`) and whose earliest cycle is ≤ cycle + unit busy. Stop at the issue width.
- **P5 pairing** (0x1073b3e0/0x1073b597): the second instruction in a cycle must be U/V-pairable with the first (pairing bits 0 UV, 1 PU, 2 PV), or be an FP op followed by fxch.
- **Deferral** (non-G6, `sched_defer_for_bypassed_pred` 0x1073b4a8): a node is deferred if a bypassable predecessor becomes ready next cycle.
- **fxch** (/Ot G5, 0x1073b500): holds help fxch pairing.
- **Output:** each window is relinked in emission order (0x1073b669).

## 5. Final emission 0x1073ebea (code.c)

- **Switch lowering** (0x1073eb93 → 0x1074fbee, before emission): each switch becomes `jmp [table+reg*4]`, and its `_data` jump table is placed **at the end of the function**, before the end marker.
- **Branch relaxation** (0x1073ef70):
  - `relax_init_sizes` 0x1073efe0 **starts every local-label jcc/jmp SHORT** (0xf→0x113, 0x10→0x115).
  - `relax_branches_iterate` 0x1073ef84 repeats offset passes. `relax_widen_branch` 0x1073fe4f widens a branch to near when `target − end_of_short_branch` falls outside [−128, 127] (0x1073fe93). For a forward target it uses the old target offset plus the growth accumulated so far in the current pass (0x1073fe7b). It also widens branches to labels in another section.
  - Branches only grow, and the loop stops when a pass makes no change. The result is the least fixpoint (standard MASM-like behaviour).
- **Alignment** (`assign_code_offsets` 0x1073f0e5, `emit_code_bytes` 0x1073f756):
  - There is **no automatic loop or label alignment**. The ALIGN pseudo-op 0x1ba is created only by the IL reader, from front-end input.
  - Jump tables: under /Ot+/Og, a class-2 label followed by a dword `_data` is aligned to 4 (0x1073f20b).
  - Function end: under /Ot+/Og, the function is padded with **0x90 bytes to a multiple of 16** relative to its start (0x1073f7f9). /O1 does no padding.
  - Nop fill tuples use `g_nop_fill` 0x107a2dc0: 1:`90` 2:`8bff` 3:`8d4900` 4:`8d642400` 5:`90 8d642400` 6:`8d9b00000000` 7:`8da42400000000`. Fills of 7 or more use repeated 7-byte `lea esp,[esp+0]`.
- **Encoding** (`encode_instruction` 0x10737aee):
  - Each opcode has up to 6 forms (0x107a1e5c opcode bytes, 0x107a25fc form codes). The **first form whose operand checks pass wins**.
  - For add/sub/cmp/and/or/xor the forms are [acc,imm] [r/m,imm with s-bit] [r/m,reg].
  - The acc,imm32 form is skipped when the immediate fits imm8 (0x10737dc3). So `add eax,1` is `83 C0 01` and `add eax,0x100` is `05 imm32`.
  - Immediates that fit imm8 set the s-bit (0x83) through `encode_imm_or_disp` 0x10738715.
  - Shift by 1 uses the D1 form, except with /G4+/Ot, which uses `C1 ib` (0x1076c6fd).
- **Other emission steps:** FPO record 0x1073faa9, asm listing 0x1073fa72, CRT references `__acrtused`/`__fltused` 0x1073edd3.

## 6. Other late passes (lower confidence)

- **`late_register_value_cse` 0x10736b27 (/Og):** tracks register↔value equivalences within extended blocks, reset at labels. It deletes redundant `mov`s and replaces loads of memory or constants that some register already holds. Candidates are looked up within a window set by table 0x107a0bf8, default 100.
- **`post_schedule_merge_moves` 0x1073e113 (/Ot):** merges adjacent move chains that both issued alone. If ebx/ebp/esi/edi become unused, it deletes their _epush/_epop and fixes the frame counter.
- **`late_stack_temp_forwarding` 0x1073e591:** stack temporaries (class 3, no symbol) that are written once and reloaded get the stored register forwarded, and the load or store is deleted. The exact rules were not fully derived.
- **`compute_esp_depth_adjustments` 0x1073e945:** propagates push/pop esp depth through control flow to labels and rewrites esp-relative operands. It ICEs on inconsistent depths.

## Matching implications

1. **Pipeline gates:**
   - Without /Og, there is no second jump optimizer, no mover and no scheduler; only the first jump_optimize runs.
   - The first jump_optimize never cross-jumps or sinks tails. All tail and cross-jump effects come from jump_optimize #2.
2. **Tail sinking** (0x1074d84f):
   - Two `goto`/`break`/`return` paths that end identically and jump to the same label L get their shared tail placed physically **immediately before L**. This requires L to be preceded by a jmp or ret.
   - The surviving copy is the one belonging to the jump that comes **later** in L's LIFO reference list.
   - There is no size limit, even under /O2.
3. **Cross-jumping** of jumps to the same label (0x1071dfc6):
   - Under /O2 it happens only when more than 20 bytes are saved, or when the match covers a whole block ending in a jmp.
   - Under /O1 it always happens.
   - Small shared tails therefore stay duplicated under /O2 and get merged under /O1.
4. **Block mover loop 1** (verified gate): an unconditional forward jmp J whose next tuple is a label, and whose target's predecessor is a jmp **or ret**, causes the skipped chunk to be moved after the first jmp/ret following L.
5. **Block mover loop 2** (new):
   - A `jmp L` whose target block is single-entry and not reachable by fall-through gets that block **pulled into the jump site**.
   - Otherwise, a target block of ≤ 20 bytes (/O2) or ≤ 2 bytes (/O1) ending in jmp or ret is **duplicated** at the jump site. This is how /O2 duplicates small epilogues or return blocks (`pop esi; pop ebx; ret`) at each return.
6. Only in the jump optimizer: jumps to a `jmp` are threaded, `jcc; jmp` pairs are inverted, and conditional branches are threaded through condition implication (up to 4 hops).
7. **Scheduling windows are basic-block-local** (branch or label ends a window) and capped at 81 nodes, counting pseudo nodes such as 0x162 round markers. Anything that adds or removes IL nodes shifts the window boundary.
8. **Scheduling order is decided by:**
   - priority, which on /G5 is `height·8192 + 65536·(is_load) + 65536·(is_float_store)`;
   - then **original order**;
   - within the constraints of issue width 2, U/V pairing and earliest-ready cycle.
   Loads get a bonus equivalent to 8 cycles of height, so they tend to float up.
9. **Callee-saved pushes and pops** (up to 10 tuples) are scheduled together with the first and last body windows. Argument loads can be hoisted above pushes with an adjusted `[esp+N]` (displacement rewrite). If the prologue gets too long (≥ 40 tuples to the original prologue end), the pushes are restored.
10. **Branch sizes:** start short and widen only when needed. Encoding size decisions (imm8 vs imm32, acc form) are deterministic from the value.
11. **/O2 padding:**
    - Functions are padded with 0x90 to a 16-byte multiple.
    - Switch jump tables sit at the function end, aligned to 4 with lea-style nops.
    - Neither happens under /O1.
12. **Tail call conversion** (0x10742830): a last `call` followed only by epilogue pops and `ret 0` becomes a `jmp`. It requires call byte+0x24 == 4, and the origin of that value is unknown.

## Open questions and uncertainty

- **Opcode 0x18c/0x18b:** resolved in [branch-variants.md](branch-variants.md). 0x18b is an exception edge that final lowering deletes before the mover runs; 0x18c is the no-return exit after `noreturn` calls and `throw`. Ordinary source jumps are always 0x185/0x186.
- **Call byte+0x24 == 4:** the tail-call precondition. Its producer was not traced.
- **Initial RPO edge order:** the order in which successors are created, which decides RPO placement, was not traced to the block builder. The empirical rule from crimson's layout traces ("RPO follows source order") stands.
- **`hoist_join_instruction` 0x1073d7fe, `late_stack_temp_forwarding` 0x1073e591 and `post_schedule_merge_moves` 0x1073e113:** the patterns are only partly decoded.
- **Edge kinds 0x20, 0x40 and 0x80 in the DAG:** the direction of the memory and anti edge kinds is inferred from call sites, not fully verified.
- **fp_mode=1 scheduler path:** dead; the only call passes 0 (0x10758522). x87 order is fixed before scheduling ([x87-scheduling.md](x87-scheduling.md)).
- **0x107ac384/0x107ac388:** exact meaning. They are related to esp-frame tracking.
