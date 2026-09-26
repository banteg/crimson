# How C2 compiles a function

These notes describe the pinned VC6 back end, `tools/match/compilers/msvc6.5/Bin/C2.DLL`
(12.00.8966, SHA-256 `d50100ac…5dda4a`, image base 0x10700000). Crimson and snail-mail both match
against this build. The notes explain how C2 turns frontend IL into the exact bytes we compare against.
All addresses are virtual addresses. Crimson's older notes write `C2+0xNNNN`; add 0x10700000.

The findings come from static reading of the binary in Binary Ninja. They have not been checked against
compiler traces unless a section says so. Each detailed note states its confidence per claim. The
[tracing tools](../README.md) are the way to confirm one of these rules on a concrete scratch.

| Note | Covers |
|---|---|
| [core.md](core.md) | Node kinds, the IL opcode space, symbols, CFG and block records, bitsets, arenas, the compile loop |
| [optimizer.md](optimizer.md) | /Og passes before lowering: flow graph, RPO block order, loop inversion and compaction, expression sort, CSE, forward substitution, loop and induction-variable optimizations |
| [lowering.md](lowering.md) | Lowering and instruction selection: byte lanes, sizeopt, if-conversion, multiply/divide by constant, address modes, switch, intrinsics, x87, `__int64` |
| [regalloc.md](regalloc.md) | Webs, global colouring, the chooser, local allocation and eax/ecx/edx rotation, frame pointer, callee-saved registers |
| [frame.md](frame.md) | Stack slot packing and local offsets, prolog/epilog, final peepholes, EH state, x87 stack |
| [layout.md](layout.md) | Jump optimizer, tail sinking and cross-jumping, block mover, scheduler, emission |
| [array-constructors.md](array-constructors.md) | How `T arr[N];` with an inline constructor becomes the `*_global_init` countdowns (C1XX `??_H` plus C2 inlining), and what the native relink needs to use real array definitions |
| [plain-float-sources.md](plain-float-sources.md) | Plain replacements for retained float spellings: single-use float locals as FROUND owners, guard folding for countdown loops, why `memcpy` label copies stay |
| [x87-held-lanes.md](x87-held-lanes.md) | When a two-lane vector build keeps both x87 products live (forward-propagation alias refusal), with the player_update per-arm shape |
| [x87-spills.md](x87-spills.md) | The x87 register allocator: candidate scores, the nesting test, splits, and when floats live in memory or dead parameter homes |
| [post-promotion-stores.md](post-promotion-stores.md) | Every path that creates a stack store after register promotion, and why dead home stores survive |
| [small-aggregate-copies.md](small-aggregate-copies.md) | How 8-byte copies lower and why alias classes, not addresses, decide whether their loads group |
| [constant-candidates.md](constant-candidates.md) | Which immediate uses save or cost in constant register candidates, and how byte-argument locals get their stores demoted to memory |
| [alias-field-records.md](alias-field-records.md) | Alias field records: the 96-per-class cap, the 0x400 class limit, and what inlined helpers count against `this` |
| [aggregate-temporaries.md](aggregate-temporaries.md) | By-value struct results and copy propagation, plus switch-tail cross-jumping and short-circuit block order |
| [call-operand-order.md](call-operand-order.md) | Which call runs first when both operands of a compare are calls: Sethi-Ullman keys and translation-unit-wide callee hashes |
| [value-threading.md](value-threading.md) | How globopt threads known constants through later compares, and how the block mover then shapes the stores |
| [x87-memory-values.md](x87-memory-values.md) | Why a float value lands in memory through a stack-nesting failure, and how sibling-field stores keep a def ahead of its use |
| [arm-local-builds.md](arm-local-builds.md) | Why identical call sequences in sibling arms merge only their call, and the rotation-distance rule that predicts it |
| [aim-chain-mover.md](aim-chain-mover.md) | Layouts that look like block moves but come from cross-jumping tails copied into several arms, and how label reference order picks which copy survives |
| [per-arm-frame-weights.md](per-arm-frame-weights.md) | How per-arm copies change stack weights before jump-opt merges them, and how to keep slot order while splitting arms |
| [weapon-arm-schedule.md](weapon-arm-schedule.md) | How a cast-inserted FROUND and fst/AGI latency penalties decide integer store placement in a scheduling window, and a tail merge refused at exactly 20 bytes |
| [guard-placement.md](guard-placement.md) | Where loop-cursor inits land relative to the inverted guard, and how the extra preheader block shifts register priorities |
| [frontend-ids.md](frontend-ids.md) | How many translation-unit-wide frontend ids each declaration consumes, measured, with a probe to count a header |
| [codeless-tuples.md](codeless-tuples.md) | Which tuples count toward the 81-node windows without emitting code: parenthesized float expressions make C1 emit a FROUND |
| [iv-cursor-merge.md](iv-cursor-merge.md) | Why hand-written loop cursors always challenge last in the IV merge, and the pointer-after-test shape that anchors a loop at the struct base |
| [tail-merge-rotation.md](tail-merge-rotation.md) | Statements written once after an if/else that the block mover copies back into a jumping arm after allocation, sharing registers without a rotation slot |
| [slot-sharing-symbols.md](slot-sharing-symbols.md) | Cross-jumping compares stack operands by symbol, why function-scope address-taken vectors block slot sharing, and label-offset scoring effects |
| [load-recompute.md](load-recompute.md) | Why a repeated load is recomputed or merged between lanes (value-number owners, forward-propagation rounds), and when a held x87 lane spills |
| [native-slot-partition.md](native-slot-partition.md) | Mapping a native frame slot by slot, and why never-killed float locals force native's shared variables |
| [invisible-ranges.md](invisible-ranges.md) | Exactly which live ranges count toward a block's register pressure P, and which of them emit no instruction |
| [frame-model.md](frame-model.md) | The symbol flags and reference counts behind local offsets, retained field-pointer homes, and the frame predictor |
| [iv-anchor-examples.md](iv-anchor-examples.md) | Worked IV merge chains (projectile_render's plasma loop) and a replay tool that predicts the surviving anchor |
| [x87-scheduling.md](x87-scheduling.md) | Why the scheduler never reorders x87 code, how commutative fadd/fmul operands are ordered (symbol ids mod 8), where FROUND markers come from, and how the 81-node windows split |
| [strength-reduction.md](strength-reduction.md) | Where strength reduction and exit-test replacement put IV setups, which field a loop pointer anchors to, and how to write plain indexed loops that reproduce native cursors |
| [branch-variants.md](branch-variants.md) | Which source jumps emit which IL branch ops, what flag 8 marks, and how to predict block-mover moves in flat rule chains |

## Binary Ninja annotations

[`analysis/binary_ninja/c2`](../../../../analysis/binary_ninja/c2) holds the annotations that make the C2 decompile readable:

- `c2_types.h` defines the node, operand, tuple, symbol, block, CFG, live range, stack slot and
  scheduler records, plus enums for node kinds, IL opcodes and x86 opcodes.
- `c2_symbols.json` names about 1170 functions and 380 globals. It also holds prototypes and
  comments at decision points.

Apply them to a Binary Ninja database of the pinned C2.DLL:

```sh
just binja-sync-c2
```

The script refuses any other binary. Functions that only raise internal errors from a known source file
are named `<file>_<address>`, for example `stack_1074b617`. The source path strings
(`E:\8966\vc98\p2\src\P2\*.c`) are the only record of the original file names.
C2.DLL was reordered by BBT, so functions from one source file are not adjacent. Many functions also
have cold blocks far from their entry.

## Options that gate passes

The `-X` option table at 0x107a35c8 and the letter tables for `-O`, `-G` and `-W` name the globals.

| Global | Option | Main effects |
|---|---|---|
| `g_opt_global` 0x107ac058 | `/Og` | Enables every pass before lowering, the second jump optimizer, the block mover and the scheduler |
| `g_opt_favor_speed` 0x107ac0b4 | `/Ot` (set by /O2, cleared by /O1 and /Os) | Allocator savings, rotation, loop weights, multiply/divide sequences, switch tables, epilog and copy size limits |
| `g_opt_omit_frame_pointer` 0x107ac054 | `/Oy` | FPO decision (`choose_frame_pointer_mode`) |
| `g_opt_cpu_target` 0x107ac0b0 | `/G3`..`/G6` | Scheduler model, multiply budget, copy unrolling |
| `g_opt_float_consistency` 0x107ac0a4 | `/Op` | Float register candidates, `fst` merging |
| `g_opt_eh_enabled` 0x107ac070 | `/GX`, `-EHs`, `-EHa` | EH passes and state stores |
| `g_opt_basic` 0x107ac310 | `-basic` | Visual Basic front end; VB5/6 drive this same C2 |

## Per-function pipeline

`_InvokeCompilerPass@12` 0x10757444 → `backend_main` 0x10757541 → `compile_functions` 0x10757fc2.
For each function in `g_function_list` the driver reads the IL (`read_function_il` 0x1071ba73), runs
the passes below, and calls `function_cleanup` 0x1073fbdd. `abort_poll` 0x107013f2 runs between passes.

| Pass | Gate | What decides output shape |
|---|---|---|
| `cfg_rebuild` 0x1070592f | /Og | Basic blocks and edges (fg.c) |
| `compute_alias_classes` 0x10718eaf | /Og | Alias classes. Over 10000 tuples turns /Oa off |
| `eliminate_tail_recursion` 0x10712b1a | /Og | Self tail calls become parameter copies plus a jump |
| `optimize_flow_graph_initial` 0x107053de | /Og | **Reverse-postorder block order**, loop inversion, loop compaction, preheaders |
| `optimize_expression_trees` 0x1070fc45 | /Og | Simplifier. **Commutative operands are sorted by packed cost** |
| `purge_unreferenced_temps` 0x1070fcda | /Og | Frees dead temps. Their ids are reused LIFO |
| `cfg_dfs_rpo`, `mark_constant_branch_dead_edges`, `warn_missing_return_value`, `warn_uninitialized_locals` | always | Diagnostics only |
| `globopt_run` 0x107130cb | /Og | Copy coalescing, forward substitution, value numbering, CSE, loop invariants, IV and strength reduction |
| `pass_narrow_byte_lanes` 0x107281cd | always | AL/AH narrowing |
| `pass_mark_register_candidates` 0x107284d8 | /Og | Register candidates |
| `pass_form_read_modify_write` 0x10728587 | always | `op [mem], y` |
| `pass_sizeopt` 0x107285f0 | always | Zero-extension and width choices |
| `pass_remove_redundant_branches` 0x10728ee5 | always | Jump-to-next and dead labels |
| `pass_if_convert` 0x1072906a | always | `sbb`/`setcc` selects |
| `pass_strength_reduce_mul_div` 0x107290aa | /Og | lea/shift multiply chains, magic divide |
| `pass_select_address_modes` 0x1072930f | always | **lea vs add**, SIB forms |
| `pass_merge_return_tails` 0x107294f3 | /Og without /Ot | Cross-jumping before the exit label |
| `pass_lower_function` 0x10729511 | always | IL → x86 opcodes, switch, intrinsics, x87, `__int64` |
| `assign_parameter_homes` 0x107296de | always | fastcall/thiscall registers, stack parameter offsets |
| `pass_machine_peephole` 0x1072c2e5 | /Og | inc/dec, `test`, load folding |
| `cfg_rebuild`, `cfg_reanalyze` 0x10706210 | always | Rebuild after lowering |
| `duplicate_exit_block_into_predecessors` 0x10727731 | /Ot | Return blocks of ≤2 instructions copied into predecessors |
| `build_live_ranges` 0x10726d75 | always | Webs and live ranges |
| `choose_frame_pointer_mode` 0x1072f8fc | always | FPO and 8-byte aligned frames |
| `global_color_registers` 0x1072fb58 | always | **Callee-saved and global register choice** |
| `local_color_registers` 0x107336f4 | always | **eax/ecx/edx rotation** for short temps |
| `split_memory_operands_g5` 0x107337ec | /Og and /Ot | /G5 memory-operand splits |
| `stack_frame_layout_pass` 0x10733b7b | always | **Local variable offsets** |
| `compute_frame_size`, `generate_prolog_epilog` 0x1073404f | always | Push order, `__chkstk`, `leave` |
| `jump_optimize` 0x10735042 (first run) | unless function flag 0x800 | Jump threading. No cross-jumping yet |
| `final_lowering_peepholes` 0x1073536c | always | `push ecx`, `xor r,r`, `or r,-1`, `pop ecx` |
| `jump_optimize` (second run) | /Og | **Tail sinking, cross-jumping, head hoisting** |
| `block_mover` 0x1073663c | /Og | **Block moves and small-block duplication** |
| `coalesce_label_runs`, `remove_dead_labels`, `remove_unreachable_after_terminators`, `late_register_value_cse` | /Og | Cleanup |
| `schedule_instructions` 0x107374aa | /Og | **Instruction order within blocks** |
| `post_schedule_merge_moves`, `late_stack_temp_forwarding` | /Og | Late peepholes |
| `compute_esp_depth_adjustments` 0x1073e945, `lower_switch_pseudo_ops` 0x1073eb93 | always | esp depths, jump tables |
| `emit_function` 0x1073ebea | always | Encoding, branch sizing, /O2 padding |

Without `/Og` the flow graph is built only for the warnings and then collapsed by
`cfg_reset_single_block` 0x10704d75. Block order then stays source order.

## Rules that most often explain a mismatch

This is a digest; the detailed notes give the evidence and exceptions.

- **Block order** (optimizer.md): under /Og the physical order is the reverse postorder of a DFS that
  explores the most recently created edge first. Structured code keeps source order. Blocks reached only
  from later code move. Top-tested loops are rotated, with the test copied to the bottom. Branch polarity
  follows which block is physically next, not how the condition is written.
- **Late layout** (layout.md): tail sinking and cross-jumping come only from the second jump optimizer.
  The block mover's second loop pulls single-entry targets to their jump site. It also copies target
  blocks of up to 20 bytes (/Ot) or 2 bytes (/Os). That is how /O2 duplicates epilogues.
- **Operand order** (optimizer.md, lowering.md): commutative operands are sorted by
  `need<<24 | size<<16 | hash16`, and constants go last. Ties depend on symbol ids, so an unrelated
  temporary or declaration can swap a SIB base and index.
- **Registers** (regalloc.md): a variable not live across a call usually gets eax, ecx or edx from the
  global allocator. Calls push ranges into esi, edi, ebx and ebp. Priority grows with references and
  loop depth, and falls with every busy block a range lives through. Declaration order acts only through
  ids and the tie key, which is the definition position.
- **Local offsets** (frame.md, frame-model.md): locals are sorted by size, then by reference count,
  counted after register allocation with no loop weighting. Calls add no references; inline-asm
  blocks do. Frames over 0x80 bytes are re-sorted by density with an unstable quicksort. Dead
  parameter homes are reused. /Od uses declaration order. `scripts/c2/frame_predict.py` reproduces
  the compiler's own layout for a scratch.
- **Instruction order** (layout.md): scheduling is local to a basic block, with an 81-node window. The
  priority is height×8192 plus load and float-store bonuses, and ties keep the original order.
  x87 instructions all write ST(0), so the scheduler never reorders them. Their order comes from
  the expression sort, forward propagation and lowering ([x87-scheduling.md](x87-scheduling.md)).
- **/O1 versus /O2** (frame.md, lowering.md, layout.md): `leave`, `pop ecx` cleanup, `movzx`, `idiv`
  for constant divisors, and always cross-jumping mark /O1. `mov esp,ebp`, `xor`/byte-`mov`
  zero-extension, magic divides, 16-byte padding and duplicated epilogues mark /O2.

## Relation to earlier notes

The deep reading corrects several earlier readings:

- Snail-mail's `global-allocation.md`: under /Ot each reference saves 2, not 1. The pressure P counts
  candidates referenced in a block, not those live in it. Live ranges are built by 0x10726d75.
- Snail-mail's tools label 0x107ac058 as the /G5 split flag. It is /Og.
- Crimson's `expand_constant_multiplies` 0x107281cd narrows byte lanes. Multiplies are
  `pass_strength_reduce_mul_div` 0x107290aa.

[regalloc.md](regalloc.md) lists all the corrections to earlier notes.
