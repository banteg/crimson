# C2.DLL (VC6 build 8966): frame layout, prolog/epilog, late lowering, EH, x87

Everything here comes from static reading of HLIL and disassembly in the shared read-only DB. Confidence is
given per claim: **[H]** means the code path was read end to end, **[M]** means the structure is clear but some
inputs were not traced, and **[L]** means the role is inferred. Addresses are VAs (base 0x10700000).

## 1. Frame layout (stack.c)

### 1.1 Which layout path runs: `stack_frame_layout_pass` 0x10733b7b [H]
- `-ZI` (0x107ac008): with `-ZX` (0x107ac00c, ENC recompile) the pass uses `enc_layout_frame_reusing_locals` 0x107937f8. That path reads the previous locals from the PDB with FSGetEnumLocals, SVName, SVTypeIndex and SVOffBP, matches each local by name and type index, and keeps its old `[ebp-x]`. Without `-ZX` it uses `zi_layout_frame` 0x10793797. Both paths add **0x40 bytes of ENC padding** (`reserve_enc_frame_padding` 0x107937b5, stored at fsym+0x3e). The ENC padding is the old-minus-new frame size when that is non-negative, otherwise 0x40.
- The unpacked path is `assign_temp_homes_in_reference_order` 0x1075ea65. It runs when any of these holds: `!/Og`, the function symbol has flag 0x1000 (contains `__try`), `-dlp` is set, or the function has a C++ `try` (fn flag 0x10000) and `/GX` is off.
- Every other function goes through `pack_frame_locals` 0x10733bf8.
- After packing: a function with fn flag 0x10000 also runs `assign_eh_object_homes` 0x10789791, and one with fn flag 0x8000 also runs 0x1076089a.

### 1.2 The unpacked (/Od) layout [H]
- Autos get a home as soon as their "sym il" record is read (`read_function_symbols` 0x107418a4 → `fe_symbol_assign_frame` 0x107011e1). The order is therefore the **symbol-stream (declaration) order**. Each auto takes `align_up(size,4)` bytes, so a `char` sits at `[ebp-4]` and the first declared local is closest to ebp.
- Params get homes from cursor 0x107ac10c, which starts at 8. It starts at 0xC instead when fsym+0x14 bit 2 is set, or under a cpu==6 rule (0x107ac324); what that case means is unconfirmed. Param offsets are rounded to `-isize#` (0x107ac328, 4). fsym+0x42 holds the total parameter bytes (0x107296de), and that value becomes `ret N`.
- Compiler temps (class 3) are homed by 0x1075ea65 in **first-reference order**: blocks in list order, tuples in order, source operands before destinations. They are placed below the autos. A double temp is 8-aligned only in an aligned frame (flag 0x600000).
- The EH or SEH record (0x10799020) is always homed at the top of the frame. Callback 0x107675d9 shifts the existing autos down by the size of the record.

### 1.3 The packed (/Og) layout [H]
`init_frame_layout_state` 0x10733d67 resets the frame cursor to 0. It then homes the EH record (0x10799020) first, and after it the `!/GX` guard local 0x1079bd90. It clears the "homed" bit on every auto and collects the params.

**Reference counting** (`count_stack_object_references` 0x10733e75 → `order_stack_object` 0x1073c7e4):
- Operands are walked in block-list order, *before the block mover runs*. Within each real tuple the source list is walked before the destination list.
- Operand kinds that count:
  - kind 2/3 (symbol) → sym+8 (the owning stack object);
  - kind 5/6 memory → +0x20 frame object;
  - kind 11 call-effect operand of a call tuple (kind 0x15) → **every member of its alias set** (address-taken locals).
- Only objects of class 3 (temp), 4 (named local) and 5 (param) are counted. Every reference adds 1; **loop depth is not used**.
- List order:
  - Size is ascending (+0x20).
  - An object seen for the first time is appended at the end of its size group with count 1.
  - On a repeat reference the count goes up by 1 and the object moves toward the head past same-size predecessors whose count is **strictly smaller** (0x1073c876).
  - Result: within one size, order is count descending. Among equal counts, the object that reached that count first in walk order wins. This is not simply first-reference order.
- Objects that are never referenced get no slot.

**Liveness and interference** [M] (0x1074ac4c, 0x1074b107):
- This is standard backward liveness per block. At each definition, `interf[def] |= live`, recorded in one direction only.
- All params interfere with each other.
- An object with flag +6 bit 0x04 (conflicts with everything) gets all bits set.

**Packing** (`pack_stack_slots` 0x1074b617), slot records are `c2_stack_slot` 0x14 bytes. Steps in order:
1. Each param gets its own slot. The slot size is the param size rounded to 4, and the slot offset is the param's home.
2. Each non-param object, in list order:
   1. It first tries the **param slots**, oldest first. It joins if `obj.size <= slot.size`, the object is not in the slot's interference set, and no member of the slot conflicts with the object. **Dead parameter homes are reused for locals.** This step is skipped when fn flags include 0x40 or 0x600000.
   2. Otherwise it goes to `join_or_create_stack_slot` 0x1074bae6. That routine scans the local slots from newest to oldest and joins the first slot where `obj.size <= 2*slot.size` and there is no conflict in either direction. On a join, weight += count and size = max. If no slot fits, it creates a new slot.
3. `arg2` means FPO or aligned frame (fn flags 0x10 or 0x600000). If `arg2` is set, some local reused a param slot, and the raw local bytes are ≥ **0x70**, all slots are thrown away and the packing is redone **without** param reuse.
4. If the raw sum of local slot sizes is > **0x80**, the local slots only (the param slots keep their place) are sorted with `sort_stack_slots_by_density` 0x10761bf0. The key is `weight*1000/size` descending, using an unstable K&R quicksort (middle pivot, strict `>`).
5. Offsets:
   - **ebp frame** (arg2=0): slots are taken in index order 0..n-1. Each gets `frame_alloc_local(size,0)`, so slot 0 is closest to ebp. A member smaller than its slot sits at the **high end** of the slot: offset = `-align(-(slot_off+slot_size-obj_size))`.
   - **FPO or aligned frame**: slots are taken from n-1 down to 0. Each gets `frame_alloc_local(size, align)`, where `align` is 8 when an aligned frame holds a double and 0 otherwise. Slot 0 ends up lowest, at `[esp+0]`. Every member sits at the slot base.
6. Alignment (`align_frame_offset` 0x10703f7b):
   - size 1: no alignment;
   - size 2: 2-byte alignment;
   - any other size: 4-byte alignment (the default 0x107ac0f4).
   - **Doubles are only 4-aligned** unless the frame is aligned.
7. Frame size is set by `compute_frame_size` 0x10734032: fsym+0x5b = `align_up(-cursor, 4)`.

The snail and crimson notes agree with this. Two refinements: the tie-break rule within a size group, and the fact that call alias sets add references.

## 2. Frame-pointer decisions [H]

**FPO** (`choose_frame_pointer_mode` 0x1072f8fc, which runs before global colouring):
- FPO (fn flag 0x10) is set when all of these hold: `/Oy` is on; fn flags have none of 0xc1; the function has no `__try` (fsym flag 0x1000); it has no C++ `try` (0x10000).
- An **8-aligned frame** (0x600000) is considered only under `/Og` and `/Ot`, for a function that uses FP (flag 8) and does not have flag 1.
  - The score is 3 × (weighted count of `double` accesses through esp-based memory) plus the weighted count of other double accesses. Weights come from `0x107638c8(10, loop_depth)`.
  - The frame is aligned when score ≥ 0xfa, or when score > 0xf and no double parameter is read.
  - An aligned frame that also has params used as doubles drops FPO.
  - The aligned prolog emits `and esp,-8`, pads `sub esp` so that (pushes + frame) is a multiple of 8, and addresses locals relative to esp.

**/Os FPO veto** (`choose_fpo_for_size` 0x10734011 / 0x1076b7d5): this applies only under `!/Ot` and only when ebp is not in use as a general register. It counts the esp-relative frame operands (0x14a/0x14e). FPO is dropped when the count is > 1 for a function with locals, or > 4 for one without. The thresholds match byte cost: each esp access pays for a SIB byte.

**ebp frame in the prolog** (0x1073404f):
- Every function gets an ebp frame under `!/Og`.
- Under /Og an FPO function has no frame. Otherwise the function is framed when any of these holds:
  - it has locals (fsym+0x5b ≠ 0);
  - it has fn flags 0xc0 or 0x100000;
  - it has params (fsym+0x42) and `function_references_ebp` 0x1076b595 is true.

## 3. Prolog and epilog: `generate_prolog_epilog` 0x1073404f [H]

**Prolog order.** Each item is inserted after the previous one:
1. `push ebp; mov ebp,esp`. If fn+0x28 > 0 the second instruction is `lea ebp,[esp-bias]` instead. An aligned frame adds `and esp,-8`.
2. SEH prolog (`seh_emit_prolog` 0x10767a37): `push -1; push scopetable; push __except_handler3; mov eax,fs:[0]; push eax; mov fs:[0],esp; sub esp,8`.
   - The C++ EH prolog (`cxx_eh_emit_prolog` 0x107608cc) goes here instead when the function has C++ EH:
     - under `!/Ot`: `mov eax,__ehhandler; call __EH_prolog`;
     - under `/Ot`: `push -1; push __ehhandler; mov eax,fs:[0]; push eax; mov fs:[0],esp`, plus `sub esp,4` when a `try` needs the saved-esp slot.
3. Frame allocation: size = fsym+0x5b minus the bytes of the EH record that the prolog pushed (0x10799010).
   - `mov eax,N; call __chkstk` if `/Ge` (0x107ac0bc) is on or N ≥ `/Gs#` (0x107ac0fc, default **0x1000**). A VB function calls `___vbaChkstk` instead.
   - Otherwise `sub esp,N`.
   - The prolog never emits `push ecx` itself; finlower converts it later (§4).
4. A function with SEH, a C++ `try`, or built with -ZI **always saves ebx, esi and edi**, because they are marked dirty.
5. `/GZ` (ICE if /Og is also set), via `emit_gz_stack_fill` 0x1076acee. The fill value is `-stkfill#`, default 0xCCCCCCCC.
   - fewer than 16 bytes: one immediate store per dword;
   - fewer than 40 bytes: `mov eax,imm` followed by dword stores;
   - otherwise: `lea edi,[ebp-N]; mov ecx,N/4; mov eax,imm; rep stosd`, wrapped in `push ecx`/`pop ecx` for fastcall and thiscall functions.

   The fill sequence is inserted at the same point as the pushes, so it ends up **after** them.
6. Callee-saved pushes (`emit_callee_saved_pushes` 0x10734f8b):
   - The order is **ebx, ebp, esi, edi**, for each register that is in mask 0x10799014 (0x1d0) and whose descriptor+5 bit 0x10 (dirty) is set.
   - Under /Og, with no aligned frame, no SEH, no C++ try and no fn flags 0xc0, `shrink_wrap_callee_saves` 0x10734647 first **moves push/pop pairs to the blocks where the register is actually used**, so pushes can appear after early-exit tests. [M]
   - The pushes are opcode 0xba `_epush` and the pops opcode 0xb9 `_epop`; the esp-depth tracker uses these opcodes (0x1073e9e2).
7. After the pushes: the SEH prolog saves esp with `mov [ebp-0x18],esp`, or the C++ EH prolog with `mov [ebp-0x10],esp` when a `try` is present.

**Epilog order** (inserted before the block's return tuple, kind 0x18):
1. EH unlink: `mov ecx,[rec.next]; mov fs:[0],ecx`.
2. If fn flag 0x80: `lea esp,[ebp-frame-4*npushed]`.
3. Pops: edi, esi, ebp, ebx.
4. `/GZ`, only when fn flag 0x200 or 0x1 is set and flags 0xc0 are clear: `add esp,N; cmp ebp,esp; call __chkesp`. Flag 0x200 probably means the function makes calls, and 0x1 probably means inline asm; both are inferred.
5. Frame teardown:
   - no locals: `pop ebp`;
   - `!/Ot`: **`leave`**;
   - `/Ot`: `mov esp,ebp; pop ebp`;
   - a function without an ebp frame instead ends with `add esp,N`.
6. `ret N`: N = fsym+0x42 when the calling-convention bits (fsym+0x14 & 0x1c) are set, otherwise 0.

**Per-function options** (`apply_function_optimize_flags` 0x1071bc73, reflects `#pragma optimize`):
- `/GZ` and `-ZI` both force `/Og` and `/Oy` off.
- `-dlp` forces `/Oy`, `/Oa` and `/Ow` off.

## 4. Final lowering: `final_lowering_peepholes` 0x1073536c (finlower.c) [H unless noted]

One pass over the tuples. It dispatches on opcode through two byte tables:
- 0x1073b88c: opcodes 1..0x5f;
- 0x1073b900: opcodes 0x63..0x118.

`var_44` records "a flags consumer is live" (the tuple references symbol 0x107adcd8). A live flags consumer blocks the conversions that clobber flags.

**mov** (opcode 1):
- `mov r,0` → `xor r,r`.
- `mov r,-1` → `or r,-1`.
- `mov a,b` followed by `mov b,a`: the second move is removed.
- A self-move is removed.
- Under `!/Ot` only:
  - `mov r,imm` that fits in 8 bits → `push imm; pop r`;
  - `mov [m],0` → `and [m],0`;
  - `mov [m],-1` → `or [m],-1`.

**sub/add esp**:
- `sub esp,4` → **`push ecx`** under both /O1 and /O2.
- `sub esp,8` → `push ecx; push ecx` under `!/Ot` only.
- `add esp,4` immediately before a `ret` → `pop ecx`.
- An adjacent opposite pair (sub then add, or add then sub) is merged.

**call**:
- Under `!/Ot`, an `add esp,4` right after the call → `pop ecx`, and `add esp,8` → `pop ecx; pop ecx`. Under `/Ot` the `add esp,N` stays.
- **Tail call** under /Og: `call f` → `jmp f`. Conditions:
  - the call tuple's +0x20 is 0;
  - `ret 0` follows the call;
  - between them there are only no-op moves or 0x19e markers, or up to 5 unconditional jumps;
  - no label intervenes.

**inc/dec** (0x107667f3): `add/sub r,±1` → `inc/dec`. `±2` becomes two inc/dec only under `!/Ot`.

**Identity operations** (0x107365d8): `add/sub/or r,0` and `and r,-1` are deleted when their flags are dead.

**lea**:
- `lea r,[r+1]` → `inc r`, `lea r,[r-1]` → `dec r`, `lea r,[r+d]` → `add r,d`.
- `lea r,[r+x]` or `lea r,[x+r]` → `add r,x`.
- `lea r,[i*2^k]` with no displacement, where k ≥ 2:
  - i == r → `shl r,k`;
  - i ≠ r and `!/Ot` → `mov r,i; shl r,k`;
  - otherwise the lea stays.

**cmp/test/movzx**:
- `cmp r,0` → `test r,r`.
- When `/G6` or `/Ot` is set and the source does not read r: `movzx r,x` → `xor r,r; mov r8,x`. This is the classic VC6 byte load.
- Narrowing of and, or and test [L], via 0x1073ddac and 0x10743b11. It does not run under `/G6`.

**x87**:
- `fst m; fstp st(0)` → `fstp m`.
- `fcom m; fstp st(0)` → `fcomp m`.
- `fmul [2.0]` → `fadd st,st` (constant 0x10799400).
- An arithmetic op followed by a pop becomes the pop form (0x10764040).
- `fld a; fld b; fxch` → the two loads are swapped (0x107772a5).
- **`fstp m; fld m` → `fst m` only when `/Op` is off** (0x10735f14). Under `/Op` the round-trip store and reload stay.
- `sahf` → `test ah,mask` under **/Ot only** (0x10764420). The mask is 0x40, 0x41 or 0x01 with je/jne. Under /O1 the `sahf; jcc` form stays.

## 5. x87 stack model (fppeeps.c 0x1076xxxx, lowerflt.c) [M]

**Lowering** (`lower_x87_tuple` 0x10762fc3):
- Stack depth is tracked in 0x1079903c, where -1 means empty and 7 means full; a full stack spills through 0x1076ea17.
- Float to int: `/QIfist` (0x107ac088) emits `fistp dword tmp` inline. Otherwise, and always for 64-bit results, it emits `call __ftol`.
- Unsigned or wider ints are stored to a temp (with a zero high dword when needed) and loaded with `fild qword`.
- `/Op` inserts a consistency store after the result lands in a variable.
- `lower_float_move_as_integer` 0x10763761, under /Ot only: float copies, argument pushes and compares against 0.0 are done with integer moves, provided no register temp is involved.

**Scheduling** (`x87_block_fxch_scheduling` 0x107392c7), which runs from local register allocation only under /Ot and only in functions that use FP:
1. `x87_simulate_stack_ids` 0x107638e0 gives every stack value an id for each block.
2. `x87_rewrite_stack_operands` 0x10766381 **deletes the existing fxch**, recomputes st(i), and inserts `fxch` (0x107664e9) only where an operation needs its operand in st(0).
3. `x87_restore_stack_order` 0x107664fc restores the entry order at the end of the block with pairs of fxch.

An inserted fxch is placed after the previous FP tuple, call, branch, label or `fistp`, but never directly after the round marker 0x162. Under /O1 this whole pass does not run, so the source's fxch placement survives.

## 6. Exception handling

**SEH** (except.c and ehgen.c; the ehgen.c setup below runs only when fsym flag 0x1000 is set) [H/M]:
- `seh_create_record_and_scopetable` 0x10767498 creates `__$SEHRec`, 0x18 bytes:
  - `[ebp-0x18]` saved esp;
  - `-0x14` xpointers;
  - `-0x10` next;
  - `-0xc` handler;
  - `-8` scopetable;
  - `-4` trylevel.

  It also creates the scope table: 12 bytes per level, {enclosing, filter, handler} (0x10767513).
- `seh_mark_try_region_memory_ops` 0x107623c3 forces stores to memory inside `__try`: operand +0x11 bit 8.
- `seh_lower_pseudo_op` 0x10767609 writes trylevel to `[rec+0x14]` and emits `__local_unwind2`.

**C++ EH** (ehexcept.c) [M/L]:
- The record `__$EHRec` is 0xC bytes, or 0x10 with a saved-esp slot when the function has a try (0x1076052f). The state field sits at `[ebp-4]`.
- The EH tables go to `.xdata$x` (EHDATA), and the funclets to `.text$x` (EHTEXT).
- **State numbering** (`push_eh_state` 0x1075f8d9): states count from 0 in IL walk order; the counter resets per function. Each new state's toState is the enclosing state, or -1.
- The unwind map is 8 bytes per state (0x10760ce0).
- **State stores** (`insert_eh_state_store` 0x107606d5) use `mov byte ptr [ebp-4],n` when all of these hold:
  - the previous state is known, not -2;
  - (old XOR new) & 0xffffff00 == 0;
  - old ≠ 0, or guard object 0x1079bd98 is absent;
  - the old state's flag bit 0x100 is clear.

  Otherwise the store is `mov dword ptr [ebp-4],n`.
- Names: `__ehhandler$`, `__ehfuncinfo$`, `__unwindtable$`, `__tryblocktable$`, `__catchsym$f$N`, `__unwindfunclet$f$N`, `__unwind$`, `__tryend$`, `__sehtable$`. **Every one of these name strings is used only with -ZI.** Without -ZI the symbols stay anonymous (compiler temps). [H for the gating]

## Matching implications
1. **The order of stack offsets comes from reference counts, not from declarations.**
   - Size groups go in ascending order.
   - Within a size, the higher count goes first.
   - Ties go to whichever object reached the count first.
   - Call alias sets add a count to every address-taken local on every call.
   - One extra read, or one extra call while a local's address is taken, can reorder every offset.
2. **Small frames (raw local bytes ≤ 0x80) are not sorted.** In an ebp frame the smallest objects sit nearest ebp, and arrays and structs sit at the most negative offsets. In an FPO frame the order is the mirror image, so the first slot is at `[esp+0]`.
3. **Large frames are sorted by density.** The sort is unstable, so reproducing it needs the exact quicksort (0x10761bf0).
4. **Locals can live in dead parameter homes** (`[ebp+8]`, `[esp+N+4]`). In FPO and aligned frames this reuse is undone once local bytes reach 0x70.
5. Sharing a slot needs size ≤ 2× the slot size. A smaller member sits at the high end of an ebp slot but at the base of an esp slot.
6. **/Od layout** follows declaration order, with every auto rounded up to 4 bytes.
7. **Callee-saved push order** is ebx, ebp, esi, edi. Under /Og the pushes can be shrink-wrapped away from the entry. SEH functions, functions with a C++ try, and -ZI builds always push ebx, esi and edi.
8. **/O1 versus /O2 epilog and call cleanup.** /O1 uses `leave`, `pop ecx` for call cleanup, `push imm8/pop r`, `and [m],0`, `sahf`, and `__EH_prolog`. /O2 uses `mov esp,ebp/pop ebp`, `add esp,N`, and `fnstsw ax; test ah,..`. `sub esp,4` → `push ecx` happens under both.
9. **`__chkstk` appears at 4096 bytes of locals and above** (a frame of exactly 0x1000 already gets it). `/GZ` fill thresholds are 16 and 40 bytes.
10. **The FPO choice under /Os depends on the number of esp-relative references.** More than one reference in a function with locals switches it to an ebp frame.
11. **`/Op` keeps `fstp m; fld m` pairs**; without `/Op` they collapse to `fst m`. `/QIfist` removes `__ftol`. Under /O2 the fxch placement comes from the x87 rescheduler, not from the order of the source expression.
12. **EH state writes use a byte store** when only the low byte changes from a known state. A write of -1, or any write from an unknown state, is a dword store.

## Open questions
- The meanings of fn flag bits 0x1 (set by IL op 0x191, probably inline asm), 0x40 (intrinsics 0xdb and 0x11e), 0x80 and 0x200 (probably "makes calls") are inferred, not traced.
- The exact interference rule for partial definitions: `edi_4 == ebp_4` at 0x1074b45e, which kills a variable only on a whole-object def.
- The C++ EH lowering passes 0x1075f30e, 0x1075f970, 0x1075fa91 and 0x10760276 were only skimmed.
- The internal jcc condition numbering used by `sahf_to_test_ah` was not mapped.
- 0x1073c534, the add/sub constant merger in finlower, was not read.
- In `frame_object_base_adjust` 0x1073c8dc, the meaning of the return value 4 is unclear.
