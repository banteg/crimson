# C2.DLL register allocation, end to end

Covers C2.DLL 12.00.8966 (image base 0x10700000). All addresses are VAs. Unless marked *(inferred)* or *(uncertain)*, each statement comes from reading the HLIL or disassembly. Annotations are in [`analysis/binary_ninja/c2`](../../../../analysis/binary_ninja/c2).

The flag names used below:
- `/Ot` means `[0x107ac0b4]`. The snail notes call it "/O2".
- `/Og` means `[0x107ac058]`. The snail notes call it "g5 split enabled", which is wrong.
- `/Oy` means `[0x107ac054]`.

## 0. Corrections to the earlier snail and crimson notes

| Earlier claim | What the code shows |
|---|---|
| 0x10730308, 0x107306c1 and 0x10730a40 are "live-range builders a/b/c" | Live ranges are built earlier, by **0x10726d75** (webs, through 0x1072f55d → `new_live_range` 0x10723758). Constant candidates are built by 0x10727f41. The three functions do other jobs: 0x10730308 coalesces copies, 0x107306c1 forward-substitutes single-def ranges, and 0x10730a40 initialises per-block register sets. |
| A read or write saves 1, and a store saves 1 or 2 | Under /Ot, **every non-constant reference saves 2**: 0x10725751 and 0x107254dc both return 2, and a spill or reload costs 2. Constants save 1 per load, and 0 or 1 when folded into the instruction. Without /Ot, all of these values are byte counts (see §3.5). |
| The pressure P counts candidates "referenced or live" in the block | P counts only the distinct candidate ranges **referenced** in the block: coloured ones, queued ones, and fresh ones. A range that is live through the block does not add to P, but it is charged −P·w there. |
| 0x10762f4a spills | It **splits** a range whose allowed set is empty: it places split markers and returns {id}. The next loop iteration splits the range with 0x107204d6. |
| 0x10732216 splits | It **builds the interference neighbour set** for the chooser and inserts pressure split markers. It does not split anything itself. |
| 0x107ac190 and 0x107ac194 are masks for "flagged ranges" | They are the **byte-register set {eax,ecx,edx,ebx}** and the **non-byte set {ebp,esi,edi}**. |
| 0x10726d75 is "assign_symbol_homes / demote temps" (crimson) | It is the web and live-range builder. Kind-1 operands with the placeholder home 0x107ae040 are rewritten to `c2_live_range*`. |
| 0x10730a40 lowers float copies to mov (crimson) | That change happens in 0x1072fef2, the x87 fld/fstp folding, which runs between the same two hook points. 0x10730a40 only allocates block bitsets. |

The rest of the snail chooser, queue and rotation description checks out exactly. Details are added below.

## 1. Pipeline

The driver is 0x10757fc2. The steps in order:

1. **0x10727731 `duplicate_exit_block_into_predecessors`** (fg.c:7499). This runs only under /Ot.
   - It takes `fn->blocks->last->prev`, the real exit block.
   - That block must start with a label. Its last real tuple must not be a branch (kind 0x11) or a switch (kind 0x13).
   - Its tail must have **≤2 real tuples**. Opcode 0x19e is not counted, and a call (kind 0xe) or kind 0x15 aborts the pass.
   - No predecessor may end in kind 0x13 or carry flag bit 8.
   - Condition: **#preds × tail_len ≤ 8**.
   - When it applies, the tail is cloned (0x10714605) onto the end of every predecessor. A conditional-branch predecessor gets an edge block first (0x10726481 or 0x10711198). The last predecessor receives the original list.
   - *Matching:* a short `return x;` tail really is copied into each branch before allocation. Each copy consumes local rotation slots, even when the jump optimiser later cross-jumps the copies back into one tail. This explains the "invisible slot" in the snail `update_subgame` notes.
2. **0x10726d75 `build_live_ranges`** (color.c). See §2.
3. **0x1072f8fc `choose_frame_pointer_mode`**. See §5.
4. **0x1072fb58 `global_color_registers`**. See §3.
5. **0x107336f4 `local_color_registers`** (regasg.c). See §4.
6. **0x107337ec `split_memory_operands_g5`**, gated by the driver on /Og and /Ot. See §4.4.
7. The stack frame is laid out next. Then **0x10734032 `compute_frame_size`** sets `fnsym+0x5b = align_up(-lowest_offset, align)`, and **0x1073404f `generate_prolog_epilog`** runs (§5).

## 2. Building candidates and webs (0x10726d75)

`build_live_ranges` also re-examines kind-2 operands created by lowering. It inserts store-backs
(0x1072f6cc) when stored bytes are later read as memory (another typed view, an indirect read or a
call alias), for volatile operands, and for parents with `flags6 & 1`, and returns overlapping typed
views and escaped locals to memory ([post-promotion-stores.md](post-promotion-stores.md)).

1. The class register sets are initialised once (0x10757353):
   - class 0 (integer) = {eax,ecx,edx,ebx,ebp,esi,edi}
   - class 1 (x87) = {}
   - byte = {eax..ebx}
   - non-byte = {ebp,esi,edi}

   The class of a value comes from `0x107a09bc[type>>12]`. Type nibbles 1,2,3,5,7 map to 0, and nibble 4 (float) maps to 1.
2. **0x1072795a / 0x10727f41 turn constants into candidates.** For each eligible instruction (0x10727e73 excludes imul2/imul3, shld/shrd, `ebp`/`esp` destinations and some zero forms), each immediate or address-constant source operand is replaced by a class-0xd constant symbol. There is **one symbol per distinct value**, found through the hash `0x1079d750[value%64]`, and its live range is created at once. This produces the hoisted `mov edi, 1`.
3. **0x10727bd3** numbers the promotable symbols. These are temps, locals and params, subject to size and overlap tests; float types are excluded under /Op. Each gets a 0x18-byte `c2_candidate_info` at `sym+0x30`.
4. **Liveness.** 0x1072707a computes per-block sets (+0x2c referenced, +0x30 upward-exposed, +0x34 defs). 0x10726fc6 iterates to live-in (+0x40) and live-out (+0x44).
5. 0x1072e5b9 and 0x1072e7cb insert 0x163 **reloads** at upward-exposed uses, loop boundaries and edges. Their exact placement rules were not fully traced.
6. **Webs.** 0x1072ed0d numbers the defs per symbol and unions defs that reach a common use (0x1073168d). 0x1072f55d then creates **one live range per web**. *Matching:* reusing one C variable for unrelated values gives independent ranges, which may receive different registers.
7. **Operand rewrite and tie key.** The rewrite loop walks blocks forward and tuples **backward** within each block, keeping a running ordinal of real tuples. Every placeholder kind-1 operand becomes its web's range. For **destination** operands it also sets `lr+0x40 = ordinal`, and the last write wins (0x1072f667). The resulting tie key is highest for:
   - the def in the latest block, in layout order;
   - within that block, the earliest def.

   The snail observation "target0 = 41, target1 = 40, target2 = 39, `this` = 10" matches this rule. Split pieces copy the tie key of their parent (0x107211b8).

## 3. Global colouring (0x1072fb58)

### 3.1 Driver

1. Reset state. Then run 0x10730308 (coalesce copies), 0x107306c1 (forward-substitute single-def ranges) and 0x10730a40 (per-block register bitsets).
2. If there are no candidates in either class: set `g_no_global_candidates` (0x107ae098), run the x87 fold 0x1072fef2, and return.
3. Otherwise run 0x1072fef2. When there are float candidates, or loops qualify for x87 caching, run 0x107645d8 first.
4. Run 0x1072f8fc again, because the instructions have changed.
5. Compute `k` = 0x10730a91: 7 if ebp is allocatable, otherwise 6.
6. For each class, x87 (1) first and then integer (0):

   ```
   splits = mark_register_pressure_splits(fn, cls, k)          // 0x10730ab7
   score_live_ranges(fn, cls, cands)                           // 0x10724b25
   prune_low_use_live_ranges(fn, cls, cands, splits)           // 0x10725b42
   empty = build_colour_queue(fn, cls, empty)                  // 0x10733569
   loop over queue head lr:
     if pending split set: remove flagged from queue (0x1072049c), split at markers (0x107204d6),
        rescore (0x10724b25), prune, requeue pieces (0x1072158f), recompute last-use flags
     pop lr
     if benefit<0 or (benefit==0 and !(single block && non-const && refs>2 && /Ot)):
         set = handle_unprofitable_live_range(lr)              // 0x10732001
     elif lr substitutable (+5&4==0) and try_substitute (0x10752624): requeue with prio=min(related)-1
     elif allowed empty: set = split_uncolourable_live_range(lr)   // 0x10762f4a
     else: nb = new set; mark lr processed
           set' = build_interference_and_pressure_splits(fn, lr, cls, nb, processed, k)  // 0x10732216
           choose_register_for_live_range(lr, cls, nb)         // 0x10732f7c
           set = propagate_colour_to_neighbours(fn, cls, lr, nb, set')                   // 0x10733230
   ```
7. Finally run **0x107388f3 `rewrite_live_range_operands`**. It deletes split markers, replaces each range home with `reg_find_subreg(reg, size*8, offset*8)`, and turns reloads (0x163) and spill stores (0x164) into `mov`.

### 3.2 Register pressure and frame pointer (0x10730ab7)

The pass walks each block backward over the class ranges and sets the last-use flag (operand `+0x11` bit 0x10). A def with no later use gets a 0x19e marker. Byte references set `lr+5` bit 0x80.
- If pressure exceeds `k`, 0x1078eafe splits a local temp across the hot point.
- If pressure equals `k`, 0x10721b26 inserts a split marker (kind 0x1b) holding the set of live ranges. The returned set flags those ranges with `+5|=2`.
- It can **undo frame-pointer omission** (§5).

### 3.3 Allowed sets and constraints

- **Start:** the class set (0x107237c8).
- **0x10731cc5, called before queueing:**
  - A byte range gets `allowed &= {eax,ecx,edx,ebx}`.
  - Otherwise ebp is dropped unless it is allocatable.
- **During scoring (0x10724b25):**
  - A call's clobber operand (kind 0xa) removes the clobbered registers (eax, ecx, edx) from every range live across it. A range whose last use is the call itself is unlinked before the clobber is processed, so it keeps them.
  - An explicit physical-register use or def (for example `eax` return values, `ecx` for thiscall, `edx:eax` for div/mul, `cl` for shifts) removes that register from every range live at that point. The `mov reg, lr` or `mov lr, reg` partner range is exempt and gets a preference instead.
  - Registers already held by coloured ranges are removed at each reference.
  - I did not trace which lowering routines emit the fixed registers. They appear as ordinary kind-1 operands whose home is a register descriptor.
- **After each colouring (0x10733230):** the chosen register is removed from every uncoloured neighbour. A neighbour left with an empty set is either rematerialized (0x1076a63e) or given split points (0x107223d5, 0x107216f1).

### 3.4 Preferences (`c2_register_preference`)

0x107257e9 adds or increments a preference with **weight +1 per copy instance**. It is not scaled by loop depth, and it is ignored once the range is coloured. Preferences come from:
- `mov lr, <coloured lr or physical reg>`
- `mov <coloured lr or physical reg>, lr`
- `lea lr, [coloured base]`
- copy-related ranges collected in 0x1079d860, which prefer the register just chosen (0x1073321a)

### 3.5 Benefit and priority (0x10724b25)

Scoring walks the blocks in list order and the tuples forward. The block weight is `w = 1 << depth(block+0x6e)` under /Ot, and 1 otherwise.

**Benefit** (`+0x3c`):
- A source reference adds `w × S`. S is 0x107254dc (load saving) if the operand cannot be a memory operand of the instruction, and 0x10725751 otherwise. The test is 0x107254f6 *(inferred semantics)*.
- A destination reference that is not a reload adds `w × S`. S is 0x10725b22 (2) if there is no memory form, 0 for partial writes, and 0x10725751 otherwise.
- A 0x163 reload subtracts `w × 0x107254dc`.
- A 0x164 spill store subtracts `w × 2`. It is free when the block's loop info already covers the symbol, and such stores are counted in `+7`.

The savings values:

| Function | Under /Ot | Without /Ot (bytes) |
|---|---|---|
| 0x107254dc, load saving | 2 non-constant, 1 constant | 6 absolute, 3+ebp_alloc for stack, 2/3/5 for immediates |
| 0x10725751, memory-operand saving | 2 non-constant; constants 0 or 1 | 4 absolute, 1+ebp_alloc for stack |
| 0x10725b22, spill/reload cost | 2 | 6 absolute, 3+ebp_alloc for stack |

**Priority** (`+0xc`). For each block, P = the number of distinct candidate ranges referenced in the block. Let S_b be the sum of raw (unweighted) savings of the range in the block, accumulated in `+0x18`. Then:
- If the range is referenced in the block: `priority += P·w·S_b` (0x10725417 / 0x1072543c).
- If it is only live through the block: `priority −= P·w` (0x1072545b).

`+0x24` counts references.

Constant loads, reloads (0x163) and spill stores (0x164) count toward P but not S, physical-register
operands never count, and ranges pruned after the first scoring drop out of later rescorings
([invisible-ranges.md](invisible-ranges.md)).

### 3.6 Pruning (0x10725b42)

- A range with fewer than 2 references is demoted back to memory or local temps (0x10725eed). The exception is a range whose benefit is above 0 and whose last or def tuple is a reload.
- A range with exactly 2 references is a load feeding a single use. If the use accepts a memory operand, the load is folded into it (0x10725c27).

*Matching:* a value used once is never a global candidate. It goes to the local allocator.

### 3.7 Queue order (0x10731d21)

The queue is sorted by **priority descending**, then **tie key descending**. When two ranges have both the same priority and the same tie key, the newly inserted one goes first. Initial insertion walks the hash buckets `id & 0x3ff` in ascending order, each chain last-in first-out. Requeued pieces go in ascending id order, so on full ties the later-inserted piece (the higher id) is coloured first.

### 3.8 Ranges with benefit ≤ 0 (0x10732001)

1. **Force a preference** (0x10732152). This applies if `load_saving + benefit > 0` and some preferred register is still allowed. The range's allowed set becomes that single register (the heaviest preference), its benefit becomes 1, and it is pushed back at the queue head.
2. Otherwise it is **deferred once** (+5 bit 0x40). It moves behind the other deferred ranges, ordered by benefit, with constants last (0x1072639d).
3. On the second visit:
   - A single-block range, or one with no uncharged stores, is **demoted** (0x10725eed).
   - Otherwise it is **split at every block entry where it is live** (0x10743722; constants use 0x1073df72). Following deferred ranges with benefit ≤ 0 are handled the same way.

### 3.9 Interference (0x10732216)

Interference is computed lazily, only over the blocks the range spans. The neighbours are:
- ranges live after any def of the range;
- ranges defined while the range is live.

The source of a copy does not interfere with its destination. Neighbours already processed are excluded, because coloured neighbours are handled through the allowed sets.

The same pass counts integer pressure (esi, edi and ebp are counted separately) and byte-register pressure. When pressure reaches `k`, or byte pressure reaches 3, it inserts split markers.

### 3.10 Chooser (0x10732f7c), confirmed

```
c[] = 0
for each neighbour n with n.benefit > 0:
    for (r, w) in n.prefs where r ∈ n.allowed:  c[r] += w
    if |n.allowed| == 1: c[that r] += 100 * n.benefit
for (r, w) in lr.prefs:  c[r] -= w
pick the first r in order eax,ecx,edx,esi,edi,ebx,ebp with r ∈ lr.allowed and c[r] strictly minimal
```

After choosing, `lr+0x20` is freed. The chosen register is added to the busy sets (+0x24/+0x28/+0x4c) of every block the range spans. Pending copies (0x107ae0b0) are then resolved.

**Consequence:** the order list starts with eax, ecx, edx. A global range that crosses no call and does not conflict with fixed registers **takes eax, then ecx, then edx**. Callee-saved registers are used only once those three are removed. The order among them is esi, edi, ebx, ebp.

## 4. Local allocation (0x107336f4, regasg.c)

Operands of local temps point (`+0x18`) to class-3 temp symbols. These have exactly one def and are freed at the first source use, unless the same tuple redefines them (read-modify-write).

1. **Conflicts and preferences.**
   - Under /Og, with global candidates present, 0x10738c8a walks each block **backward**. It starts from the registers busy at block exit, which the chooser recorded in `block+0x28`. A temp that is live across any of the following conflicts with that register (`0x1079d6c8[r]`):
     - an explicit or globally coloured register;
     - a use of such a register;
     - a call clobber.

     Byte temps also conflict with esi, edi and ebp. The preference `+0x2c` comes from `mov t, reg` at the def; failing that, from `mov reg, t` at the use.
   - Without /Og, or when global colouring was skipped, the forward variant 0x10751166 runs instead.
   - Both variants set the used flag `desc.flags|=0x10` and the constant score `desc.const_score`.
2. **Walk.** The cursor is reset once per function (0x1073375e). Tuples are walked in current layout order. Each tuple handles its sources first (0x107384c2) and then its destinations (0x1073855d).
3. **Selector** 0x1073c97c, as described by snail:
   1. Preference. If it is unset, it is derived from the defining tuple: `mov t, reg(1..8, not esp)` or `lea t, [base(+disp)]`. Taking the preference does not move the cursor.
   2. **Rotation, under /Ot only.** It tries eax, ecx, edx from the cursor and advances the cursor. Choosing edx wraps it to eax.
   3. First free register in the order eax, ecx, edx, esi, edi, ebx, ebp.
   4. Heuristics:
      - 0x10767fa8: moves an existing holder into a free register it may use and takes the holder's register.
      - 0x10768205, /Og only: hoists the holder's consumer above the current tuple.
      - 0x1076860c (regasg.c:1288): spills the register whose next fixed use is **furthest away** in the block.
      - 0x1076925b / 0x1078ba26: last-resort spills.

   *Matching:* without /Ot (for example /O1 or /Os) there is no rotation. Every local temp takes the lowest free register.
4. **0x107395e3, after the walk (/Og, global colouring ran):**
   - A register that holds only constants and has `const_score ≤ 2` is replaced by immediates again (0x1073fefe; the undo helper was not examined), and its used flag is cleared. The score is `Σ uses·(0x10725751<<depth) − Σ loads·(0x107254dc<<depth)`, and eax, ecx and edx start as "dirty" (0x1000000). *Matching:* a hoisted `mov edi, CONST` survives only when its net saving is above 2.
   - Under **/Os only**, when ebp was allocated as a general register, its use is renamed to the first unused register of ebx, esi, edi (0x1076e8b3).

### 4.4 /G5 memory-operand split (0x107337ec)

- **What it splits.** Opcodes with table flag 0x400 are candidates: xchg, push, inc, dec, neg, not, the shifts and rotates, adc, add, and, cmp, or, sbb, sub, test, xor. For the first memory operand (destination list first) that is not a float, not 16-bit and not special, it inserts `mov reg,[mem]` (and a write-back when it is a destination) with 0x1073c419. Only one operand is split per tuple.
- **Walk.** Blocks are walked forward and **tuples backward**. The busy set starts from the registers busy at block exit, or is empty when there were no global candidates.
- **Cursor.** The cursor 0x107ac2dc is **reset to 7 at each block**, so the next pick starts at eax.
- **Register choice.** 0x1073a0fd rotates from cursor+1 over all 7 registers. The first pass accepts only registers already used in the function, to avoid new pushes. The second pass accepts any register. Byte operands need a register ≤ ebx.
- *Matching:* the split registers rotate bottom-up within each block, not top-down.

## 5. Frame pointer and callee-saved registers

### 5.1 Frame pointer and double alignment

**0x1072f8fc** (called by the driver and again inside global colouring):
- Under **/Oy**, if `fn->flags(+0x34) & 0xc1` is clear and a few other flags allow it, it sets bit 0x10: the frame pointer is omitted and ebp is allocatable.
- Under /Og and /Ot it also computes a **double-alignment score**:
  - `3·x + y` over references to 8-byte doubles in the frame, each weighted by 10^depth.
  - If the score is ≥ 250, or > 15 when no parameters are referenced, it sets `0x600000`: `and esp,-8` alignment. In that case ebp is kept as the frame pointer when parameters are referenced.
  - If the score is ≥ 15, it is only remembered in `0x107ac150`.

**0x10730ab7** can revert the omission:
- Under /Ot, when `score ≥ 2 × Σ5^depth`, summed over high-pressure points (more than 7 simultaneous candidates).
- Under /Os, when frame-resident references outweigh the saving.

In both cases ebp stops being allocatable, `k` drops by 1, and the aligned frame is enabled.

### 5.2 Callee-saved pushes and pops

The mask is 0x10799014 = 0x1d0 = {ebx, ebp, esi, edi} (0x10757d02).
- **0x10734f8b** pushes the used registers in number order **ebx, ebp, esi, edi**. **0x10734ff3** pops them in reverse: edi, esi, ebp, ebx.
- A register counts as "used" if any allocator bound it or any tuple defined or clobbered it: flags bit 0x10 (0x1073cca4, 0x10738e30, 0x10738fbb, 0x10733b26).
- Functions with EH (sym `+0x14` bit 0x1000), with flag 0x10000, or compiled with /ZI always save ebx, esi and edi (0x107344a2).
- Under /Og without a frame, 0x10734647 can shrink-wrap saves away from the entry. I only read this partly.

### 5.3 Prolog and epilog (0x1073404f)

The frame part is `push ebp / mov ebp,esp`, plus `and esp,-8` when double-aligned. It is followed by `sub esp,N`, or `__chkstk` for large frames.

The epilog restores the frame one of two ways:
- `leave` when /Ot is off;
- `mov esp,ebp; pop ebp` when /Ot is on.

It ends with `ret n`. Under /GZ, `__chkesp` is added.

## 6. What source changes flip register choices

- **Loop nesting** multiplies every saving and penalty by 2^depth (global) and 1<<depth (constant scores). A reference moved into a loop dominates priority.
- **Reference counts:**
  - A single-use value is local (rotation).
  - Two references (a load and one use) can be folded into a memory operand.
  - Each extra reference adds `2·w·P` to priority under /Ot. P is the number of candidates referenced in that block, so busy blocks amplify it.
- **Long live ranges** lose `P·w` in every block they cross without a reference. Declaring a variable early, or keeping it alive over busy code, lowers its priority.
- **Calls** remove eax, ecx and edx from every range live across them. This is the main reason a variable lands in esi, edi or ebx. A variable not live across a call usually gets **eax, ecx or edx from the global allocator**, not from the rotation.
- **Declaration order has no direct effect.** Order matters only through:
  - web and live-range ids (hash-order ties);
  - the tie key: the *definition position*, where a later block wins and, within a block, an earlier def wins;
  - constant symbol creation order.
- **Explicit register uses** remove that register from everything live across them, and add +1 preferences for the copy partner. Examples: returns in eax, thiscall `this` in ecx, div and mul in edx:eax, shifts in cl.
- **Byte-sized uses** confine a range to eax, ecx, edx or ebx. A byte range whose set shrinks to one register adds 100×benefit to that register's cost for every neighbour.
- **Constants:**
  - Every use of the same immediate value in eligible instructions forms one candidate.
  - Under /Ot, each use saves 1·w and each load costs 1·w.
  - It is kept in a callee-saved register only if its `const_score` exceeds 2.
- **Frame pointer:** omitting it (`/Oy`, default with /O2) gives the allocator 7 registers. Heavy use of doubles or frame references can take ebp back.

## 7. Open questions and uncertainty

- The x87 path is only named. This covers 0x107645d8 (float class), 0x1073932c and 0x107392c7, and the class-1 queue.
- The internals of the web builder are only partly read: 0x1072ed0d, 0x1073168d, and the reload placement in 0x1072e5b9 and 0x1072e7cb.
- 0x107254f6: I infer "operand can be a memory operand" from the /Os savings. Under /Ot it only matters for constants.
- 0x10752624, 0x1076a63e and 0x107527b2 (rematerialization cost test) were read at the call level only.
- The purposes of `lr+6` bit 4 (0x1078f12f) and `lr+7` are partly inferred.
- I did not identify which lowering routines emit the fixed-register operands for div, mul and shift.
- 0x107ae00c is written as 6 (ebp) or 0 but has no reader among the code references BN resolved.
