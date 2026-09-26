# Join statements cloned after allocation: rotation slots and identical arm tails (C2.DLL 8966)

This note is about a native shape where both arms of an if/else end with the **same statement in the same
registers**, and the local rotation cursor seems to skip a slot in the first arm:

```
arm1:  ...; mov ecx,[esi+0xc]; push ecx; mov ecx,[esi+0x10]; call SetBelow; jmp OUT
arm2:  ...; mov ecx,[esi+0xc]; mov [esi+0x14],ebx; push ecx; mov ecx,[esi+0x10]; call SetBelow; jmp OUT
```

The source writes that statement **once, after the if/else**. Block mover loop 2 copies it back into the
first arm after register allocation. Addresses are virtual addresses in the pinned C2.DLL (image base
0x10700000), and everything here is `/O2 /G5`.

Evidence labels:

- **Verified** means observed in a compile, or in a preserving trace (`il_stage_trace.py --preset jumpopt`),
  or in a pick-by-pick comparison of the local rotation cursor against native.
- **Read** means taken from disassembly or from the notes cited.
- **Inferred** means the rule fits every compile here, but the C2 code for it was not traced.

See also [layout.md](layout.md) §2 (block mover), [regalloc.md](regalloc.md) §1 and §4 (exit-block
duplication and the rotation), and [arm-local-builds.md](arm-local-builds.md) (per-arm copies and the mod-3 rule).

## 1. Rule

1. **A copy made before allocation and a clone made after it count differently.**
   - Before allocation: a statement written in each arm, or a `return x;` tail cloned by
     `duplicate_exit_block_into_predecessors` 0x10727731. Each copy is allocated separately. Each takes its own
     rotation slots, and the copies get different registers unless the slots between them are a multiple of 3
     ([arm-local-builds.md](arm-local-builds.md)).
   - After allocation: a block cloned by **block mover loop 2** (0x10736920, after jump_optimize #2). The clone
     is a deep `node_clone` 0x10701ef1 copy (call at 0x1073695f), so it keeps the original's registers.
     It **takes no rotation slot**. The single slot was taken where the join block sits in layout order at
     allocation time: after the arm that falls into it, which is the last arm. [Read + verified]
2. **When the clone happens.** Write `if (c) { A } else { B } S;` where S is followed by a jmp, for example
   because an outer `else` comes next. Arm A ends with `jmp JOIN`, and B falls into `JOIN: S; jmp OUT`.
   - JOIN has a fall-in, so loop 2 cannot move the block ([layout.md](layout.md) §2 step 3).
   - It **duplicates** the block when `S + jmp` is **≤ 20 bytes** (/Ot) and `jmp JOIN` is deleted.
   - JOIN then has no references and is removed after the mover (remove_dead_labels 0x10704ea7).
   - B's last statements and S become one scheduling window, so B's stores can move into S's argument
     setup (`mov ecx,[esi+0xc]; mov [esi+0x14],ebx; push ecx`). [Verified]
   - If the block is larger than 20 bytes, arm A keeps `jmp JOIN` and there is one copy. [Verified, §2 control]
3. **No jump-optimizer merge is involved.** In this shape, `cross_jump_into_fallthrough` on arm A's
   `jmp JOIN` finds nothing, because A ends differently from B. `cross_jump_pair` and
   `sink_common_tail_pair` never apply: JOIN has one jump reference and a fall-in. [Verified: jo2
   reports `cross_jump_into_fallthrough: no` for that jmp]
4. **How to recognise it in native.** Both arms end with a byte-identical short statement, for example
   `mov r,[..]; push r; mov ecx,[..]; call` with the same `r`. The arm that falls through would usually
   jump to a shared exit. When per-arm source copies give the first copy a different register, or the
   rotation cursor offset against native changes at the first copy and then **returns** to the old value
   at the next pick (a one-row `+k` blip), write the statement once after the if/else.
5. **Re-count the slots after moving the statement.**
   - Moving S from each arm to the join changes the number of picks between S and the last arm. Before, each copy
     was allocated inside its own arm. Now there is one pick, after all of B's picks.
   - The picks inside B must then put S on native's register. If they do not, look in B for loads that native
     makes as rotation temps but the candidate makes as named locals or globally coloured values.
     **A named single-use pointer local** (`T* p = this->field;`) can take a register from the global allocator
     without taking a slot. The same read written inline (`this->field->x`) takes a slot.

## 2. Evidence

Verified on Snail Mail's initialize_tip (`cRTip::Init`). There native's two arms end with the same
`widget_ok->SetBelow(widget_main)`; with its `jmp OUT` the join block is 14 bytes. Writing it once after
the if/else, together with an inline member read in place of a named pointer local in the else arm
(rule 5), made the function byte-exact.

- `il_stage_trace --preset jumpopt`: at block_mover entry arm 1 ends `...call; jmp JOIN`, and the else
  arm falls into `JOIN: mov ecx,[esi+0xc]; push; mov ecx,[esi+0x10]; call; jmp OUT`. At emit, arm 1
  has a new copy of the four tuples, with new tuple addresses but the same temps and the same
  registers, followed by `jmp OUT`. JOIN is gone, and the else arm's store is scheduled between the
  load and the push.
- The join `SetBelow` is the statement's only rotation pick.
- Control: a second `SetBelow` in the join makes it 26 bytes. It is not duplicated; arm 1 keeps its
  `jmp` to the join, and there is one copy.
- Writing the statement in each arm instead, with the same inline read, does not reproduce native.

## 3. Open questions

- The loop-2 duplicate event was not hooked directly. It is attributed from the IL at mover entry and at emit,
  the clone call to node_clone at 0x1073695f, and the >20-byte control. `branch_trace.py` hooks only loop-1
  moves.
- The global allocator's choice of register for a named single-use pointer local was not traced. Only its
  effect matters here: it takes no slot.
