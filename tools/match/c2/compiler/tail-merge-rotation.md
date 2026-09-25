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

- **Verified** means observed in a compile, or in a preserving trace (`il_stage_trace.py --preset jumpopt`,
  snail `rotation.py`).
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
   - If the block is larger than 20 bytes, arm A keeps `jmp JOIN` and there is one copy. [Verified, control c1]
3. **No jump-optimizer merge is involved.** In this shape, `cross_jump_into_fallthrough` on arm A's
   `jmp JOIN` finds nothing, because A ends differently from B. `cross_jump_pair` and
   `sink_common_tail_pair` never apply: JOIN has one jump reference and a fall-in. [Verified: jo2
   reports `cross_jump_into_fallthrough: no` for that jmp]
4. **How to recognise it in native.** Both arms end with a byte-identical short statement, for example
   `mov r,[..]; push r; mov ecx,[..]; call` with the same `r`. The arm that falls through would usually
   jump to a shared exit. When per-arm source copies give the first copy a different register, or the snail
   `rotation.py` offset changes at the first copy and then **returns** to the old value at the next pick
   (a one-row `+k` blip), write the statement once after the if/else.
5. **Re-count the slots after moving the statement.**
   - Moving S from each arm to the join changes the number of picks between S and the last arm. Before, each copy
     was allocated inside its own arm. Now there is one pick, after all of B's picks.
   - The picks inside B must then put S on native's register. If they do not, look in B for loads that native
     makes as rotation temps but the candidate makes as named locals or globally coloured values.
     **A named single-use pointer local** (`T* p = this->field;`) can take a register from the global allocator
     without taking a slot. The same read written inline (`this->field->x`) takes a slot.

## 2. The snail case: `cRTip::Init` (initialize_tip, 0x448a40)

Overlay `d.cpp` (97.40%). There, the hide-disable branch and the else branch each end with
`widget_ok->SetBelow(widget_main);`, and the else branch reads `cRTipData* button_definition = definition;
... button_definition->anchor_x`.

Native, with registers:

| where | native | d.cpp |
|---|---|---|
| arm 1, `widget_disable->SetBelow` | ecx (rotation) | ecx |
| arm 1, `widget_ok->SetBelow` | **ecx** (clone of the join copy) | edx (own pick) |
| else, `definition` load | **edx** (rotation temp) | eax (global allocator, `button_definition`, no slot) |
| else, `->anchor_x` | eax (rotation, edx busy) | eax |
| else, `widget_ok->SetBelow` | ecx | ecx |
| the rest, `previous_outer_owner`... | edx, eax, (ecx deleted), edx | same |

d.cpp gets the rest right because the pick count from `widget_disable->SetBelow` to the rest is 3 in
both. d.cpp spends one pick on arm 1's own `SetBelow` and one fewer in the else branch, because
`button_definition` does not take a slot.

The snail variants explain the partial results:

- **g1.cpp**: `SetBelow` after the inner if/else, with `button_definition` kept.
  - The mover duplicates the join, which gives the native structure.
  - The else branch has only one pick, so the join's `SetBelow` gets eax, and everything after it is off
    by +1 (88.96%).
- **Fix**: take the join form **and** read `definition->anchor_x` inline in the else branch.
  - The else branch's two picks are edx and eax. The join `SetBelow` is ecx, and the clone in arm 1 is ecx
    too.

```cpp
            widget_disable->SetBelow(widget_main);
        } else {
            widget_ok->Init(..., color.Set(1.0f, 1.0f, 1.0f, 1.0f), 2, definition->anchor_x);
            widget_disable = 0;
        }
        widget_ok->SetBelow(widget_main);
    } else {
```

**Result: 100.00%, 154/154, encoded body match, refs 27/0/0.** [Verified]

## 3. Evidence (predictions written before each compile)

| variant | prediction | observed |
|---|---|---|
| base = d.cpp | – | 97.40%, `rotation.py` offset `+0 → +2 → +0` at row #11 (arm 1's `SetBelow`) only |
| g1 (join `SetBelow`, `button_definition` kept) | – | 88.96%, offset +1 from the else branch's first pick onward |
| **v1** (join `SetBelow`, inline `definition->anchor_x`) | exact | **100.00%**, `rotation.py`: "every pinned allocation agrees with native"; join `SetBelow` is row #13 ecx, the only pick for that statement |
| v2 (per-arm `SetBelow`, inline `definition`) | not exact | 88.96% |
| c1 (v1 + a second `SetBelow` in the join, 26-byte block) | no duplication | arm 1 keeps `jmp` to the join, and there is one copy |

`il_stage_trace --preset jumpopt` on v1 (`jo_v1.txt`):

- **At block_mover entry,** arm 1 ends `...call; jmp JOIN`. The else branch falls into `JOIN: mov ecx(#296),[esi+0xc]; push;
  mov ecx(#222),[esi+0x10]; call; jmp OUT`.
- **At emit,** arm 1 has a new copy of the four tuples, with new tuple addresses (6c160a4c ...) but the same
  temps #296 and #222 and the same registers, followed by `jmp OUT`. JOIN is gone, and the else branch's store is
  scheduled between the load and the push.

## 4. Open questions

- The loop-2 duplicate event was not hooked directly. It is attributed from the IL at mover entry and at emit,
  the clone call to node_clone at 0x1073695f, and the >20-byte control. `branch_trace.py` hooks only loop-1 moves
  and does not run on snail scratches.
- The global allocator's choice of eax for `button_definition` was not traced. Only its effect matters here:
  it takes no slot.
