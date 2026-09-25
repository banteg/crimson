# player_update aim chain: a cross-jumped atan2, not a mover move (C2.DLL 8966)

This note explains the native layout of the `player_update` aim section (0x415284..0x41575e). In that
section, arm 4 ends with `jmp 0x4152da`, into the tail of arm 0. The note covers:

- which C2 pass produces that jump;
- how the order of a label's reference list decides which copy of a shared tail survives;
- a source shape that reproduces native's layout.

Addresses are absolute VAs in the pinned C2.DLL. The evidence labels mean:

- **Verified:** confirmed by a preserving trace or by compiles.
- **Read:** static reading only.
- **Inferred:** fits every compile, but the C2 code was not traced.

See also [branch-variants.md](branch-variants.md) (mover gate), [layout.md](layout.md) §1–2 (jump
optimizer and mover), [aggregate-temporaries.md](aggregate-temporaries.md) §6 (cross-jump
profitability), [value-threading.md](value-threading.md) (threading) and
[x87-held-lanes.md](x87-held-lanes.md).

## 1. Short answer

- **Native uses plain source order.** The blocks appear as arm 0, arm 4, arm 3, arm 1, POV, auto-aim,
  then the join `L207e`. No block sits out of order, so neither mover loop moved anything.
- **0x4152da is not the join. It is a second copy of the atan2 statement:**
  `fld [esi+4]; fsub [edi+0x54]; fld [esi]; fsub [edi+0x50]; fpatan; fsub; fstp [edi+0x300]`.
  - This copy is followed by `jmp L207e`, and `L207e` begins with the same atan2.
  - The source therefore has `aim_heading = atan2(...)` at the end of arms 0 and 4, as well as after
    the whole if/else.
- **The 25-byte copies in arms 0 and 4 were merged by `cross_jump_pair`** 0x1071dfc6 in
  jump_optimize #2.
  - Arm 4's copy was deleted, and arm 4's jmp was retargeted into arm 0's copy.
  - The integer struct-copy stores before the atan2 use different registers in the two arms (eax/ecx
    against edx/eax), so the match stops at the atan2.
- **Which copy survives depends on the order of the join label's reference list.**
  - With the `else if` chain, arm 0's copy is the one deleted.
  - When the arm exits are threaded jumps (flat `if` rules on the local `aim_scheme`), arm 4's copy is
    the one deleted, as in native.

## 2. Mover verdicts on the canonical scratch (verified)

`branch_trace.py` on the canonical 5436cf105 scratch reports, at block_mover entry, for C2 lines 790–894
(scratch lines 931–1035):

| jmp | source | loop-1 verdict |
|---|---|---|
| jmp@1933 line 790 → L2214 | arm 0 else-skip (reader JUMP) | `target-prev-kind0xc(0x1)` |
| jmp@1983 line 809 → L2214 | arm 4 | same |
| jmp@2055 line 843 → L2214 | arm 3 | same |
| jmp@2107 line 865 → L2214 | arm 1 | same |
| jmp@2143 line 882 → L2214 | POV / outer then-arm | same |
| jmp@2179 line 894 → L2199 | auto-aim inner else-skip | `target-prev-kind0xc(0x63)` |

**Loop 1** fails on condition 4 of the gate. The tuple before the join `L2214` is auto-aim's
`mov byte [esp+0x13], 1`, which falls into the join. It is not a jmp or ret.

**Loop 2** fails as well (read, [layout.md](layout.md) §2):

- the join block has five jumps plus a fall-in, so it is multi-entry;
- the walk from `L2214` meets the conditional branch of the `shot_cooldown` test before any jmp or ret.

Native needs no mover move, because every block is already in source order.

## 3. Cross-jump survivor: the reference list order

### 3.1 The pair loop (read and verified)

1. `cross_jump_label_refs` 0x1073d211 takes the references of L in list order.
2. Each reference in turn is the anchor J2, and is tried against every later reference J1 with
   `cross_jump_pair(J1, J2)`.
3. On a merge, `tuple_range_free` deletes J1's matched range, and J1 is retargeted to
   `label_after_or_create` before J2's copy. **The later reference in the list loses its copy.**
   - There is one exception: the roles swap when the first unmatched tuple on J2's side is an
     unconditional jmp or ret while J1's is not.

### 3.2 How the list gets its order

**Primitives (read):**

- `label_add_ref` 0x107038d5 prepends: the newest reference comes first.
- `label_retarget_all_refs` 0x10705224 repeatedly takes the head reference and calls `tuple_retarget`,
  which also prepends. So a retarget-all moves the whole group to the front of the new label's list
  in **reversed** order.

**Observed list for the else-if chain (p1, verified at jump_optimize #2):** the join refs are
`[arm1, arm3, arm4, arm0, outer then-arm jmp]`.

- The reader creates the arm JUMPs in source order, each to its own nested join label J0, J4, J3, J1.
- These labels are adjacent, and are merged so that the group reads `[arm0, arm4, arm3, arm1]`. The
  label-merging step is inferred, not traced.
- Jump-to-jump threading onto the outer then-arm's jmp then reverses the group.
- Result: the pair `(J1 = arm0, J2 = arm4)` deletes **arm 0's** copy. This is the opposite of native.

**Flat threaded rules (f1/g6, verified):** with `if (s == 0) {...} if (s == 4) {...} ...`, each arm
falls out into the next rule's test.

- `thread_jumps_at_block_end` decides those tests from the equality fact on the local `aim_scheme` and
  creates one jmp per arm exit, in list order arm0, arm4, arm3, arm1. `branch_trace` shows all four as
  born in postglob (`thread_jumps_at_block_end`).
- The later retarget-all onto the join reverses them into `[arm0, arm4, arm3, arm1, ...]`.
- The first pair tried is `(J1 = arm4, J2 = arm0)`, and it merges.
- Arm 4 ends `jmp <arm 0's atan2>`, as in native.

**`switch` (sw1, verified):** every `break` targets one label, so it gives the same order and
direction. But this switch lowers to a jump table (`cmp 4; ja default; jmp [table]`), which native does
not have.

### 3.3 Profitability (verified with `scripts/c2/xjump_trace.py`)

Under /Ot, `cross_jump_pair` adds `tuple_encoded_length` over the matched tuples, starting at the
**earliest** matched tuple. It stops once the sum reaches 20, and merges only if sum + counter > 20.

- **p1 (scalar stores, atan2 in arms 0 and 4):**
  - The match covers 11 tuples: fst, fstp, two int moves, then the atan2 loads. They are equal
    because both arms happen to use ecx.
  - The running sum is 3+3+3+3+3+3+2 = **20 exactly**, so there is no merge.
  - This is the exact-20 trap from [aggregate-temporaries.md](aggregate-temporaries.md), hit from
    the other end: the extra matched int moves push the stop point to exactly 20.
- **g6:**
  - The match stops at arm 4's `mov [edi+0x54], ecx` against arm 0's `mov [edi+0x54], edx`.
  - It counts only the atan2: 3+3+2+3+2+6+6 = 25 > 20, so it merges.
- **Consequence:** the arms must copy `player->aim` through an integer struct copy, as native does.
  - That copy stops globopt from forwarding `scratch_pos.y` into the atan2.
  - Its registers differ between the arms, which bounds the match at a 25-byte tail.

## 4. Held lanes in arm 0

Native arm 0 computes y, then x, and only then stores x and y:
`fld; fsub; fld; fsub; fstp [esp+0x40]; mov eax; fstp [esp+0x44]`. This is the
[x87-held-lanes.md](x87-held-lanes.md) shape: a by-value inline setter, with y read through a pointer
that the function computes. A direct `player_aim_screen_x[i*2+1]` read is not aliased by the x store,
so y is forward-propagated and stored first (g1). A local
`player_update_vec2_t *mouse_screen = (player_update_vec2_t *)&player_aim_screen_x[i * 2]` reproduces
native's arm 0, still addressed as `[ecx*8+ADDR]` (g3/g6). Arm 4 needs only the setter.

## 5. Predicting from source

1. A tail copied into two arms that both jump to the same label L merges under /O2 only when:
   - the backward match counts **more than 20 bytes** before the running sum stops;
   - or the match covers a whole block.

   Count from the first equal tuple going back. Register differences, from the /Ot rotation, end the
   match.
2. The survivor is the copy of the **earlier** reference in L's list. To find the order:
   - Reader jumps into one label: newest first.
   - Each jump-to-jump or label merge that moves a group reverses that group and puts it in front.
   - Else-if chain whose join is followed by an outer else-skip jmp: order is reverse source
     (`[last arm, ..., first arm, outer]`), so the **later** arm keeps the copy.
   - Threaded flat rules, or `switch` breaks, whose join is then retargeted: order is source
     (`[first arm, ...]`), so the **earlier** arm keeps the copy.

## 6. Acceptance tests

Predictions were written down before each round was compiled.
Scores are for the whole function, with refs as ok/unresolved/mismatch. Baseline: 70.35%, 799/0/2.

| variant | shape | prediction | observed |
|---|---|---|---|
| p1 | atan2 at the end of arms 0 and 4, scalar stores | arm 4 → arm 0 merge | **wrong**: no merge (running sum exactly 20); 70.06%, 799/0/1 |
| n1 (control) | atan2 in arm 0 only | no cross-jump | as predicted; 70.51%, 801/0/2 |
| n2 (control) | arms 0, 4, 3 | three-way merge | merges happen (arm 4 → arm 0 → arm 3 chain); 70.01% |
| s1 | struct copy + atan2 in arms 0 and 4 (else-if) | arm 4 → arm 0 | **wrong direction**: arm 0 → arm 4 (list `[.., arm4, arm0, ..]`); 69.52% |
| s3 (control) | struct copies only | no merge, about 70.1% | no merge; 69.72% |
| sw1 | `switch`, struct copy + atan2 in cases 0 and 4 | arm 4 → arm 0; chain order uncertain | arm 4 → arm 0, but a jump table; 69.56% |
| sw0 (control) | `switch`, no atan2 | no merge | no merge; 70.06% |
| f0 (control) | flat rules, no atan2 | not pre-registered | instruction-identical to the canonical scratch (70.35%) |
| f1 | flat rules + struct copy + atan2 in arms 0 and 4 | native compare chain, arm 4 → arm 0 | as predicted; 69.93%, 799/0/1 |
| g6 | f1 + setter in arms 0/4 + `mouse_screen` pointer | (post hoc, from x87-held-lanes) | arm 0 and arm 4 in native shape except registers; **70.37%, 801/0/2** |

## 7. Remaining residuals in the aim section

- **Register rotation.**
  - Arm 0's copy uses ecx/edx, where native uses eax/ecx. From there on, every rotating pick in arm 4
    is one step ahead of native's.
  - The local cursor is reset once per function and walked in layout order
    ([regalloc.md](regalloc.md) §4), so the offset comes from upstream code.
  - The canonical scratch hid this offset because its arm 0 made one pick instead of two. (Inferred.)
- **Arm 4 head.** `scalar` lives at [esp+0x18] where native uses [esp+0x20], and the clamp's x87 shape
  differs. This is frame and x87 work, not layout.
- **Arms 3, 1 and POV.** They use scalar stores where native uses int copies with held lanes.
  Converting them lost score (g2 69.19%, g5 70.06%).

## 8. Tool

`scripts/c2/xjump_trace.py` runs `il_stage_trace.py --preset jumpopt`, with return hooks on
`tuples_equal` (call 0x1071e08a) and `tuple_encoded_length` (call 0x1071e19f) inside
`cross_jump_pair`. For each pair it prints J1, J2, the verdict, every backward comparison (the last one
is where the match stopped) and every counted length:

```sh
uv run python scripts/c2/xjump_trace.py <scratch> --out /private/tmp/<new-dir> [--jump <jmp tuple addr>]
uv run python scripts/c2/xjump_trace.py --out /private/tmp/<dir> --reuse [--jump ...]
```

## 9. Open questions

- The exact step that merges the nested join labels J1/J3/J4/J0 into one list `[arm0, arm4, arm3, arm1]`
  was not traced. The resulting orders were observed; how they are produced is inferred.
- Whether native's source really used flat rules or some other shape that produces the same order was
  not established. The flat rules are one shape that works and compiles instruction-identically to the
  else-if chain when no tail is copied.
