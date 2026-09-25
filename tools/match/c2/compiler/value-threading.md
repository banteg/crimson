# Value threading: known constants through a compare, and the mover that follows

C2.DLL 12.00.8966 (image base 0x10700000), `/O2` (so `/Ot`). This note covers what happens when a block
assigns a constant to a local and control then reaches a compare of that local against a constant, for
example `h = 3.1415927f; ... if (h == -1.0f)`. The globopt CSE sweep decides the compare on that edge and
retargets the edge past it ("value threading"). The visible layout, though, is decided later by the block
mover, and that is what usually differs from native.

The case that prompted this is the `move_mode == 2` arm of `player_update`. Three stores to
`movement_heading` (3.926991, 2.3561945, 3.1415927) end the backward-key block. They are followed by
`if (movement_heading == -1.0f) {decel} else {accel}`.

Evidence labels:

- **Verified** means observed in a preserving trace (`scripts/c2/branch_trace.py`) or in a compiled object.
- **Static** means read in Binary Ninja only.

See also [branch-variants.md](branch-variants.md) (mover gate, jump lineage), [optimizer.md](optimizer.md)
(CSE sweeps, branch facts) and [layout.md](layout.md) (jump optimizer, block mover).

## 1. Summary

- `thread_jumps_at_block_end` 0x10708fa7 runs inside `cse_block` during globopt. For each successor edge of
  a block, it finds the first compare reachable through labels, facts and unconditional jumps
  (`follow_trivial_branch_chain` 0x10709618, up to 10 hops). It clones that compare and substitutes the
  block's available copies into the clone (`cse_replace_operands` 0x107098ea). If both operands are now
  constants, the compare is decided. A float pair is decided by `float_const_compare_mask` 0x10763d24 and
  the result is applied by `fold_constant_compare` 0x1074bf2c. The edge is then retargeted to the branch
  target, or to a new label after the branch. A block that ends in a jump or conditional branch has that
  branch retargeted (`tuple_retarget` 0x1070429b). A block that falls through gets a new machine `jmp`
  (`tuple_new_jmp_before` at 0x10709567). Verified.
- **Native threads all three `player_update` stores as well.** At 0x414a78, 0x414a82 and 0x414a8c each
  store is followed by `jmp 0x414aab`. 0x414aab is `mov eax,[esp+0x18]; push eax; call
  player_heading_approach_target`, the first instruction of the accel arm, *after* the `fld; fcomp; fnstsw;
  test ah,0x40; jne 0x414bd6` test at 0x414a96. The test is reached only from the not-taken path of the
  backward-key test. The normalized listing hides this because it prints `jmp L13fb` without showing where
  L13fb is.
- The candidate differs from native because of **block_mover loop 1** ([branch-variants.md](branch-variants.md)
  §4), not because of threading. With `if (h == -1.0f) {decel} else {accel}`, the threaded target is the
  *else* arm. The tuple before the else arm's label is the then-arm's else-skip `jmp`, so the gate passes for
  the first threaded jump. The mover moves `[other stores, test, decel]` after the first jmp inside accel and
  deletes that jump. The first store then falls straight into accel, and the test appears to be gone.
- With `if (h != -1.0f) {accel} else {decel}`, or `if (!(h == -1.0f))`, the threaded target is the *then* arm.
  The tuple before it is the test's jcc, so the gate fails (`target-prev-cond-jcc`). This is native's layout:
  three `mov; jmp accel` pairs, then the kept test with `jne decel`, then accel.

## 2. The threading step (`thread_jumps_at_block_end` 0x10708fa7)

This section is static reading of the listed addresses, checked against the traces in §4.

1. The step is skipped when the function object (second argument) has flag 0x40, or when its symbol has
   aux bit 0x10. Neither flag was decoded.
2. For every successor edge of the block: when the edge goes to the physical next block (fall-through), it
   continues only when `g_opt_favor_speed` 0x107ac0b4 is set (/Ot, 0x10709064). /O2 sets it.
3. `follow_trivial_branch_chain` starts at the successor's first tuple. It skips non-real tuples and the
   status-1/2 fact tuples (the `iv_tag` 1 and 2 checks at 0x1070963a), and follows unconditional jumps to
   labels, at most 10 of them. The first other tuple must have tag 0x11 (a compare). Otherwise nothing
   happens.
4. The compare's block must not be earlier in RPO than the source block (block+0x6c), and both blocks must be
   in the same loop (block+0x68, 0x10709090..0x1070909c). The compare's result must be used by the very next
   tuple (`find_next_use_of_dst` 0x107037e4, 0x10709100). A compare with a symbol operand whose operand byte
   +0x10 has bit 0x40 is rejected at 0x107090d8. The volatile probe fits this check, but the bit is not
   decoded.
5. `tuple_new_compare` 0x10707a48 builds a scratch compare with the same operands, followed by a scratch
   CJUMP. `cse_replace_operands` 0x107098ea rewrites the scratch operands from the block's available set, so
   `h` becomes `3.1415927f` when the block's last write to `h` is that store and it is still available.
6. When both operands are constants, the branch outcome is computed:
   - For floats (`NK_FCONST`, 0x10790aee), `sub_10708b46` returns the consuming branch's condition code and
     `float_const_compare_mask` 0x10763d24 compares the two constants.
   - Integer and address pairs use the switch at 0x10709229.
   - Two addresses of the same parent compare their offsets.

   `fold_constant_compare` 0x1074bf2c then chooses the taken or not-taken successor.
7. Retargeting (0x10709306..0x10709567):
   - Taken: the edge goes to the branch's label.
   - Not taken: the edge goes to a label after the branch, created with `tuple_new_label` at 0x107094b2 when
     needed.
   - The source block's terminating jump, conditional branch or switch entry is retargeted with `tuple_retarget`.
   - A fall-through source gets a new `jmp` before its end label. The jmp carries the line of the first
     tuple of the bypassed block, as noted in [branch-variants.md](branch-variants.md) §4.
   - The flow graph edge is moved (`cfg_add_edge`, `remove_loop_back_edge`).

What stops the step (verified by the probes in §4):

- **Not a constant after copy substitution.** A store of a variable (`h = a1`) leaves the compare undecided.
  A block that stores a variable keeps its jump to the test.
- **`volatile`.** Every read of `h` is kept, so the test is kept for all stores.

What does *not* stop it (verified):

- **`double` instead of `float`.** The double constants still decide `h == -1.0`.
- **Address-taken `h`.** `observe(&h)` before the chain does not stop it, because no call or store through a
  pointer sits between the constant store and the compare.
- **Which arm or store it is.** All three stores in the chain are threaded. The else-if JUMP of 2.356 and the
  `cfg_repair_fallthrough` jmp of 3.1415927 are retargeted, and the 3.927 fall-through gets a new jmp.

## 3. The mover step that decides the layout

At block_mover entry the relevant list for the `==` form is:

```
... tests ...
S_pi:   h = 3.1415927     ; jmp ACCEL      (J: first threaded jump)
S_2.36: h = 2.3561945     ; jmp ACCEL
S_3.93: h = 3.926991      ; jmp ACCEL      (new jmp from threading)
TEST:   cmp h, -1.0       ; jcc(!=) ACCEL
DECEL:  ...               ; jmp JOIN       (the if/else else-skip)
ACCEL:  ...
```

Loop 1 checks four conditions for J = `jmp ACCEL` after S_pi:

- J is unconditional;
- `J->next` is a label other than ACCEL;
- ACCEL comes after J;
- the tuple before ACCEL is DECEL's unconditional `jmp JOIN`.

All four hold, so the gate is **PASS**. `[S_2.36 .. DECEL's jmp]` moves after the first jmp or ret after
ACCEL, and J is deleted. S_pi now falls into ACCEL. The other two threaded jumps now come after ACCEL, so the
gate cannot fire for them.

For the `!=` form the list is `... S_pi; jmp ACCEL; S_2.36; jmp ACCEL; S_3.93; jmp ACCEL; TEST: jcc(==) DECEL;
ACCEL: ...; jmp JOIN; DECEL: ...`. The tuple before ACCEL is the test's jcc, so every threaded jump fails with
`target-prev-cond-jcc` and nothing moves.

`optimize_flow_graph_initial` lays the stores out as pi, 2.356, 3.927, the reverse of source order. This is
the same order native has. So the store that falls through in the `==` form is always the else-most store
(pi here).

### Predicting from source

When a constant store reaches `if (x OP C) {A} else {B}` and the constant decides the test:

1. The store's edge is threaded to whichever arm the constant selects (§2).
2. If that arm is **B, the else arm**, B's label is preceded by A's else-skip `jmp`. The first such threaded
   jump passes the mover gate. Everything between it and B (other stores, the test, arm A) moves after B's
   first jmp or ret, and the store falls into B.
3. If that arm is **A, the then arm**, A's label is preceded by the test's jcc. Nothing moves: each store
   keeps a `jmp A` past the test, and the test stays in place for the paths where x is unknown.

To get native's `mov; jmp; mov; jmp; mov; jmp; test; jne` shape, write the arm that the constants select as
the then-arm.

## 4. Acceptance tests

### player_update (other session's uncommitted source, 67.39%)

The variants are copies of the canonical scratch.cpp and scratch.conf. Only the mode-2 `if` was changed.

| variant | prediction | observed (matcher) | three stores keep `jmp accel`? |
|---|---|---|---|
| base `== -1.0f {decel} else {accel}` | all three threaded; mover PASS on pi's jmp; pi falls into accel; `[2.356, 3.927, test, decel]` after a jmp inside accel | 67.39%, refs 785/0/2. Trace: `jmp@1438 line 582`, `jmp@1441 line 581` and `jmp@1444 line 586` (born in `thread_jumps_at_block_end`) all PASS. `MOVE [1439..1475] -> after jmp line 598`, which is inside the inlined `player_accelerate_move_speed` | no: pi falls through |
| inv `!= -1.0f {accel} else {decel}` | all three threaded; all gates `target-prev-cond-jcc`; native shape | **67.45%**, refs 785/0/3. The trace shows the three jumps with `target-prev-cond-jcc`. The listing has `mov [esp+0x14], pi; jmp L; mov .., 2.356; jmp L; mov .., 3.927; jmp L; fld; fcomp; fnstsw; test ah,0x40; jne decel; L: mov ecx,[esp+0x14]; push ecx; call`, the same as native 0x414a78..0x414ab0 apart from the frame offset 0x14/0x18 | **yes** |
| `!(h == -1.0f) {accel} else {decel}` | identical to inv | identical normalized listing, 67.45% | yes |
| inv + apply_move pushed into each arm | – | 66.74%, refs 776/0/4 (older base; on 8439eb73c it is 70.35%, 799/0/2, see [arm-local-builds.md](arm-local-builds.md)) | – |
| base + apply_move pushed into each arm | – | 66.70%, refs 777/0/4 | – |
| `double movement_heading` (control) | I predicted that double would block threading, following optimizer.md's "no double constant propagation". **Wrong.** | 50.66%. The stores still thread: `fld qword const; jmp accel`, with the pi store falling into accel | no |

The extra reference mismatch in inv is an alignment artifact. The reference audit pairs native 0x414baa
`fmul [7.957747]` (the accel arm's `move_dy`) with candidate +0x156f `fmul [25.0]` (the decel arm's
`move_dy`). This happens because the accel arm's x87 sequence still differs from native: native spills
`3.1415927f - angle_step` to `[esp+0x28]` and schedules the `lea/push` of the apply-move arguments inside
each arm. The mode-2 heading region itself is exact in inv.

### Probes (`probe.cpp` in the work dir)

The probes are built on the same shape: `h = -1; if (key(0)) h = 4.71; if (key(1)) { if (key(2)) h = C1;
else if (key(3)) h = C2; else h = C3; } if (test) ...`, with a large accel arm and a shared tail. The
predictions were written before the compile, except where the table says otherwise.

| probe | prediction | observed |
|---|---|---|
| `probe_eq` (`==`, decel first) | 3 threaded, PASS, one store falls into accel | 3 PASS, `MOVE [24..46]`; store 3.927 falls into accel, the other two `jmp accel`, and test + decel sit after the ret |
| `probe_ne` (`!=`, accel first) | 3 threaded, `target-prev-cond-jcc`, native shape | exactly native: `mov; jmp L78` ×3, `fld; fcomp; fnstsw; test ah,0x40; jne decel`, `L78: mov eax,[esp]; push eax; call accel` |
| `probe_dbl` (double) | no threading (wrong, see above) | 3 threaded, moved |
| `probe_addr` (`observe(&h)` first) | uncertain | 3 threaded, moved |
| `probe_vol` (volatile) | no threading | no threading; every store jumps to the test |
| `probe_var` (`h = a1/a2/a3`) | no threading | no threading; every store jumps to the test |
| `probe_mix` (`a1, a2, pi`) | only pi threads | only pi reaches accel directly; the a1 and a2 stores go to the test |

The small probes needed a larger accel arm and a tail after the join. Without them, the exit-block
duplication and jump optimizer copy the small accel arm into each store block, which hides the shape.

## 5. How to check a residual like this

1. Read the native addresses, not only the normalized listing. Find the instruction the jump lands on.
   A threaded jump lands one instruction *after* the test's jcc.
2. Run `uv run python scripts/c2/branch_trace.py <scratch copy> --out <new dir>`. The stores' jumps are
   listed with their lineage. A jump born in `thread_jumps_at_block_end`, or a reader jump whose target
   changed at postglob, was threaded. The verdict shows whether the mover will pull the target arm up.
3. If the verdict is PASS and native keeps the stores apart, swap the arms so that the arm the constants
   select comes first.

## 6. Open questions and corrections

- [optimizer.md](optimizer.md) (CSE section) says "a constant is not propagated if it is a double". The double
  probes show that `thread_jumps_at_block_end` still decides a double compare from a double constant store.
  Either the restriction applies only to real-tuple operand replacement and not to the scratch compare, or
  it is narrower than stated. This was not traced.
- The flag-0x40 operand rejection at 0x107090d8 was only linked to `volatile` by the probe. Its full meaning
  was not decoded.
- `sub_10708b46` (static) returns the condition code of the branch that consumes a compare's result. For a
  machine `jcc` (kind 0x10) that is byte +0x20, and for an IL CJUMP it is byte +0xa.
