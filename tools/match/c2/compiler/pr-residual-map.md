# projectile_render: map of the residual after the frame work (C2.DLL 8966)

This note maps every mismatching region of `projectile_render` at 32b0ec7fa (81.79% raw, 541/0/0 refs) to
a C2 mechanism, and records the source changes that remove most of them. It also answers why the
weight-16 slots of best_p (from [pr-spill-order.md](pr-spill-order.md)) sort opposite to native.

Addresses are C2.DLL virtual addresses (image base 0x10700000), `/O2 /GB`. Target addresses are
crimsonland.exe VAs. Evidence labels:

- **verified**: observed in a compile, in the preserving observer of
  [`frame_predict.py`](../../../../scripts/c2/frame_predict.py), or in a trace
  ([`sched_trace.py`](../../../../scripts/c2/sched_trace.py), [`xjump_trace.py`](../../../../scripts/c2/xjump_trace.py));
- **read**: static reading;
- **inferred**: fits every compile below but was not traced.

See also [frame-model.md](frame-model.md) (weights, list order, density sort),
[native-slot-partition.md](native-slot-partition.md), [aim-chain-mover.md](aim-chain-mover.md) §3 (cross-jump
survivor), [x87-scheduling.md](x87-scheduling.md) (81-node windows, operand keys) and
[pu-factor-order.md](pu-factor-order.md) (sort keys of field and local leaves).

## 1. Short answer

| Build | Raw | Labels masked | Structural | Stack masked | Refs | Objects at native offset |
|---|---|---|---|---|---|---|
| 32b0ec7fa | 81.79% | 86.86% | 86.86% | 98.87% | 541/0/0 | 83/169 |
| + P (pulse arm writes `half_size`) | 81.95% | 87.03% | 87.03% | 98.87% | 537/0/**2** | 85/168 |
| + X (one function-scope `step_x`/`step_y`) | 86.93% | 92.01% | 92.01% | 99.10% | 541/0/0 | 120/160 |
| + A (`point0 = start_result; point1 = start_result;`) | 93.83% | 98.81% | 98.81% | 99.17% | 540/0/0 | **160/160** |
| + C (pulse/splitter/blade/ion as one else-if chain) | 94.03% | 99.01% | 99.01% | 99.37% | 542/0/0 | 160/160 |
| + W (three FROUND parentheses in the sharpshooter geometry) | 94.17% | 99.14% | 99.14% | 99.50% | 544/0/0 | 160/160 |
| + L (parenthesized splitter/blade `length()`) | **94.23%** | **99.20%** | **99.20%** | **99.57%** | **544/0/0** | 160/160 |

All rows are verified compiles. "Structural" is `crimson match --structural` (labels plus eax/ecx/edx masked),
"stack masked" is its `structural_stack_masked`. The last row is `pr-residual-map/best.diff`.

1. **The frame is solved.** With P, X and A every one of the 160 mapped stack objects sits at its native
   bottom offset. What separated labels-masked from stack-masked at 32b0ec7fa (357 of the 400-odd
   residual target lines) was slot order only, and it came from two source differences: the plasma
   `step_x`/`step_y` were per-loop locals, and the ion-arc start copies were field copies. [verified]
2. **Equal-weight slots have no tie-break key.** `sort_stack_slots_by_density` 0x10761bf0 is an unstable
   K&R quicksort. The final order of equal-density slots depends on every other slot's density and position
   in the pre-sort array. With P the four weight-16 slots come out as native's order reversed pairwise, and
   they come out as native as soon as X changes other slots' densities. Their own pre-sort positions (3, 20,
   21, 22) are the same in both builds. [verified, §4.2]
3. **What remains** (5.8 raw points, 0.8 labels-masked points): one constant that native passes through a
   stack temp (§5, K2, unknown), four x87 operand orders decided by C2 symbol-index residues (K6, K7), and two
   81-node scheduler-window boundaries (K8, K9). K2 and K7 change the byte count (−10 and −12 bytes), and all
   of the remaining label drift (raw vs labels masked) comes from them.

## 2. Tool: `residual_map.py`

```sh
uv run python scripts/c2/residual_map.py <scratch-dir> [--merge 2] [--window 64] [--show] [--json out.json]
```

It prints the four ratios (raw, labels, structural, stack), the reference problems, and each non-equal
region of the labels-masked diff (opcodes merged across ≤ `--merge` equal lines) with its target address
range. Each target line in a region is charged to the first mask under which a local re-diff pairs it:

| Class | Meaning |
|---|---|
| `scratch-reg` | pairs once eax/ecx/edx are masked |
| `stack` | pairs once ESP displacements are masked: slot ownership, or the same instructions at another push depth |
| `saved-reg` | pairs once ebx/esi/edi/ebp are masked |
| `order` | the fully masked line is elsewhere on the other side of the same region |
| `moved` | the fully masked line is an unused candidate line of another region within `--window` lines |
| `branch` / `code` | an unpaired jcc/jmp, or a different instruction |

Two operand swaps whose operands are both `[esp+x]` are charged to `stack`, because masking makes them equal.
Read those with `--show`.

## 3. The residual at 32b0ec7fa

"Fixed by" is the verified feature that makes the lines match (a line diff between consecutive builds).

| Target range | Separates labels-masked from stack/structural | Mechanism | Verdict |
|---|---|---|---|
| S1: 4-byte slots bottom 0x0/0x4 swapped. All refs of fading `along`, the conventional staging temps, the plasma `step_y`s, `ion_scale` and its temps (e.g. 0x422cd8, 0x4230f9–0x423320, 0x4245cb–0x424a74, 0x425c2b) | stack slot order | The w2 `step_x`/`step_y` are placed after `first`/`ion_scale` created their slots, so they join those slots ([frame.md](frame.md) §1.3). The 0x0 slot then weighs 27 and the 0x4 slot 28, and the density order flips | source-reachable: X, verified (§4.1) |
| S2: 0x24/0x28 (`projectile_index` vs the ion-pointer spill group) and `half_size` holding the staging temps | stack slot order | the pulse arm's size is a separate temp, so `half_size` weighs 10 ([pr-spill-order.md](pr-spill-order.md) §4) | source-reachable: P, verified |
| S3: the four w16 8-byte slots 0x7c/0x84/0x8c/0x94 (`direction_result` ×2, `base`, `half_size`), e.g. 0x4245c5/0x4248f3, 0x42450b–0x424549, 0x424843–0x424881 | stack slot order (and with P alone, two alignment ref mismatches) | quicksort tie (§4.2) | source-reachable: X (with P), verified |
| S4: 8-byte band 0x34–0x74 (`point0`, 0.4 `along` + `step_x`, `direction`, `point1`, the `step`/`old_arc_x` group, `point3`, `distance`, two `draw_pos` `$T` groups), e.g. 0x423173–0x4231de, 0x42322a–0x4232a0, 0x424506–0x424559, 0x424bf7–0x424f27 | stack slot order | `point0`/`point1` weigh 3 less than native (the start copies are dead-store eliminated), so the density order moves | source-reachable: A, verified (§4.3) |
| S5: `$T` and `span`/`first` slots 0x9c–0xe4 | stack slot order | density order and ties, as S1/S3/S4 | fixed by X and A, verified |
| K1: 0x422e90–0x422eaf (sharpshooter `perk_counts[perk_id_sharpshooter]` load) | instruction order | the 81-node scheduler window 3 (C2 lines 42–60) ends at `fst; fstp` of `point3`; native's boundary is ≥3 nodes earlier, so `mov ecx,[perk_id]` fills the `fadd` latency | source-reachable: W, verified (§4.5) |
| K2: 0x422f9b–0x422fc7 (`grim_set_color_slot(0/1, .5,.5,.5, 0.0f)`) | different code (−10 bytes; all later labels drift) | native stores 0 to a 4-byte object at bottom 0x4 and pushes it twice through esi; our constant is propagated | unknown (§5) |
| K3: 0x424377–0x42437b, 0x424404–0x424408 (splitter/blade `scale = length()`) | instruction order (x87) | `fst [scale]` comes before the dead-register `fxch; fstp st(0)` in IL order; the scheduler cannot reorder x87 stack writes ([x87-scheduling.md](x87-scheduling.md) §1) | source-reachable: L, verified (§4.6) |
| K4: 0x424475–0x42448f native, +0x1762 candidate (`call set_color; mov eax,[scale]; fld [scale]; fmul [0.5]`) | branch layout (moved block) | `cross_jump_pair`: the later reference in the label's list loses its copy ([aim-chain-mover.md](aim-chain-mover.md) §3). Ours keeps the splitter copy, native the blade copy | source-reachable: C, verified (§4.4) |
| K5: 0x424bf7–0x424cb0 (ion arc start copies) | different code and slots | native keeps `point0.x = point1.x = start_result.x` through eax/ecx; ours forwards and deletes them | source-reachable: A, verified |
| K6: 0x424c5e–0x424c62 (`direction * scale`, y lane) | instruction (operand) order | commutative operand sort key `0x10000 \| (index & 0x7ff) << 5` ([pu-factor-order.md](pu-factor-order.md) §1) | compiler-state-dependent (§5) |
| K7: 0x424cd0–0x424ce6, 0x424d75–0x424d7c, 0x424e37–0x424e59, 0x424efd–0x424f10 (arc `+=` lanes) | instruction (operand) order (−12 bytes) | same keys, on the product temps against the scalarized point fields | compiler-state-dependent (§5) |
| K8: 0x424f38–0x424f3c (`set_atlas_frame(4,2)` vtable load) | instruction order | 81-node window 197/198 boundary falls between `mov ecx,[grim]` and `mov eax,[ecx]` | compiler-state-dependent (§5) |
| K9: 0x42518c–0x4251a2 (plague third quad: `push 62; push 62; push ecx` vs `fld st(0); fsin`) | instruction order (and one esp depth) | 81-node window 206 (C2 lines 849–889) ends after the first push | compiler-state-dependent (§5) |
| label drift: every branch after 0x422f9b | label drift only | cumulative byte deltas: −10 at K2, −22 after K7 (`label_drift.py --drift`) | follows K2 and K7 |

## 4. Mechanisms of the fixes

### 4.1 X: one pair of plasma step variables

The five plasma segment loops each declared `float step_x = ...; float step_y = ...;` (w2 each: one `fstp`,
one read inside the loop). Written once at function scope:

- each weighs 10 (five stores and five loop reads), so both are listed right after the two `along`s (w11);
- `grim_draw_quad`'s arguments are evaluated right to left, so every loop reads `step_y` before `step_x`.
  `step_y` reaches 10 first (walk positions 296 and 297), and is placed first. [verified, list replay]
- Newest compatible slot first: `step_y` joins the fading `along` slot (native 0x0, with the staging
  temps), and `step_x` the 0.4 `along` slot (native 0x3c). This is native's grouping. The 0x0 slot weighs
  37 and the `ion_scale` slot 20, so they sort as native. [verified, 120/160 objects at native offset]

`fstp` stores kill, so the function-scope pair only conflicts locally ([native-slot-partition.md](native-slot-partition.md) §2).
X without P gives one reference mismatch (514/0/1); with P it gives 541/0/0.

### 4.2 The weight-16 order is a quicksort outcome

`pack_stack_slots` creates slots in list order. Above 0x80 local bytes `sort_stack_slots_by_density`
0x10761bf0 sorts them (weight·1000/size, middle pivot swapped to lo, strict `>`, [frame-model.md](frame-model.md) §4).
Equal-density slots are never compared as "less", so their final order is whatever the partition swaps leave.

- The four w16 slots have the same pre-sort positions in P and in P+X: `half_size` 3, `direction_result`s
  20 and 21, `base` 22. [verified, `sortlab.py` in the work directory, a replay on `frame_whatif.py` data]
- P gives `direction_result`(4664), `direction_result`(4686), `half_size`, `base`. P+X gives
  `direction_result`(4686), `direction_result`(4664), `base`, `half_size`, which is native.
- The partition trace (`qstrace.py`, work directory) shows why. The second partition, around `direction` (density 2875),
  leaves 9 denser slots below it in P and 10 in P+X (the 0.4 `along` + `step_x` slot is now 3125). The next
  sub-range starts one slot later, its middle pivot is a different slot, and the equal slots are swapped
  differently from there on.

So symbol id, first reference, size and alignment do not decide it. To predict it, replay the whole sort
(`frame_whatif.py`, or `sortlab.py` in the work directory). To change it, change other slots' densities.
Here that meant fixing the real remaining difference, X. Single-object weight perturbations that also
give native's `base`/`half_size` order either break other slots (`$T` weights) or are not native counts.

### 4.3 A: the arc start copies are whole-vector assignments

Native, per creature arc: `mov eax,[start.x]; mov [point0.x],eax; mov [point1.x],eax; fstp [start.y];
... mov ecx,[start.y]; mov [point0.y],ecx; mov [point1.y],ecx`, which is the same shape as
`point2 = end_result; point3 = end_result;`. With four field copies in the source the global optimizer
forwards `start_result` into the `-=`/`+=` and deletes the copies. With `point0 = start_result;
point1 = start_result;` the copies stay, and `point0`/`point1` go from weight 10 to 13. Their slots then
weigh 25 and 21, which are native's final reference counts at bottom 0x34 and 0x4c (ours were 22 and 18), and
the 8-byte band sorts as native. [verified]

### 4.4 C: which arm keeps the shared tail

The splitter and blade arms end in the same 25-plus bytes (`call set_color; mov eax,[scale]; fld [scale];
fmul [0.5]`). `xjump_trace.py` on 32b0ec7fa: both first merge into the pulse arm's draw tail, blade first
(`J1=blade ln600, J2=pulse` MERGED, then `J1=splitter ln576`). Each retarget prepends to the new label's list,
giving `[splitter, blade]`. The second round pairs `(J1=blade, J2=splitter)`, and blade loses its copy.
Native has the reverse.

Writing pulse, splitter, blade and ion as one else-if chain (no `continue`) routes the arm exits through the
chain's join. Retarget-all onto the latch reverses the group. Now splitter merges into the pulse tail first,
then blade, and the second round is `(J1=splitter ln575, J2=blade ln595)` MERGED: splitter jumps into
blade's copy, as native does. [verified: xjump trace and score]

Controls: positive `if (life == 0.4f) {...}` inside the arms, alone or both, is byte-identical (T2, T3).

### 4.5 W: the sharpshooter window boundary

`sched_trace.py`: window 3 (C2 lines 42–60) has 81 nodes (67 machine, 14 FROUND) and ends at
`fst [tmp]; fstp [point3 temp .y]`. Window 4 starts with `fadd st2`, and the perk-count load (`mov ecx,[perk_id]`,
height 8) can only move inside window 4. Native emits `fld; fadd; mov ecx,[perk_id]; fst; fstp; ...`, so its
window 4 starts at least at that `fadd`. Each C1 `round` (a parenthesized float subexpression) is one more
node before the boundary ([x87-scheduling.md](x87-scheduling.md), short version item 3):

| Parentheses | Window 3 | Window 4 starts at | Result |
|---|---|---|---|
| none | 67 + 14 FROUND | `fadd st2` | 94.03% |
| `heading` | 66 + 15 | `fstp` | 94.13%, perk load one line late |
| `heading`, `start_heading` | 65 + 16 | `fst` | 94.13%, same |
| `heading`, `start_heading`, the first `cos(start_heading) * 15` term | +3 | before the `fadd` | 94.17%, native |

[verified] The same device is used in player_update's smoke arms (`move_delta.y = (random_offset.y * 15.0f)`).
It is a no-op in C without `/Op`.

### 4.6 L: a round between `fsqrt` and the store

Splitter and blade: `scale = vec(...).length(); if (scale > 20) ...`. Our IL order is `fsqrt; fst [scale];
fxch; fstp st(0)`, and native's is `fsqrt; fxch; fstp st(0); fst [scale]`. The scheduler emits them in IL order,
because all four write the x87 stack. With `scale = (vec(...).length());` the extra round tuple sits between
`fsqrt` and the store, and the dead register is popped before the store, as native. [verified: result; the
stackifier rule "pop the dead register before the next tuple after its last use" is inferred]

Controls:

- `(float)vec.length()` is identical (L5).
- A `float length` local (L2) scores lower.
- `sqrt` of `dx`/`dy` locals (L3) scores lower.
- `length()` without its `(float)` cast is identical (L1).

## 5. What remains in best.diff, and what each would need

| Region | What differs | Verdict and what is needed |
|---|---|---|
| K2 0x422f9b–0x422fc7 | native `mov dword [esp+0x14],0; mov esi,[esp+0x14]; ... push esi` ×2 (object at bottom 0x4, weight 2) | **unknown.** Native passes the value through a stack object that C2 does not constant-propagate. A float local `= 0.0f` is folded (Z), and so are `0.0` and `0` literals (Z1, Z2), all byte-identical. Needed: the source construct whose value C2 cannot see as a constant, such as a non-candidate (address-taken) 4-byte float or a late-folded CSE temp. Fixing it would remove the −10-byte drift ahead of every later branch. |
| K6 0x424c5e | y lane of `direction * scale`: native `fld [scale]; fmul [dir.y]`, ours the reverse | **compiler-state-dependent.** Lowering-entry keys from `sched_trace.py` on best (C2 line 780): x lane `l0x78d` (0x1f1a0) before `l0x43a` (`scale`, 0x18740), y lane `l0x79a` (0x1f340) before `scale`. Native keeps the x lane and swaps the y lane. That needs a multiple of 0x800 between the two field symbols' indices, which a shift of +0x66..+0x72 would give [inferred]. Moving `old_arc_x` to function scope changes nothing (O). |
| K7 arc `+=` lanes | native x lane `fld [p.x]; fadd st(1)`, y lane `fld [t.y]; fadd [p.y]`; ours `fadd [p.x]` and `fld [p.y]; fadd [t.y]` (−12 bytes) | **compiler-state-dependent.** The pairs at lowering entry are product temps against start/point values: x lanes `0xee1/0xeb4` (line 781), `0xef7/0x108` (800), `0xf29/0x10b` (803); y lanes `0x10a/0x1063`, `0x107/0x1069`, `0x107/0x1071`, `0x10a/0x107d`. The x lane of line 788 (`0xeeb/0xee4`) already matches native. All of native's orders follow if the optimizer temps (0xe00–0x1100) were +0x11f..+0x14b higher, with the point field symbols (0x104–0x10e) unchanged. Line 788's x lane must not flip, which excludes +0x115..+0x11b [inferred]. The direction fields need a different shift (K6), so the counters differ in more than one place. Operand order in `operator+=` is irrelevant (B1 identical); `p = p + t` (B2) and `*this = *this + other` (B4) are worse. |
| K8 0x424f38 | `mov eax,[ecx]` before the pushes of `set_atlas_frame(4,2)` | **compiler-state-dependent.** The arc body is windows 195–198. 195, 196 and 197 are all 81-node windows (6/8/8 FROUND), and 198 starts at `mov eax,[ecx]`. Native's 197/198 boundary is at least one node earlier. One more FROUND in 195–197 moves all three boundaries. `(-direction.y)` (Q1) regresses and `(direction.x)` (Q2) is identical. |
| K9 0x42518c–0x4251a2 | native `mov ecx; push 62; push 62; push ecx; fld st(0); fsin; mov edx,[ecx]; fstp [phase_120_sin]` | **compiler-state-dependent.** Window 206 (lines 849–889, 81 machine nodes, no FROUND) ends at the first `push 62`, so the other two pushes are scheduled in window 207 after the x87 chain. Native has the whole group in one window, so its window 206 boundary differs. Parentheses on the plague `heading`/`phase`/`phase_120`/`sin(phase)*11` (Ga–Gd, alone or in pairs) regress. |

Everything else matches, including all 160 frame objects. `native_slots.py` still lists 13 native references
as "no candidate object": 0x422e96/0x422e9e, K2, and the arc's `[esp+0x64]` group. The arc lines are
matched instructions at the same offsets, so those entries are voting artifacts of the tool, not residuals.

## 6. Acceptance tests (predictions written before the compile)

| # | Change | Prediction | Observed |
|---|---|---|---|
| 1 | X on P | `step_y` (w10, reaches 10 first) joins fading `along` (0x0), `step_x` joins 0.4 `along` (0x3c); 0x0 above 0x4 | as predicted; w16 slots also native; 81.95→86.93%, 537/0/2→541/0/0 |
| 2 | A on P+X | `point0`/`point1` +3 refs each; 8-byte band native | 160/160 objects; 93.83% |
| 3 | C on P+X+A | splitter merges into the pulse tail first and loses the second round | xjump: `(J1=splitter, J2=blade) MERGED`; 94.03% |
| 4 | W | +3 nodes in window 3 puts the perk load before `fst` | 94.17%; +1/+2 nodes move it only part way (table in §4.5) |
| 5 | L | round between `fsqrt` and `fst` puts the pop first | 94.23% |
| n1 | Z, Z1, Z2 (zero alpha as local, `0.0`, `0`) | if constant-propagated, identical | identical |
| n2 | B1 (`x = other.x + x`) | commutative sort ignores source order: identical | identical |
| n3 | O (function-scope `old_arc_x`) | K6 is a key of the field symbols, not of `old_arc_x`: identical | identical |
| n4 | T2/T3 (positive life tests) | same CFG after threading: identical | identical |
| n5 | L1, L5 | the cast is folded into the store: identical | identical |

## 7. Predicting it from source

- Before blaming a tie, compare densities of **every** slot with native. The quicksort order of equal
  slots is a function of the whole array. Fix the real membership or weight differences first, then re-check
  the tie with the replay.
- A per-loop scalar that native groups with a heavier slot of another loop is usually one function-scope
  variable. Its weight is the sum over loops, and the slot it joins is the newest compatible one at that
  weight. Argument evaluation is right to left, which decides which of a lane pair reaches a count first.
- An aggregate whose field copies native keeps, with the same shape as a sibling `a = b;`, was a
  whole-object assignment. Field copies are forwarded and deleted.
- A cross-jump survivor in the wrong arm points at the arms' exit structure (`continue` vs else-if chain),
  because retarget-all reverses reference groups.
- An integer load that native hoists into x87 code but we do not, near a window of exactly 81 nodes, is a
  window-boundary question: count FROUND nodes (`sched_trace.py`).

## 8. Corrections to existing notes

- [pr-spill-order.md](pr-spill-order.md) §5, "Remaining differences":
  - the plasma `step_x`/`step_y` are one function-scope pair (§4.1);
  - the equal-density order of the four weight-16 slots has no tie-break key and is fixed by the same change (§4.2);
  - native bottom 0x54 has no separate "arc-loop product temp" once A is in: all its objects match.
- [frame-model.md](frame-model.md) §4 says the density sort is a "K&R quicksort ... strict >". Add that the
  resulting order of equal-density slots depends on the whole pre-sort array (§4.2).
- [frame-model.md](frame-model.md) §7 ("What must change is interference, not only weights"):
  - the complete native layout needed both kinds of change: interference (D, Q in pr-spill-order), and
    weights and list order (P, S, X, A);
  - the remaining weight gaps were one merged variable (X) and three copies per point (A).

## 9. Open questions

- K2: which construct leaves native's zero alpha in a stack object.
- The stackifier rule behind §4.6 (why a round tuple moves the dead-register pop ahead of the store) was not
  traced.
- K6/K7: which upstream constructs shift the C2 symbol indices by the amounts §5 derives (+0x66..+0x72 for
  the direction field symbols, +0x11f..+0x14b for the optimizer temps). The derivation assumes a uniform shift
  within each group.
