# Identical tails that native keeps apart: different stack objects in one slot (C2.DLL 8966)

This note explains why native `player_update` keeps two pairs of movement arms apart, although each
pair ends in the same instructions with the same registers:

- the demo accel arm and the mode-3 decel arm (`lea edx,[esp+0x48]` ... `mov eax,[idx]; push eax; fstp;
  fstp; jmp L186c`);
- the mode-4 decel arm and the mode-3 accel arm (the same tail with eax/ecx).

Our scratch merges the first pair, and would merge the second one as soon as mode 4 builds in
`move_delta` as native does. The note also records two smaller rules found in the same round (§5) and
a scorer effect that decides whether such changes pay (§6).

Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000), `/O2 /GB`. **Verified**
means observed in a compile or in a preserving trace, **read** means static reading, **inferred** means
consistent with every compile below but not traced.

See also [aim-chain-mover.md](aim-chain-mover.md) §3 (the cross-jump pair loop and byte rule),
[arm-local-builds.md](arm-local-builds.md) (rotation), [per-arm-frame-weights.md](per-arm-frame-weights.md)
(weights, slot room; its §7 asks this question) and [frame-model.md](frame-model.md) (packer).

## 1. Short answer

1. **The merge is decided by symbols, not by registers or bytes.** `cross_jump_pair` 0x1071dfc6 walks
   back with `tuples_equal`. That function compares a stack-object operand by symbol. `lea r,&move_delta`
   and `lea r,&move_step` are different tuples even when the packer later gives both objects the same
   frame slot, and so the same `[esp+0x48]`. [verified, §3]
2. **What our scratch merges.** Both arms use the function-scope `move_delta`. The backward match runs
   through the whole `pu_move_scaled` build and the `move_dy` store (15 tuples). It stops at
   `fmul [7.957747]` against `fmul [25.0]`. The counted bytes are 3+6+2+3+2+3+0+3 = 22 > 20, so the pair
   merges. [verified]
3. **What native must have.** Each arm builds into a *different* object, and all of those objects live
   in the slot at frame bottom 0x38. Then the match stops at the `lea`. The sum is 1+1+5+1+5 = 13
   (mov eax) or 1+1+6+1+5 = 14 (another register), and the pair is refused. The emitted code is
   identical to the merged-away copy. [verified with block-scoped vectors, §3]
4. **Why our scratch cannot do this inside the movement section.** Block-scoped aggregates in disjoint
   branches share a slot. A function-scope, address-taken aggregate, on the other hand, conflicts with
   every block-scoped aggregate placed inside the movement section, even one that no definition of it
   reaches (§4). `move_delta` is such an object, so no second object can join its slot. The block-scoped
   builds open a new slot instead, and the frame grows. [verified with `slot_scan.py`]
5. **Consequence for the source.** Native's b0x38 slot is shared by several block-scoped vectors: the
   movement builds of modes 4, 3 and demo, and (from [weapon-arm-schedule.md](weapon-arm-schedule.md))
   the projectile and sprite spawn positions. Our single function-scope `move_delta` stands for all of
   them. To reproduce native's non-merges, `move_delta` has to be split into block-scoped vectors
   everywhere it is used, so that nothing function-scope is left in that slot. That is a whole-function
   frame change and was not attempted here. [inferred]

## 2. The two pairs in our scratch

`scripts/c2/xjump_trace.py` on b882202d5 (C2 line = scratch line − 140) gives the following.
`cross_jump_label_refs` works on the shared call label L186c. Every arm jmp reaches it after the
per-mode `cross_jump_into_fallthrough` merges of jump_optimize #2.

| pair (J1, J2) | registers | stops at | counted bytes | result |
|---|---|---|---|---|
| demo accel ln663, mode-3 decel ln429 | edx/eax both | `fmul [7.957747]` vs `fmul [25.0]`, after 15 equal tuples | 3+6+2+3+2+3+0+3 = 22 | **MERGED** (native: apart) |
| mode-3 accel ln412, mode-4 decel ln375 | eax/ecx both | `lea &move_delta` vs `lea &movement_input` | 1+1+6+1+5 = 14 | no |
| same pair with mode 4 building in `move_delta` (M4) | eax/ecx both | the constants, as the first pair | 22 | **MERGED** |
| any accel/decel pair with different registers | – | the last `push` | ≤ 6 | no |

The tuple list of the merged match, from the jmp back:

1. `push r2`, `mov r2,[render_overlay_player_index]`, `push esi`, `push r1`, `lea r1,&move_delta`
2. `fstp md.y`, `fstp md.x`, `round` (the FROUND that `forward_propagate_definitions` inserts when it
   forwards the setter's `x` parameter; `il_stage_trace.py --preset globopt` shows it appear at the
   `fwd` stage)
3. `fmul [player+0x1c]`, `fxch`, `fmul [player+0x20]`, `fld st0`, `fld frame_dt`
4. `fstp [edi+0x20]` (move_dy)
5. The walk stops at the constant multiply.

C2's length estimates seen in these traces: `jmp` 5, `lea r,[esp+x]` 6, `mov eax,[abs]` 5,
`mov ecx|edx,[abs]` 6, `push` 1, `fstp [esp+x]` 3, `round` 0.

## 3. Acceptance tests

Copies of b882202d5's scratch. Predictions were written in `predictions.md` before each compile. The
score is the whole function, and refs are ok/unresolved/mismatch.

| variant | change | prediction | observed |
|---|---|---|---|
| base | – | – | pair 1 merged, pair 2 apart (different objects); 72.62%, 840/0/1 |
| M4 | mode-4 builds in `move_delta` (on the best aim variant) | pair 2 merges like pair 1, sum 22 | as predicted: ln412/ln375 MERGED, lens 3+6+2+3+2+3+0+3; and `movement_input` 182 < `scratch_pos` 184, so the slots swap; 67.14% |
| hv1 | block-scoped `player_update_vec2_t move_step;` in the mode-4 block and in the mode-3 block, demo keeps `move_delta` | pairs stop at the `lea`, no merge; frame grows | as predicted: ln665/ln431 stops at `lea &move_delta` vs `lea &move_step` (eq 1111, sum 13), ln414/ln376 at `&move_step` vs `&move_step` of the other block (sum 14). The listing has native's structure: mode-4 accel jmp into demo decel's pushes, and four separate `lea; push; push esi; …; jmp call` tails. Both `move_step` objects join slot 7 together (local bytes 0x46 → 0x4e); 62.85%, 824/0/6 |
| m1 / m2 | one arm with a direct `player_update_vec2_set(&move_delta, dt*m.x, dt*m.y)` instead of `pu_move_scaled` (to remove the FROUND) | the match stops before md.x, exact-20 refusal | **wrong**: the direct setter forwards the `move_dy` store (`fst [edi+0x20]; fmul`), and the pair still merges; 72.61% / 71.27% |

The m1/m2 idea is sound arithmetic. If the tuple before the md.x store differed, the match would
cover md.x, md.y, lea, push, push esi and mov: 3+3+6+1+1+6 = 20 exactly, and the pair would be
refused. But no spelling was found that changes that tuple without changing the code. Symbols
(hv1) explain native without any coincidence.

## 4. Interference of the vectors (verified with `scripts/c2/slot_scan.py`)

| object | declared | conflicts found |
|---|---|---|
| `move_step` (mode-4 block) and `move_step` (mode-3 block), hv1 | block scope, address-taken | each: `movement_input`, `scratch_pos`, `move_delta`, `random_offset`, `movement_heading`, `scalar`, `previous_pos`. **Not each other** |
| `move_step`, `move_step3`, v3 | function scope, used only in modes 4 and 3 | the same, **plus each other**: two new 8-byte slots, local bytes 0x56 |
| `move_step` in v2 (hv1 plus the fire-cough prelude moved to its own block vector, so that no `move_delta` definition precedes the movement section) | block scope | still conflicts with `move_delta` |
| `previous_pos` | function scope, not address-taken | only the four vectors |

So a function-scope, address-taken aggregate interferes with every block-scoped aggregate inside the
movement section, whether or not one of its definitions reaches there. Two block-scoped aggregates in
disjoint branches do not interfere. The liveness rule behind this (0x1074b45e, the field-store rule
of per-arm-frame-weights.md) was not traced; these rows are its observed effect.

## 5. Other rules found in this round

**Held compare against a constant: operand order picks the form.** In the aim arm-4 clamp, the value
is a single-use float local, so it stays on the x87 stack.

| source | code | verified |
|---|---|---|
| `if (length > 1.0f) s = 1.0f; else s = length;` (also the `?:` form) | `fcom [1.0]; fnstsw; test ah,0x41; jne` | yes |
| `if (1.0f < length) s = 1.0f; else s = length;` | `fld [1.0]; fcomp st(1); fnstsw; test ah,0x1; je; fstp st(0); mov [s],1.0; jmp; fstp [s]` (native 0x41534f) | yes |

With the constant on the left, C2 loads it and compares it against the held value. Nothing else in
the function changed.

**Field-address local in an index loop gives anchor +0.** For the auto-target loop, this spelling
reproduces native (0x413eb2..0x413f17: `mov ecx,creature_pool; cmp byte [ecx],0; fld [ecx+0x24];
fsub [ecx+0x18]; fsub [ecx+0x14]; …; cmp ecx,creature_pool+0xe400`):

```cpp
int creature_index = 0;
do {
    if (creature_pool[creature_index].active && creature_pool[creature_index].health > 0.0f) {
        const vec2f_t *position = &creature_pool[creature_index].position;
        ... position->y ... position->x ...
    }
    ++creature_index;
} while (creature_index < 384);
```

This is strength-reduction.md control `g1` in a real function. A named `creature_t *candidate` loop
anchors at +0x18 or +0x24: the named pointer's own IV goes first in the preheader, is the last
challenger, and has 1 use against an accumulated 3 (`iv_merge_chain.py`). The `for` form of the same
body also anchors at +0 but scores lower (72.59% against 73.23% for `do`, both on the same aim variant).

## 6. Scorer effect: branch labels count only at equal byte offsets

The score is `SequenceMatcher` over listing text, and a branch line reads `jne L11ab`, where the label
is the function-relative byte offset of its target. A branch therefore matches only where the
candidate's cumulative byte offset equals native's at the target.

On b882202d5 the movement section (native 0x414750..0x414e1d) happens to sit at delta 0. That gives 56
branch lines for free. Any upstream size change moves them:

- the aim-chain copies make the auto-target distance block native (d1 vs d2 below), and that block is
  2 bytes shorter;
- that change alone costs those 56 lines, which is most of g6's loss (g6 71.85%, b1 72.19%).

The auto-target change comes from the two extra atan2 statements, not from the new `mouse_screen`
local:

- d1 (flat rules, struct copies, the atan2 copies and scalar stores) changes the block;
- d2 (the same without the atan2 copies) does not;
- c1 (`mouse_screen` and `auto_aim` sharing one pointer, so no new named local) still changes it.

The id or temp that decides the product order of that block was not identified.

`scripts/c2/score_regions.py A B [--min N] [--offsets]` prints:

- the target ranges matched only by A or only by B, with the number of branch lines in each;
- B's byte-offset delta along the matched blocks;
- both sides' reference problems with their symbols.

Use it before deciding that a native-shaped change "lost".

## 7. Open questions

- Which native objects share b0x38, and in which order the packer creates that slot. The slot has to
  come third among the 8-byte slots (weight list order), so the heaviest block-scoped vector in it
  must outweigh the object that native keeps at b0x40.
- The exact liveness rule that makes a function-scope escaped aggregate interfere with block-scoped
  objects that none of its definitions reach (0x1074b45e was not traced).
- Why native computes `cos(h)` before `sin(h)` in aim arms 3, 1 and POV and reloads `move_delta.y`.
  Every spelling tried either forwards the cosine to its use (sin first) or stores it (S1, T1, T4 in
  the work dir).
