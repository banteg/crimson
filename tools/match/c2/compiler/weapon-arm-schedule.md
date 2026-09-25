# Smoke-sprite arms in player_update: color store order and the pistol tail merge (C2.DLL 8966)

This note covers the 11 weapon arms of `player_update` that spawn two smoke sprites, for example
WEAPON_ID_PISTOL at scratch line ~1320. It answers two questions:

1. Why our color stores for the first sprite land before `fstp [move_delta.y]`, while native puts them after
   `fstp [move_delta.y]; fld [mi.y]`.
2. Why native merges the pistol arm's second-sprite tail into the shrinkifier arm (`jmp L295e` at 0x41612a)
   and our arms stay separate.

Addresses are C2.DLL virtual addresses (image base 0x10700000). "Verified" means observed in a
preserving compiler trace or in a compile. "Read" means static reading only. Traces were taken on
`player_update` at 962b9692c (70.49%, refs 801/0/2). C2 line labels are scratch lines − 141.

Short version:

- **Colors.** Each arm is one scheduling window with no memory edge between the color stores and the
  vector stores. Native's order comes from a FROUND (0x162) between the `fmul` and `fstp [move_delta.y]`
  of the ×15 build. The FROUND takes cycle c+3 on its own, so the color stores are pushed behind
  `fstp; fld mi.y`. `move_delta.y = (float)(random_offset.y * 15.0f);` makes C1 emit that FROUND. Applied
  in all 11 arms, it makes every second-sprite build instruction-identical to native (12 of 12 blocks,
  apart from esp displacements). Score: 70.49% → **71.02%, refs 823/0/2**.
- **Tail merge.** `cross_jump_pair` matches the whole pistol arm against the shrinkifier arm, 60 tuples.
  It refuses the merge because the running byte sum lands exactly on 20 (see
  [aim-chain-mover.md](aim-chain-mover.md)). Native's shared tail starts exactly at the second sprite's
  `push eax`, so in native the tuple before that push must differ between the two arms. A distinct
  position symbol in the pistol arm reproduces native's merged shape exactly, but every such spelling
  tried costs a frame slot or the held-lane x87 shape. The native spelling is still open.

## 1. The window (verified, `sched_trace.py`, `alias_trace.py`)

- Every smoke arm is **one window**. It runs from the tuple after the arm's `jne` to the arm's `jmp`, and
  it ends at the branch. The pistol arm has 73 nodes: 70 machine tuples and 3 FROUNDs. The 81-node cap
  plays no part.
- **Alias classes.** The stores `sprite_effect_pool[effect_index].color_*` have class a170, whose symbol
  set is {sprite_effect_pool}. The class is bare: the base is `&global + idx*44`, not a named pointer,
  so there is no field record. The move_delta and scratch_pos stores are symbol operands
  (`fstp s31/s289`, `fstp s11/s13`).
- **Memory edges.** No memory edge links the color stores to the move_delta or scratch_pos stores, or to
  the random_offset loads. The only memory edges out of the colors are `st>ld` to `fadd [esi+4]` and
  `fadd [esi]`. Those loads read through `player_position`, class a458, whose points-to set contains
  sprite_effect_pool. The call before the colors is a barrier (edges 0xc0).
- **In-edges of `color_r`.** The call (order), `shl eax,2` (RAW, latency 2: 1 plus the AGI penalty), and
  `mov ebx,0x3f000000` (RAW, latency 1).
- **Latency of `fmul → fstp [move_delta.y]`: 4 cycles.** That is fmul's 3 plus 1 from
  `sched_fp_store_latency_penalty` 0x1073a42e, which adds 1 to any `fst`/`fstp` fed by
  fadd/fsub/fmul/fld.

Our schedule, pistol arm (cycle → tuple):

```
183 fmul [15]   184 shl eax,2   185 -   186 color_r, color_g   187 fstp md.y   188 fld mi.y
189 color_b, color_a   190 fadd [esi+4] ...
```

The colors become ready at 186, before the fstp at 187, so they issue first. Priority cannot change
that: nothing else is ready at 186.

**`push eax` before the fstp pair.** In our arms, and in native's unmerged arms (assault rifle 0x4161ea,
SMG 0x416819), `lea eax; push eax` fill the fadd→FROUND latency gap, so the push lands before the fstp
pair. Native's pistol is different only because its `push eax` sits after the merge label, in the
shrinkifier's code, and a window cannot cross that label. The order follows from the tail merge, not
from scheduling.

## 2. What native's order implies

Native's order (`fmul; shl; fstp md.y; fld mi.y; colors ×4; fadd [esi+4]`) needs one of two things:

- the colors are not ready before cycle 187; or
- cycle 186 is taken by something of higher priority that does not pair.

The table lists the candidates.

| Candidate | Result |
|---|---|
| An edge `fstp md.y → colors` (colors alias move_delta) | This needs the colors after the md stores in pre-schedule order and a broad alias class. A broad class, such as the reference local `effect_color_t &` at line 331 (class a463, the whole address-taken set), also gives `colors → fld mi.y` (movement_input is in that set). That forces the colors before `fld mi.y`, which contradicts native. Rejected. |
| Different window boundary | The window is well under 81 nodes and ends at the arm's `jmp` in both. Rejected. |
| **A FROUND on the move_delta.y lane** | `fmul → FROUND` has latency 3 and `FROUND → fstp` has latency 0. The FROUND has height 33 and priority 270336, above the colors' 262144. It issues alone at 186. Then fstp issues at 187, fld mi.y at 188 (311296 beats the colors), and the colors at 189-190, before the `fadd [esi+4]` that depends on them. This is native exactly. |
| A FROUND on the x lane as well | The x-lane FROUND takes cycle 180 alone. That pushes `lea eax; push edx` behind `fstp md.x; fld ry; fmul`. Rejected: not native (control c4x). |

## 3. Source rule

`(float)(float_expr)` makes C1 emit 0x162 (the parentheses do it, not the cast; see [codeless-tuples.md](codeless-tuples.md)) (verified: `il_stage_trace.py --lines 1195-1195` shows the
`round` tuple at the globopt entry dump). This extends [x87-scheduling.md](x87-scheduling.md) §3, which
lists only the explicit narrowing of a *double* expression.

Controls:

- implicit narrowing (`random_offset.y * 15.0`, a double literal) gives no 0x162 and a `fmul qword`;
- `(float)(random_offset.y * 15.0)` gives the 0x162 but also a `fmul qword`;
- a single-use float local (`float d = ry * 15.0f; move_delta.y = d;`) gives the same FROUND through
  forward propagation, but each new named local shifts slot ids (x87-scheduling §5). That swapped two
  commutative sites (the fsqrt block near line 516 and an fadd near 3707).

## 4. Acceptance tests (predictions written before each compile)

All 11 arms were changed unless the row says otherwise.

| Variant | Prediction | Observed | Score, refs |
|---|---|---|---|
| base 962b9692c | – | – | 70.49%, 801/0/2 |
| c1 `ry * 15.0` | (not predicted separately) | `fmul qword`, no FROUND, colors unchanged | 70.22%, 790/0/2 |
| c1b `(float)(ry * 15.0)` | FROUND; risk of qword | FROUND, `fmul qword` | 70.09%, 810/0/1 |
| c2 single-use local per arm | native color order; id shift elsewhere | colors native in 11 arms; 2 commutative swaps elsewhere | 70.63%, 821/0/1 |
| c3 inline setter for the ×15 build (control) | x lane breaks | x lane broken as predicted, id shift | 70.09%, 810/0/1 |
| **c4 `(float)(ry * 15.0f)`** | FROUND at 186 alone, native order | exactly that (sched trace: FROUND h33 pri 270336 cycle 186, fstp 187, fld 188, colors 189/190); only change in the listing is the 44 color lines | **71.02%, 823/0/2** |
| c6 function-scope `float` temp | same as c4 plus one id shift | same colors, one commutative swap | 71.02%, 823/0/2 |
| c4x cast on both lanes (negative control) | worse than c4 | x lane broken | 70.49%, 812/0/2 |
| c4p cast only in the pistol arm | small gain | the pistol colors are native, but the **score drops** | 69.33%, 795/0/2 |
| c4_25 also cast the ×25 y lane | equal to c4 | listing identical to c4 | 71.02%, 823/0/2 |
| c4 on origin/master 435d2db58 | – | – | 70.51% → 71.04%, 803/0/2 → 825/0/2 |

c4p is a scorer effect. With 11 near-identical arms, fixing one arm moves the alignment. The fix has to
be applied to all 11 arms.

### Tail merge

- **Mechanism.** The xjump hooks (`scripts/c2/xjump_trace.py`) on the base show the attempt
  `cross_jump_pair(pistol jmp, shrinkifier jmp)`:
  - 60 `tuples_equal` hits, back to projectile_spawn's `lea eax,&move_delta` against the shrinkifier's
    `lea eax,&random_offset`;
  - running byte sum 1+5+3+2+3+6 = **20**, so the attempt is refused. It is repeated six times per
    jump-optimizer run, with the same result.

  Native shared tail from `push eax`: 1+5+3+3+3+3 = 18, then +6 = 24 > 20, so it merges.

| Variant | Prediction | Observed | Score |
|---|---|---|---|
| m0: shrinkifier spawns from `&move_delta` (native) | whole-arm merge, not native | merge from `mov edx` (the `push 0x18`/`push 1` type constants differ before late_register_value_cse makes both `push eax`); random_offset loses references, frame reorders | 65.14%, 796/0/6 |
| m1: `(player_update_vec2_t *)&scratch_pos.x` in pistol | merge at `push eax` | C1 folds it to `&scratch_pos`, identical IL | 70.49% |
| m2a: function-scope `sprite_pos` for pistol's second sprite | – | **native merged shape** (`lea eax; fstp; fstp; jmp` into shrinkifier's `push eax`), but a new frame slot and every vector slot reordered | 65.46%, 806/0/6 |
| m2b: setter returning `v` used as the argument | – | C1 hoists the inline call before `push 2.0`, but C2 rematerialises `lea eax` at the push; identical code | 70.49% |
| m2c: block-scoped `sprite_pos` | – | shares slot 7 (frame 0x48), merge happens, but not held (x first; x87-held-lanes L5) | 65.49% |
| m2d: m2c plus a block-scoped `arm_position` pointer | – | not held | 65.09% |
| h2 (`const vec2f_t &` wrapper), h4 (`const` cast) | – | identical | 70.49% |

Why no simple spelling works:

- Address-taken function-scope vectors each keep their own slot (m2a).
- `tuples_equal` compares register operands by register and symbol operands by symbol.
- A constant address is rematerialised as `lea` right before its push (m2b).

So in native, the difference before `push eax` has to be in the pre-schedule IL, and it is not
visible in the output. It is not a register (eax in both arms), and not a constant address spelled
another way.

## 5. Open questions

- The native source difference right before the pistol arm's second `push eax`. A block-scoped vector
  shares a slot (m2c), so native's arms may use block-scoped vectors. The held-lane rule would then need
  the lane pointer in the same block, and m2d did not reproduce that.
- Native's cos/sin values are scalars: b0x08, and b0x0c, which is shared with the heading. Our
  address-taken `random_offset` has no native counterpart (native spawns the projectiles from b0x38).
  This frame difference may also be why native has the FROUND on the md.y lane.

## Tools

```sh
uv run python scripts/c2/sched_trace.py <scratch> --out <dir> --lines 1171-1204 --json   # windows, cycles
uv run python scripts/c2/alias_trace.py <scratch> --out <dir> --lines 1171-1204          # classes, memory edges
uv run python scripts/c2/xjump_trace.py <scratch> --out <dir> [--jump <tuple>]           # cross-jump walk
uv run python scripts/c2/il_stage_trace.py <scratch> --out <dir> --lines 1195-1195        # 0x162 at C1 entry
```
