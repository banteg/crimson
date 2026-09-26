# player_update: map of the residual and the native frame (C2.DLL 8966)

This note maps every mismatching region of `player_update` at 32b0ec7fa (unchanged through fac772fa2) to a C2
mechanism. It follows the model of [pr-residual-map.md](pr-residual-map.md). The largest part of the residual
was stack slot order. Twelve source changes rebuild most of the native 4-byte frame and raise the labels-masked
ratio by 5.4 points. The rest of the residual is listed with its mechanism and a verdict, and a separate list
covers what needs the 0x400 alias-class budget.

Addresses are C2.DLL virtual addresses (image base 0x10700000), `/O2 /GB`. Target addresses are crimsonland.exe
VAs. "Bottom" offsets are measured from the lowest local byte of the 0x48 frame (esp after the three register
pushes). Evidence labels:

- **verified**: seen in a compile, in `frame_predict.py`'s preserving observer, or in a trace;
- **read**: taken from the cited notes;
- **inferred**: fits every compile here but was not traced.

See also [frame-model.md](frame-model.md) (weights, list order, slot join), [pu-move-delta-split.md](pu-move-delta-split.md)
(escaped vectors and rule 5), [pu-id-delta-profile.md](pu-id-delta-profile.md) (operand orders, the inflater),
[pu-alias-budget-sources.md](pu-alias-budget-sources.md) and [unfolded-field-pointers.md](unfolded-field-pointers.md)
(the budget), [arm-local-builds.md](arm-local-builds.md) (rotation and cross-jumps).

## 1. Short answer

| Build | Raw | Labels | Structural | Stack | Refs | Residual lines | Objects at native offset |
|---|---|---|---|---|---|---|---|
| 32b0ec7fa | 74.40 | 83.76 | 84.55 | 94.11 | 863/0/0 | 708 | 13/38 |
| `best.diff` (12 features) | 73.80 | **89.15** | **89.94** | **94.56** | 792/0/0 | 484 | 25/43 |
| `best_raw.diff` (Q replaced by Q2) | **78.30** | 88.24 | 89.03 | 94.56 | 861/0/0 | 522 | 23/43 |

All rows are verified compiles. "Residual lines" is the sum of the per-class target lines of
`residual_map.py`. Refs are ok/unresolved/mismatch.

1. **58% of the residual was one thing: the native frame.** The base had 412 stack-class lines. Native keeps
   more, smaller variables than our source, and the packer shares them into slots differently. For example,
   native has separate floats for the fire section's aim heading, the weapon-arm direction (cos and sin), the
   movement speed factor, and the mode-2 key heading. Our source reused `movement_heading`, `random_offset`,
   `scalar` and `angle_step` for these (§3). [verified]
2. **Twelve respellings rebuild the 4-byte region.** The instruction count stays at 4146, except that BL
   removes two. Leave-one-out loses labels-masked lines for every one of them. Stack lines go from 412 to 205.
   [verified]
3. **The raw ratio is not a reliable guide here.** The `best.diff` set wins on every masked ratio but loses 0.6
   raw. `difflib` pairs native's mode-1 decelerate lanes (target lines 1019–1037) with an identical 18-line
   block in our mode 2. That throws about 200 lines out of alignment. Label-masked, it gains 40 target lines
   against `best_raw` and loses 2 (§6.3). `best_raw.diff` moves the mode-2 heading back and so avoids this misalignment. It
   gains on all four ratios but leaves the movement heading slots wrong.
4. **What remains of the frame needs the budget or is not yet reachable:**
   - **Native slot 0x14 is the muzzle pointer's home.** That home exists only under the 0x400 collapse. Without
     it, our next two slots sit 4 bytes low (57 operands).
   - **Native slot 0x38 is shared.** Velocities, spawn positions and the smoke colour share one 16-byte slot
     there. Our function-scope `move_delta` cannot share it (68 operands).
   - **Fire Cough's vectors have other homes** (17 operands).
5. **The code residual is listed in §4.**
   - Source-reachable and landed: the Sharpshooter arm order, the smoke template order and the blood offset.
   - Collapsed-regime: the muzzle pointer, `shot_cooldown`, the aim pointer, the swap, the tail `add edi`,
     the pellet `mov eax,esi`, the Fire Cough return loads and the Fire Cough colour.
   - Compiler-state: register rotation, cross-jump merges, and the spread's re-selected player (`ebx` colouring).
   - Unknown: the stored turn pair, the demo arms, Fire Cough's vector roles and the aim arms' held cosine.

## 2. Tools

```sh
uv run python scripts/c2/residual_map.py <scratch> [--show] [--json out.json]      # classes per region
uv run python scripts/c2/frame_bottom_diff.py <scratch> [--pairs] [--dump out.txt]  # new
uv run python scripts/c2/frame_whatif.py <scratch> --out <dir> --weight 'NAME=W'   # packer replay
```

`frame_bottom_diff.py` tracks esp through both listings (`frame_predict.binary_frames`) and rewrites each
`[esp+N]` as its bottom offset `[B+off]`. It prints the four `residual_map` ratios plus a `bottom` ratio: structural,
with bottom offsets instead of displacements. A push-depth difference pairs under `bottom`, and a slot difference
does not. `--pairs` lists (native bottom, candidate bottom) pairs over the lines that are equal under the stack
mask, with counts and native addresses. `--dump` writes the structural diff with bottom offsets and addresses.

For the base the bottom ratio is 81.94%, against 84.55% structural and 94.11% stack masked. So most stack-class
lines are slot differences, not push depths. For `best.diff` it is 90.06%.

The work directory also has:

- `slotmap.py`: the per-object native bottom votes of `native_slots.py`, with source lines, plus a dump of every
  native frame reference with its nearest source line;
- `families.py`: charges each residual line to one of the families of §4.

## 3. The native frame

### 3.1 What native keeps where

Native's 4-byte and 8-byte slots, from `frame_bottom_diff.py --dump` on the base and a reading of every native
reference by section (work directory `roles_base.txt`):

| Native bottom | Size | What native keeps there | Our base object there |
|---|---|---|---|
| 0x2, 0x3 | 1 | `perk_fire_ready`, `auto_fire` | same |
| 0x4 | 4 | final shot angle (pushed in every arm, `fadd` in pellet loops), spread angle, a Fire Cough int temp | `movement_heading` |
| 0x8 | 4 | the muzzle angle (heading − π/2), reused by the three flame arms; the mode-2 key heading; the swarmer step; weapon-arm direction x; the Man Bomb and Fire Cough owner ids | `scalar` |
| 0xc | 4 | movement speed factor (`speed_multiplier` snapshot, 22 lane `fmul`s); fire-section aim heading; weapon-arm direction y; pellet counters; Angry Reloader index; rocket heading | `angle_step` |
| 0x10 | 4 | late `scalar` (reload rate, pad aim, auto-aim, ammo cost); movement heading of modes 1, 3, 4 and demo; stored accelerate turn; smoke angle | temps |
| 0x14 | 4 | **muzzle_flash_alpha pointer home** (collapse only) and the blood angle | many temps |
| 0x18 | 8 | int→float temps, Fire Cough radius, target distance, Angry Reloader step; grown to 8 by Fire Cough's `vec2_sub` destination | 16-byte slot: temps, `previous_pos`, `smoke_color` |
| 0x20 | 8 | pellet int temps, spread radius; grown to 8 by `previous_pos` | – |
| 0x28 | 8 | weapon muzzle offset (`movement_input`) | same |
| 0x30 | 8 | sprite positions (`scratch_pos`), spread target, smoke drift direction | same |
| 0x38 | 16 | velocities, every projectile/particle spawn position, smoke colour, movement deltas | `move_delta` (8); `random_offset` at 0x40 |

### 3.2 How the packer produces it [verified on the controls in frame-model.md; per build with `frame_predict.py`]

Below 0x80 local bytes there is no density sort. `pack_stack_slots` 0x1074b617 walks the reference-count list:
size ascending, then weight descending, with ties going to the object that reached the count first. Each object
joins the **newest** existing slot it does not conflict with, if its size is at most twice the slot size.
Otherwise it opens a new slot, and FPO slots are laid out from bottom 0 upwards ([frame-model.md](frame-model.md)
§2, §4). So:

- the heaviest 4-byte object opens 0x4;
- each later slot is opened by the next object that conflicts with every earlier slot's members;
- lighter objects fall into the newest slot they fit;
- an 8-byte object that is light can join a 4-byte slot and grow it. Native's 0x18 and 0x20 are made this way.

Native's order therefore needs:

1. The shot angle to be the heaviest 4-byte object (35 references).
2. Direction x (33) to open 0x8, and direction y (33) to open 0xc. Direction y conflicts with direction x.
3. The fire heading (31) to join 0xc.
4. The speed factor (23) to be processed before the late `scalar`, so it joins 0xc. The late `scalar` then
   opens 0x10.
5. The movement heading, which is light and conflicts with the speed factor, to join 0x10.
6. The mode-2 key heading to be kept out of 0x10 and 0xc. Only a variable that is live across the fire section
   gets that, and this is why native's muzzle angle and key heading share one float.

`frame_whatif.py` confirmed step 4 before any source existed for it (§8, T1).

### 3.3 The source changes

| Feature | Source change | Frame effect |
|---|---|---|
| H | `fire_heading = player->aim_heading` in the fire gate; the fire section and arms read it | fire heading leaves `movement_heading` |
| D | `dir_x = cosf(fire_heading); dir_y = sinf(fire_heading);` in the 11 two-sprite arms, instead of `random_offset.x/.y` | native 0x8 / 0xc; `random_offset` weight 130 → 64 |
| S | `speed_scale = player->speed_multiplier;` for the 22 movement lanes; `scalar` starts at 836 | speed factor and late scalar become two objects |
| Q | one `turn_angle` for the mode-2 key heading, the muzzle angle `fire_heading − π/2` (passed by the three flame arms, as native pushes `[0x8]`) and the swarmer step | joins 0x8 because it is live through the fire section; `movement_heading` falls to 12 references |
| B | fire-bullets pellet: `float pellet_angle = ...` and the position built in `move_delta` | `scalar` 24 → 22, below `speed_scale` (23): step 4 above |
| SM | smoke: drift direction in `scratch_pos`, spawn position in `move_delta` | native 0x30 / 0x38 |
| W | spread target in `scratch_pos` instead of `random_offset` | native 0x30 |
| R | spread: `spread_radius = length * 0.5f` and `spread_distance = rand * (spread_radius * heat) * k` | only the first is stored, as native |
| SS | `if (perk_count_get(perk_id_sharpshooter) != 0) {...} else {...}` | layout: native lays out the perk arm first |
| SO2 | smoke template: `rotation` before `half_extent` (y, then x), `scale_step` after `rotation_step` | native store order; +3 refs |
| MH | mode 1 publishes `movement_heading = 1.0f` after the turn keys | native 0x414577 |
| BL | blood offset in the b20 shape of [load-recompute.md](load-recompute.md) | blood x87 identical to native |

Behaviour is preserved. Each split variable is written before every read on each path, and the merged roles
were already dead where the new variable takes over. The details are in the answer file. `crimson match
validate` passes on both diffs.

## 4. Residual table, source order

Lines are `residual_map` target lines charged to the family (base → `best.diff`). Scratch lines are HEAD's
`scratch.cpp`. "Inflated" is the non-stack residual under the diagnostic inflater (+207 `pu_diag_id`), applied
to `best.diff`.

| Family | Target range | Source | Lines | Separates labels/stack/exact | Mechanism | Verdict |
|---|---|---|---|---|---|---|
| E1 entry | 0x4136f3–0x41370d | 165–172 | 4 → 4 | order (native copies `previous_pos` before `fld health`) + slot | scheduler priority ([load-recompute.md](load-recompute.md) §3); slot 0x20 is one slot high without 0x14 | collapsed-regime (inflater: 2 → 1) |
| E2 blood | 0x4137b4–0x4137ed | 178–196 | 5 → 1 | x87 order, one store | CSE split by a propagated FROUND, held `dx` ([load-recompute.md](load-recompute.md) b20) | source-reachable: **BL**, verified; the last line is the 0x14 shift |
| P1 muzzle pointer | 0x413842–0x41385d, 0x415bcf–0x415be2, 0x415d86, 0x415ee5, 0x41760b–0x417624 | 199–203, 1223–1268, 2024 | 17 → 18 | `lea ecx,[edi+0x2fc]` + home at 0x14 vs folded `[edi+0x2fc]` | `forward_substitute_single_def_ranges` 0x107306c1 folds unless a class-1 store lies in the stretch ([unfolded-field-pointers.md](unfolded-field-pointers.md)) | collapsed-regime (inflater 18 → 1) |
| F1 Fire Cough | 0x413aba–0x413c02 | 284–314 | 34 → 30 | slots (21), addressing, x87 load order | native `[ebp+ADDR]` index addressing and `lea ebx,[ebp+ADDR]` for `this`; muzzle offset at 0x30, target at 0x28, `vec2_sub` destination at 0x18; `fld [eax]; fld [eax+4]; fxch` ([pu-firecough-heading.md](pu-firecough-heading.md) §4) | loads: collapsed-regime (native under the inflater). Vector roles: unknown (feature F puts them in native's objects, but `scratch_pos` then outweighs `movement_input` and the 8-byte order swaps, −8 labels) |
| F2 FC colour | 0x413c11–0x413c2e | 319–325 | 6 → 6 | `lea eax,[edx*4+ADDR]; mov [eax+k]` vs `shl eax,2; mov [eax+ADDR]` | reference `effect_color_t &` keeps a pointer. Direct field stores (CC) move `turned`/`normal_fire_ready` out of `bl` into stack homes (frame 0x4c) | collapsed-regime: the inflater alone gives native lines (6 → 0) |
| R1 rotation | 0x413c5b–0x413e64, 0x413f4b, 0x4158f2–0x415935 | 336–437, 1055–1071 | 30 → 30 | eax/ecx/edx picks, temp slots | /Ot local rotation cursor, one per function ([arm-local-builds.md](arm-local-builds.md) §1): upstream temp count mod 3 differs (F1, F2 differ in temps) | compiler-state |
| M4 target copy | 0x413f70–0x413f89 | 434–442 | 4 → 4 | native `fstp; mov eax,[slot]; mov [edi+0x324],eax` (struct copy) | aggregate copy lowering ([small-aggregate-copies.md](small-aggregate-copies.md)); `player->move_target = scratch_pos` (MT) gives native lines here but merges movement arms (4108 insns, 6 mismatches) | unknown |
| H1 heading slot 3/4/demo | 0x413fe5–0x414276, 0x414d6d | 450–455, 507–516, 743–769 | 8 → 0 | slot 0x10 vs 0x4 | §3.2 | source-reachable: H S Q B, verified |
| H2 mode-2 key heading | 0x414871–0x414aab | 642–704 | 11 → 0 | slot 0x8 vs 0x4 | §3.2 step 6 | source-reachable: **Q**, verified |
| T1 turn pair | 0x4140cc–0x4141a9, 0x414323–0x41435f, 0x4143e5–0x414408, 0x414b78–0x414c2b, 0x414e48 | 460–490, 521–545, 710–736, 774–800 | 32 → 22 | native `fld π; fsub st(2); fstp [0x10]`, no y store, `fmul [turn]` before `fmul [speed]` | turn stored because it crosses the held `heading − π/2` range ([x87-spills.md](x87-spills.md) §4); operand order is a creation-order site ([pu-id-delta-profile.md](pu-id-delta-profile.md) B1) | unknown. T (`movement_heading = π − angle_step`) and T2 (non-escaped `turn` vector) hold the turn on x87 instead (−0.1 labels, −0.4 stack) |
| R2 pad squares | 0x4141f1–0x4141fd | 502–505 | 2 → 2 | `x²` before the held `y²` | square-hash site 505 ([pu-id-delta-profile.md](pu-id-delta-profile.md)) | compiler-state (fixed under the inflater) |
| A1 push placement | 0x4143bf–0x4143ca, 0x414e37 | 540–544, 795–799 | 8 → 8 | `lea; push; push` before the lanes | scheduler fill of the fadd→FROUND gap ([x87-held-lanes.md](x87-held-lanes.md) §5); the copies are then merged | compiler-state |
| K1 key bytes | 0x41448a–0x4145e3 | 559–605 | 9 → 8 | native `mov al, byte [key]; push eax` vs `mov eax,[key]; and eax,0xff` | the shared `grim2d_cpp.h` declares `grim_is_key_down(unsigned int)`; native's callee takes a byte key | source-reachable only through the shared header (not tested) |
| M1 mode-1 builds | 0x414577, 0x41462d–0x414747, 0x4147ef | 549–640 | 23 → 15 | native keeps three held-lane builds; ours merges the back arm and builds decel plainly | `cross_jump_into_fallthrough` with rotation k mod 3 ([arm-local-builds.md](arm-local-builds.md)); MV (`pu_move_scaled` in decel) merges more (4127 insns) | compiler-state |
| D1 demo | 0x414c90–0x414d82, 0x414e67–0x414eee | 741–800 | 39 → 37 | SIB scale, int copies of the `>300` arm, merged accel arm | cross-jump merges (NOTES "movement twins"); `lea edx,[eax+ecx*2]; fld [edx*8+ADDR]` scale choice | unknown |
| SS Sharpshooter | 0x414f44–0x414fcd | 809–820 | 9 → 0 | branch layout | the fall-through arm is the then-arm | source-reachable: **SS**, verified |
| S1 reload | 0x414fce–0x4151bb | 836–879 | 12 → 12 | slots: stationary `scalar` 0x20, reloader temps | 0x14 shift; the reloader step at 0x18 | collapsed-regime (0x14); AR (ring step own float) is neutral |
| X1 aim schemes | 0x415333–0x415625 | 913–1019 | 26 → 22 | native `fst [angle]; fcos` held, sin stored/reloaded; ours sin first | x lane propagated: the `move_delta.y` store does not alias the angle ([x87-held-lanes.md](x87-held-lanes.md) §3). Native's angle is a separate float at 0x18, not `previous_pos.x` | unknown; the inflater gives cos-first but stores it (partial) |
| X2 auto-aim | 0x41564a–0x4156f5 | 1020–1044 | 17 → 14 | `lea ebp,[edi+0x50]`, square order | unfolded pointer; square site 1030 | collapsed-regime (AV: +0.04 stack under collapse) |
| X3 shot_cooldown | 0x415739–0x41577f | 1052, 1094–1106 | 4 → 4 | `lea ebp,[edi+0x2d4]` | unfolded pointer | collapsed-regime (4 → 0 inflated) |
| X4 swap | 0x415813–0x4158dd | 1072–1101 | 32 → 32 | sequential swaps, weapon-id `lea` | class-1 stores block substitution | collapsed-regime (`pu_swap`, §7) |
| G1 smoke | 0x415a70–0x415b93 | 1146–1175 | 28 → 19 | slots: smoke colour 0x38, angle 0x10 | `smoke_color` conflicts with the escaped function-scope `move_delta` ([pu-move-delta-split.md](pu-move-delta-split.md) rule 5) | order and roles: source-reachable (**SM, SO2**). Colour slot: unknown (0x38 group) |
| G2 spread | 0x415c03–0x415cd2 | 1188–1205 | 28 → 21 | native re-indexes the player (`lea; lea; shl ebx,5; [ebx+ADDR]`) | SP1 and SP3 reproduce the addressing, but `ebx` is re-coloured function-wide (saved-reg 9 → 35) | compiler-state (raw +5.6, labels −1.1) |
| B1 fire bullets | 0x415db6–0x415de4 | 1232–1246 | 11 → 8 | `mov eax, esi` position copy, slot 0x20 | pellet copy: collapse; slot: 0x14 shift | collapsed-regime |
| W1 weapon arms | 0x415ef3–0x4174d0 | 1276–1975 | 290 → 162 | see below | see below | mixed |
| Z1 tail | 0x4175f0–0x417602 | 2011–2023 | 3 → 3 | late `add edi,0x18` | pointer web split | collapsed-regime (3 → 0) |

Weapon arms (W1), after `best.diff`, split by kind:

- **Slots, 96 lines.**
  - Spawn positions and flame positions: native keeps them in the 0x38 group. Ours builds them in
    `random_offset`/`scratch_pos`.
  - Pellet int temps: the 0x14 shift.
  - The 0x38 group is unknown. Positions in `move_delta` (P, FL, PL) merge the arms (4073 insns) or swap the
    8-byte order. Per-arm block vectors (BP) grow the frame to 0x50.
- **Merged call tails, 26 code lines** (0x41685b, 0x416a27, 0x416ac0, 0x416e68, 0x41730c).
  - Native keeps each arm's `lea; fstp; push; push; fstp; call; add esp`. Ours cross-jumps the simple arms into
    one tail, because they build into one symbol. Native's symbols differ.
  - Verdict: collapsed-regime lead. BP under the inflater gives 4194 of native's 4206 instructions and stack
    +0.71.
- **Pellet loops' `mov eax, esi`, 18 code lines** (0x416349, 0x41645d, 0x4165e3, 0x416b29, 0x416ce2, 0x41733f).
  Collapsed-regime: native lines under the inflater.
- **Rotation and saved registers, 16 lines.** Compiler-state.

## 5. Ranking by lines recovered

| Rank | Family | Base | `best.diff` | Recovered | Remaining verdict |
|---|---|---|---|---|---|
| 1 | W1 weapon arms | 290 | 162 | 128 | 0x38 group unknown, tails and pellet copy collapsed |
| 2 | T1 turn pair | 32 | 22 | 10 | unknown |
| 3 | H2 mode-2 heading | 11 | 0 | 11 | done |
| 4 | G1 smoke | 28 | 19 | 9 | colour slot unknown |
| 5 | SS Sharpshooter | 9 | 0 | 9 | done |
| 6 | H1 movement heading | 8 | 0 | 8 | done |
| 7 | M1 mode 1 | 23 | 15 | 8 | compiler-state |
| 8 | G2 spread | 28 | 21 | 7 | compiler-state |
| 9 | E2 blood | 5 | 1 | 4 | 0x14 shift |
| 10 | F1 Fire Cough | 34 | 30 | 4 | collapsed / unknown |
| 11 | X1 aim | 26 | 22 | 4 | unknown |
| – | the rest (P1 R1 M4 R2 A1 K1 D1 S1 X2 X3 X4 B1 Z1 F2 E1) | 198 | 191 | 7 | as in §4 |

Of the 484 lines left, by family:

- **145 are collapsed-regime:** P1, F2, X2, X3, X4, Z1, E1, S1 and B1, plus W1's pellet copies (18) and call
  tails (26). The 0x14-shift stack lines inside other families come on top of these.
- **76 are compiler-state:** R1, R2, A1, M1 and G2.
- **8 depend on the header:** K1.
- **The rest, about 255, are unknown:** F1, M4, T1, D1, X1, G1, and W1's 0x38-group slots and rotation.

## 6. Feature build

`build.py out.cpp FEATURES...` applies `feat/<NAME>.py` to HEAD's source. `sweep.sh NAME FEATURES...` builds and
scores, and `loo.sh PREFIX FEATURES...` runs leave-one-out (work directory).

### 6.1 Cumulative (`best.diff` order)

| Build | Raw | Labels | Structural | Stack | Refs |
|---|---|---|---|---|---|
| HEAD | 74.40 | 83.76 | 84.55 | 94.11 | 863/0/0 |
| +H | 73.97 | 84.55 | 85.34 | 94.11 | 854/0/0 |
| +D | 74.81 | 84.17 | 84.96 | 94.11 | 864/0/0 |
| +S | 74.43 | 86.78 | 87.57 | 94.11 | 828/0/**1** |
| +Q | 74.86 | 87.21 | 88.00 | 94.11 | 828/0/**1** |
| +B | 72.46 | 87.84 | 88.63 | 94.11 | 787/0/0 |
| +SM | 72.63 | 88.00 | 88.79 | 94.11 | 787/0/0 |
| +W | 72.75 | 88.12 | 88.91 | 94.11 | 787/0/0 |
| +R | 73.37 | 88.75 | 89.54 | 94.11 | 787/0/0 |
| +SS | 73.54 | 88.96 | 89.75 | 94.32 | 789/0/0 |
| +SO2 | 73.61 | 89.03 | 89.82 | 94.40 | 792/0/0 |
| +MH | 73.64 | 89.06 | 89.85 | 94.42 | 792/0/0 |
| **+BL = best.diff** | 73.80 | **89.15** | **89.94** | **94.56** | 792/0/0 |

The mismatch after S and Q (0x414185, a constant of the mode-4 decelerate lane) is an alignment effect. It goes
away when B restores the slot order.

### 6.2 Alone on HEAD, and leave-one-out from `best.diff`

| Feature | Alone: raw / labels / struct / stack, refs | Dropped from best: raw / labels / struct / stack, refs |
|---|---|---|
| H | 73.97 / 84.55 / 85.34 / 94.11, 854 | 70.56 / 85.01 / 85.80 / 94.56, 800 |
| D | 74.40 / 83.76 / 84.55 / 94.11, 863 | 75.88 / 85.68 / 86.47 / 94.56, 861 |
| S | 69.73 / 84.20 / 84.99 / 94.11, 794 | 75.66 / 85.01 / 85.80 / 94.56, 869 |
| Q | 74.50 / 83.86 / 84.65 / 94.11, 864 | 78.13 / 88.07 / 88.86 / 94.56, 861 |
| B | 74.45 / 83.81 / 84.60 / 94.11, 863 | 76.17 / 88.50 / 89.29 / 94.56, 833/0/**1** |
| SM | 74.57 / 83.93 / 84.72 / 94.11, 863 | 73.63 / 88.98 / 89.77 / 94.56, 792 |
| W | 68.92 / 78.16 / 78.11 / 94.11, 863 | 73.68 / 89.03 / 89.82 / 94.56, 792 |
| R | 74.35 / 83.72 / 84.51 / 94.11, 863 | 73.17 / 88.53 / 89.32 / 94.56, 792 |
| SS | 74.57 / 83.98 / 84.77 / 94.32, 865 | 73.63 / 88.93 / 89.72 / 94.35, 790 |
| SO2 | 74.47 / 83.84 / 84.63 / 94.18, 866 | 73.72 / 89.08 / 89.87 / 94.49, 789 |
| MH | 74.40 / 83.76 / 84.55 / 94.13, 863 | 73.75 / 89.13 / 89.92 / 94.54, 792 |
| BL | 74.59 / 83.90 / 84.69 / 94.25, 863 | 73.64 / 89.06 / 89.85 / 94.42, 792 |

Refs without a suffix have no mismatches. The frame features work only together; alone, most of them only
reorder slots. For example, D alone gives the same ratios (a different object). Every leave-one-out row is
below `best.diff` on labels and structural.

### 6.3 Raw against labels

`label_drift.py --against` for `best.diff` against `best_raw.diff`:

- **Label-masked**, `best.diff` gains 40 target lines and loses 2 (target lines 3844–3845).
- **Raw**, it gains 26 and loses 214. None of them is a branch label. They are ranges from target line 1040 to about
  1140, plus the regions after them.

Cause, from the matching blocks:

- In `best.diff` the raw matcher pairs target lines 1019–1037 with candidate lines 1127–1145.
  - Target lines 1019–1037 are native's mode-1 decelerate lanes and held-lane build.
  - Candidate lines 1127–1145 are the identical mode-2 decelerate block.
- The next block then starts at candidate line 1317. About 200 candidate lines are skipped.
- Our own mode-1 decelerate block differs by labels and by the held build (M1), so the longest-match heuristic
  prefers the wrong copy.

This is the SequenceMatcher cross-arm effect that [pu-factor-order.md](pu-factor-order.md) §3 also saw. Two
things would repair it:

- fixing M1;
- dropping Q (`best_raw.diff`: Q2 moves only the swarmer step, and the key heading stays in
  `movement_heading`).

## 7. Collapsed-regime findings

The diagnostic inflater (+207 `pu_diag_id`, 2 classes each, 0x400 reached) is not source. It wraps
`rocket_heading` past 0x800 and reverses one `fadd` ([pu-id-delta-profile.md](pu-id-delta-profile.md) §3.2), and it
grows the frame to 0x4c. So compare against the inflated baseline, not the canonical build:

| Build under the inflater | Raw | Labels | Structural | Stack | Refs | Frame |
|---|---|---|---|---|---|---|
| HEAD + inflater | 66.05 | 75.70 | 76.70 | 94.46 | 837/0/2 | 0x4c |
| `best.diff` + inflater | 67.38 | 81.21 | 82.31 | 94.91 | 792/0/2 | 0x4c |
| `best_raw.diff` minus BL + inflater (reference for the rows below) | 71.16 | 80.26 | 81.36 | 94.77 | 857/0/2 | 0x4c |

The rows below are against that reference. Below the budget, the same source is compared with 78.09 / 88.10 /
88.89 / 94.42, 861/0/0.

| Lead | Under the budget | Below the budget |
|---|---|---|
| **Muzzle pointer home at 0x14.** The pointer declared at first use gets a home under collapse. It is the native slot 0x14 (`muzzle_flash_alpha` at bottom 0x14 in every inflated frame), and it shifts the next slots to native 0x18. | P1 18 → 1 non-stack lines, the 0x14 shift disappears | no home, 57 slot operands 4 bytes low |
| **`pu_swap`** × 7 ([pu-alias-budget-sources.md](pu-alias-budget-sources.md) §4.1) | +0.72 / +0.58 / +0.17 / +0.16, 861/0/2 | −0.61 / −0.57 / −0.21 / −0.25, 850/0/0 |
| **Block auto-aim vector** (s2a) | +0.02 / +0.03 / −0.19 / +0.04, one mismatch fewer (860/0/1) | −5.8 / −7.1 / −8.0 / −0.06 |
| **Per-arm spawn vectors** (BP): each arm builds its position in its own block vector | stack +0.71, 4194 instructions (native 4206: the call tails stop merging), labels −0.16, frame 0x50, 842/0/3 | frame 0x4c, labels −8.7, 860/0/4 |
| **Fire Cough colour through the pool fields** (CC) | raw +0.54, structural +0.11, labels −2.6, 865/0/1 | frame 0x4c, `turned`/`normal_fire_ready` lose `bl`, labels −16.7 |
| **Spread re-selected player** (SP3) | neutral (−0.03 / −0.01 / −0.01 / 0, 858/0/3) | raw −0.01, labels −1.1, stack −1.0 |
| **Mode-2 key heading only** (M, on top of Q2) | labels +0.70, raw −4.3 (the §6.3 misalignment) | same trade |

What the inflater alone changes on `best.diff` (non-stack residual lines per family, §4):

- P1 18 → 1;
- F2 6 → 0 (the colour stores become native with no source change);
- X3 4 → 0;
- Z1 3 → 0;
- R2 2 → 0;
- E1 2 → 1;
- the Fire Cough return loads become `fld [eax]; fld [eax+4]; fxch`;
- the six pellet-loop `mov eax, esi` copies appear.

It makes F1 (a moved 20-line block) and W1 (rotation in the 0x4c frame) worse, so the net is not a fair
measure.

**The frame under the budget.** The inflated frame has native's slots at 0x4 through 0x18: shot angle, muzzle
angle, speed factor, late scalar, muzzle home, temps. It is 4 bytes too large. Two changes remain, and both are
blocked by rule 5 of [pu-move-delta-split.md](pu-move-delta-split.md) (an escaped function-scope vector conflicts
with every object defined before a later call):

- `random_offset` would have to be reduced to the Fire Cough `vec2_sub` destination, so that it joins the 0x18
  slot;
- `smoke_color` would have to join the 0x38 slot.

Native's 0x38 group suggests block-scoped or temporary vectors for velocities and positions, the SDK value
style. Those grow our frame in both regimes.

## 8. Acceptance tests

"Predicted" means the prediction was written before the compile. "Explained" means the compile came first.

| Test | Prediction | Observed |
|---|---|---|
| T1 (predicted) | `frame_whatif.py --weight '_speed_scale$=25'` on HDSM/HDSQ: `speed_scale` joins 0xc and `movement_heading` joins 0x10 as soon as `scalar` weighs less than `speed_scale`. Source: B removes 2 `scalar` references | HDSQB: `scalar` 24 → 22, `speed_scale` at 0xc, `movement_heading` at 0x10 ✓ |
| T2 (predicted) | Q: a float live from the fire gate to the flame arms conflicts with the fire heading and the late scalar, so it opens no slot and joins direction x at 0x8 | `turn_angle` in the 0x8 slot ✓ |
| T3 negative control (predicted) | M: a mode-2-only float conflicts with nothing in 0x10, so it joins the newest compatible slot (0x10), not native's 0x8 | k12: `key_heading` in the 0x10 slot with `scalar` ✓ |
| T4 (predicted) | Under the inflater the muzzle pointer gets a 4-byte home that becomes slot 0x14, and the temp slot lands at native 0x18 | every inflated frame: `muzzle_flash_alpha` at bottom 0x14, temps at 0x18 ✓ |
| T5 negative control (predicted) | BP: block vectors defined before later calls conflict with the escaped `move_delta` and cannot share its slot, so the frame grows | 0x50 (0x4c below budget) ✓ |
| T6 (explained) | F: moving the Fire Cough roles to native's objects makes `scratch_pos` (190) heavier than `movement_input` (187) and swaps 0x28/0x30 | swap observed; labels 80.4 |
| T7 (predicted) | SS: the positive perk test lays out the perk arm first, as native's `je` shows | region 0x414f44 matches ✓ |
| T8 (explained) | SO: rotation before half extent fixes the store window, but the two 2.0 stores come out x then y against native's y then x | 2 ref mismatches; SO2 (y first) gives 792/0/0 ✓ |
| T9 (predicted) | Direction and heading splits (H, D, S) move only slots, so the stack-masked ratio stays 94.11 | 94.11 in every H/D/S/Q/B/SM/W/R build ✓ |

## 9. Corrections to existing notes

- **`player_update/NOTES.md` "Structural residual handoff (2026-08-13)".** It advises against local changes:
  "Do not reopen the old edge conflict or add, widen, or hoist locals: the frame already matches". The frame
  size matches, but the slot contents did not (13/38 objects at native offsets). Splitting merged locals is what
  recovers them.
- **[pu-id-delta-profile.md](pu-id-delta-profile.md) §3.2** is correct, and this adds the owners of its slots:
  - The −56 slot (bottom 0x10), which holds the turn and the auto-aim distance, belongs to the late `scalar`.
    The auto-aim distance is that `scalar`.
  - The −60 slot (0xc) holds the movement speed factor. That factor is a different variable from the later
    `scalar` (feature S).
- **[pu-move-delta-split.md](pu-move-delta-split.md) §5.** The native object at 0x38 is 16 bytes and holds much
  more than `move_delta` and `smoke_color`. It also holds every projectile and particle spawn position and the
  Fire Cough position. Native's `random_offset` role is split over 0x8/0xc (direction), 0x30 (spread target),
  0x28 (Fire Cough target) and 0x18 (the `vec2_sub` destination).
- **[per-arm-frame-weights.md](per-arm-frame-weights.md) §2** says native uses the same four 8-byte addresses
  b0x28, b0x30, b0x38 and b0x40. It does not: 0x38 is one 16-byte slot, and nothing at 0x40 is an 8-byte object
  of its own. Native references to 0x40/0x44 are only the upper half of the smoke colour (2 + 2).
- **`native_slots.py` / `frame_predict.py --native`** vote one native base per candidate object. When native
  splits a merged variable, the object is attributed to the majority slot and the other roles show as conflicts.
  `slotmap.py` in the work directory lists the votes per source line.

## 10. Open questions

- The stored turn with the dead y lane (T1). The turn must cross the held `heading − π/2` range. Neither a scalar
  (T) nor a non-escaped vector (T2) does.
- A source for the 0x38 group that neither merges arms nor grows the frame. It would also settle the smoke-colour
  slot and the call tails.
- Why the Fire Cough block addresses the firing player as `[ebp+ADDR]` with an index register, as the spread
  does, without re-colouring `ebx` function-wide.
- The aim arms' held cosine (X1). Native's angle float lives at 0x18. Something must make the `move_delta.y` store
  alias it.
- The mode-1 builds (M1). Fixing them would also remove the raw misalignment of §6.3.
