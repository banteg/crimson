# C2.DLL frame model: reference counts, homes and local offsets

This note covers the symbol and block fields that decide the stack frame of an optimized
(`/Og`) function in the pinned VC6 back end (C2.DLL 12.00.8966, base 0x10700000). It covers
which values get a stack home, how many references each home gets, and where the packer puts
it. The static reading of the passes is in [frame.md](frame.md) §1 and [regalloc.md](regalloc.md).
This note adds what was **traced** with observer hooks on real compiles, the corrections those
traces forced, and two worked acceptance tests.

Unless a claim is marked *static* or *inferred*, it was checked against compiler observations.

## 1. Tooling

`scripts/c2/frame_predict.py` compiles a scratch through the pinned C2 with an observer. It checks
that the observed object equals the normal compile (COFF, timestamp excluded), then records:

- the start of every stack-layout pass, and every call to `order_stack_object`, with the tuple
  kind, opcode, line, operand kind and block loop depth;
- at entry to `pack_stack_slots` 0x1074b617, every stack object: class, flags, type, size, weight,
  frame index, front-end record fields, name and interference set;
- at exit from `pack_stack_slots`, the slots and each object's final offset, plus the frame size
  from `generate_prolog_epilog`.

It then replays the reference-count list and the packer in Python and checks both against the
compiler. It prints each object's size, weight, flags, slot and offset, the offset from the frame
bottom, and a pure-source what-if column.

```sh
uv run python scripts/c2/frame_predict.py tools/match/scratches/<name> --out /tmp/<new-dir> [--json out.json]
uv run python scripts/c2/frame_predict.py <scratch> --out <dir> --source variant.cpp   # compile a source variant
uv run python scripts/c2/frame_predict.py <scratch> --out <dir> --decisions            # allocator events too
uv run python scripts/c2/frame_predict.py <scratch> --out <dir> --native               # native vs candidate refs per dword
uv run python scripts/c2/frame_predict.py <control-dir> --out <dir> --all --control    # synthetic controls only
```

`--decisions` adds hooks on these allocator events, for named and pointer-typed live ranges:

- forward substitution, `forward_substitute_single_def_ranges` 0x107306c1, including its two
  `has_intervening_base_definition` checks;
- the three other `substitute_definition_into_uses` callers (rematerialization);
- `demote_live_range`, from both of its callers;
- `split_range_at_block_entries`;
- `choose_register_for_live_range`, including the register it picks.

It also dumps every named-range operand just before 0x306c1. `--native` uses `binary_frames()` in the same file. It
tracks esp depth through a target or candidate listing, which gives frame offsets and reference
counts from bytes alone. It was validated against the VC6 `.cod` listing annotations: 679 of 679
and 104 of 104 `name$[esp+N]` operands agree.

The tool cannot yet handle scratches whose `SOURCE` is a relative path outside the scratch
directory. Hook indices are its own; it does not use `profile.json`.

**Validation.** The replay reproduced every offset and the reference-count list order for:
- 93 functions with 1,833 stack objects, from 104 randomly sampled scratches with local sources.
  11 of those frames were density-sorted.
- The three scratches that first failed on references to objects homed before counting. They pass after the fix.
- `projectile_render` (182 objects) and `creature_update_all` with 11 source variants.
- Eight synthetic controls. They cover `&local`, arrays, structs passed by address, `volatile`,
  inline asm, `setjmp`, `char`/`short` in ebp and FPO frames, dead-parameter reuse, the
  no-reuse redo, and an 8-aligned double frame.

## 2. Reference counts (weights)

The counter is `count_stack_object_references` 0x10733e75, which calls `order_stack_object` 0x1073c7e4.

- **When:** inside `stack_frame_layout_pass`. That is after global colouring, local colouring and
  the /G5 memory-operand splits, and before prolog/epilog, both jump-optimizer runs, final
  lowering peepholes, the block mover and the scheduler.
  - Weights therefore count the post-allocation machine tuples.
  - Across `projectile_render`'s 53 slots, the final instruction reference counts match the weights
    within 0 to 4, and exactly for 48 slots. The gaps are later peepholes, such as
    `fstp m; fld m` → `fst m`.
- **Walk order:** blocks in list order (the pre-block-mover layout), tuples forward. In each real
  tuple the source list is walked, then the destination list.
- **What counts:**
  - An operand of kind 2 (memory symbol) or kind 3 (address of symbol) adds 1 to `sym->parent`.
  - A kind 5/6 operand with a direct symbol (+0x20) adds 1 to that symbol's parent.
    - A field or part reference counts for the whole object.
    - A `lea r,[esp+x]` of an array counts.
  - Only classes 3 (temp), 4 (named local) and 5 (param) are counted. The EH record and the `/GX`
    guard local are skipped because they are homed before counting (0x1073c7f7).
- **Memory-effect operands (kind 11)** expand to every member of their alias class, but **only in
  tuples of kind 0x15, which are inline-asm blocks (IL op 0x191)**. Calls do not contribute.
  - Control `ctl_main`: `addr` has its address taken before nine calls, and its weight is exactly
    its three loads and one store.
  - Control `ctl_asm`: each `__asm` block adds 1 to every address-taken local (`c`: 2 blocks → +2)
    and 1 to each local the block names (`a`, `b`).
- **No loop weighting.** Each reference adds exactly 1. The list replay (+1 per reference)
  reproduced all 1,833 sampled objects.
- **List order** (0x1073c876): size ascending. A new object goes to the end of its size group.
  On a repeated reference it moves toward the head past same-size predecessors with a strictly
  smaller count. Among equal counts, the object that reached the count first in walk order comes first.

## 3. Sizes, alignment and flags

**Size** is `sym+0x20` in bytes. Observed alignment (`align_frame_offset` 0x10703f7b):

- a `char` (1) is not aligned;
- a 2-byte object is 2-aligned;
- everything else is 4-aligned, including doubles, except in an 8-aligned frame.
  - In `ctl_double` (fn flags 0x600000) the double slots are at 8-aligned offsets.
- In controls, an address-taken `short` was stored as a 4-byte `int` (type 0x1004), not as 2 bytes.

In an ebp frame a smaller member sits at the high end of its slot: `char`s at −1 and −2 in
`ctl_bytes`. In an FPO frame every member sits at the slot base.

**Storage symbol `c2_symbol` (0x54)**, stack-layout fields, all verified by the replay:

| Offset | Role |
|---|---|
| +0x20 | size |
| +0x28 | final frame offset of a class-3 temp. Class 4/5 objects write `fe+0x0c` instead and set `fe+0x14` bit 0x800. |
| +0x2c / +0x30 | next / prev in the reference-count list (`g_stack_object_order_head` 0x1079f220) |
| +0x34 | weight (reference count) |
| +0x38 | index into `g_stack_object_table` and the interference bitsets |

**`flags5`** (+5):

| Bit | Meaning | Set by |
|---|---|---|
| 0x04 | address taken: a kind-3 `&sym` operand (`&x`, an array or struct passed by address) | `sub_1071ad76` 0x1071ae39, from `compute_alias_points_to` |
| 0x40 | volatile access. Operand `flags10` 0x40 makes `pass_mark_register_candidates` skip the symbol. | 0x1078a262 |
| 0x02 | memory-resident aggregate or field class, including every `$T` C++ temporary | 0x1071b0b4, 0x1078b764 |
| 0x06 | an inline-asm address operand | `sub_1078b6f6` |
| 0x20 | homed by the packer (class-3 objects) | 0x1074babb |
| 0x08 | observed on named scalar locals and params that are register candidates; absent on `a` in the `setjmp` control | writer not identified |

**`flags6`**:

| Bit | Meaning | Set by |
|---|---|---|
| 0x04 | conflicts with every stack object (packer, 0x1074b6eb) | not seen in controls |
| 0x10 | read by an inline-asm block | 0x1078b78c |
| 0x02 | on most named locals | meaning unknown |

Observed combinations:

| Local | flags5 |
|---|---|
| plain scalar | 0x08 |
| `volatile` | 0x48 |
| `&`-taken | 0x06 |
| aggregate | 0x02 or 0x06 |
| used by asm | 0x0a (flags6 0x12) |

**Front-end record** (`c2_fe_symbol`):

- `+0x36` storage bits:
  - low nibble is the type kind: 1 int, 5 float, 6 aggregate;
  - bits 4..6 are the class: 1 auto → class 4, 3 param → class 5;
  - 0x200 is set on every local;
  - 0x10000 marks an array;
  - 0x80000 marks a compiler temporary. Those have `+0x30` = 0x26 and appear as `$Tnnnn` in listings.
- `+0x28` is the id that VC6 listings print as the `name$nnnn` suffix.
- `+0x14` is 0x100 for locals and 0x900 for params.

**Setjmp and inline asm.**
- `setjmp` sets fn flag 0x40. The function loses FPO and dead-parameter reuse, and even a
  non-address-taken local stays in memory (`a` in `ctl_setjmp`).
- Inline asm sets fn flag 0x1, which gives an ebp frame.

## 4. Packing, verified rules

- **Dead parameter homes are reused** (`ctl_small`: `addr` sits at `+8`, the home of `n`).
- In an FPO or aligned frame that reused a parameter slot, reaching `local_bytes ≥ 0x70` repacks
  without parameter reuse. `ctl_redo`: `addr` moves from `+8` to −0x84. After the repack the
  parameters have no slot and keep their homes.
- Joining a slot needs `size ≤ 2 × slot size` and no conflict in either direction. The slot is
  scanned newest first, and joining grows the slot. `projectile_render` and the creature frames
  confirm it.
- Local bytes above 0x80 trigger the density sort: `weight*1000/size`, signed division,
  K&R quicksort with the middle pivot swapped to lo and a strict `>`. It covers local slots only.
- FPO frames allocate slots from the last one to the first, so slot 0 is at `[esp+pushes]`.
  Ebp frames allocate slot 0 first, closest to ebp.

The Python `simulate()` in the tool implements all of this, and it is what produced the
predictions below.

## 5. What makes a value get a home

A **named scalar local** is a register candidate unless:
- it is volatile, or its address is taken;
- it is a float and `/Op` is set;
- it is in a `setjmp` function.

A candidate gets a home only if the allocator leaves some of its references in memory.

**Field pointers** (`float *p = &base[i].field`) are named, single-definition ranges.
`forward_substitute_single_def_ranges` 0x107306c1 folds the `lea` into every use, and the pointer
disappears. In `creature_update_all` the decision trace shows `health`, `lifecycle_stage`,
`collision_flag`, `size` and `attack_cooldown` all forward-substituted.

The pass works in two phases. *Static*, read from the disassembly at 0x10730721..0x107307e1:
1. Phase 1 excludes a range (lr+5 |= 4) when:
   - a use is seen before any def in walk order;
   - the pointer value is used other than as an address part, unless the use is a plain `/Ot` register copy;
   - `sub_10731bbf` rejects an address use;
   - a second def has a different opcode or tree (`compare_trees`);
   - the def is not a foldable address (`is_foldable_address_definition`).
2. Phase 2 checks `has_intervening_base_definition` for the base and the index up to the range
   end. The trace shows these checks returning 0 for the substituted pointers.

**Source pattern that retains a field pointer** (verified): assign the pointer, then write the
*next* read of that field as a direct field access (`creatures[i].f`) rather than through the
pointer. The optimizer then value-numbers the pointer definition and the direct access to one
address temporary. The named range is gone before 0x306c1: it is absent from the range dump, and
the class-3 home appears instead. That temporary is live across calls. Global colouring splits it
into region pieces: the decision trace shows the pointer pieces coloured with lr flags 0x2c, and
0x20 is set by `requeue_split_pieces`. The value lives in a stack home between pieces. The home
is a **class-3 object** whose weight is one store plus one reload per region. This is exactly the
native pattern: `lea reg,[esi*8+field]; mov [esp+x],reg`, then later `mov r,[esp+x]; fld [r]`.

The range dump confirms which pointers reach 0x306c1 as named ranges:
- canonical source: the named ranges for `health`, `lifecycle_stage`, `collision_flag`, `size`
  and `attack_cooldown` are all present;
- y10 (§6): none of them are;
- `target_player` is not a named range in either source.

Why that temporary escapes forward substitution is still open (see Open questions).

## 6. Acceptance (a): `creature_update_all` pointer homes

**Native frame, decoded.** Offsets are `esp` after the four pushes. Members come from esp-tracked
native references and a listing alignment. The frame is 0x7c with no density sort.

| esp | slot | native members (reference addresses) | refs |
|---|---|---|---|
| 0x10 | s0 | creature_index | 17 |
| 0x14 | s1 | retarget/movement `distance`; **&size**: 0x426e36 store, reloads at 0x4271ee and 0x42741b | 14+3 |
| 0x18 | s2 | phase_angle, interaction_distance | 9+6 |
| 0x1c | s3 | move_scale | 8 |
| 0x20 | s4 | alternate_distance | 4 |
| 0x24 | s5 | **&health** (0x4262b7 plus 4 reloads), a corpse-arm float temp | 5+5 |
| 0x28 | s6 | **&lifecycle_stage** (0x426575, 0x427062, 0x427436) | 3 |
| 0x2c | s7 | int→float temp (0x427122) | 2 |
| 0x30 | s8 | **&collision_flag** (0x42658f, 0x4273ff), corpse `fild` temps | 2+6 |
| 0x34.. | s9..s19 | eleven 8-byte slots, starting with `contact_delta` | |

**Prediction from the model.** The inputs were:
- the candidate's own objects and interference sets from the observer;
- `creature_index` weighted 17;
- four 4-byte pointer objects, weighted by one store plus their native reloads (health 5,
  lifecycle 3, collision 2, size 3);
- conflicts decided by source-line overlap. The three loop-carried locals, `creature_index`,
  `alternate_distance` and `move_scale`, conflict with everything because the compiler's
  interference sets show them conflicting with disjoint objects.

Packing those inputs gives **exactly the native frame**: 0x7c, the same nine 4-byte slots at the
same offsets, and the 8-byte region from esp+0x34 (`native_model_cu.py` in the work dir). The
order follows from the rules:

1. Slot order is creation order, because there is no sort below 0x80. So the list order is
   creature_index (17) > distance (14) > phase (9) > move (8) > interaction (7) > alternate (5)
   and health (5) > lifecycle and size (3) > the temp and collision (2).
   - alternate_distance and health tie at 5, and alternate_distance reaches 5 first.
   - The int temp and collision tie at 2. The temp's second reference (0x42712b) comes before
     collision's (0x4273ff).
2. **&size** reaches 3 before lifecycle does, at 0x42741b versus 0x427436, so it is placed while
   slots s0..s5 exist. Scanning newest first, it conflicts with:
   - health (s5);
   - the loop-carried alternate (s4) and move_scale (s3);
   - interaction_distance (s2), which is live over size's range.

   Distance's last use (0x426993) comes before size's definition (0x426e2f), so size joins s1.
   That is why native `&size` sits at esp+0x14.
3. **&health**, **&lifecycle** and **&collision** conflict with every earlier slot, so each opens
   a new slot: s5, s6 and s8.
4. The int temp at 0x427122 falls inside lifecycle's range and cannot join s6, so it opens s7.
5. The corpse-arm temps join the pointer slots, because the pointers are dead in the corpse arm.

Two conditions come out of the model:
- The native `creature_index` must have at least 15 memory references, more than `distance`'s 14.
  The candidate has 11.
- The pointers must be **class-3 homes** with those weights.

**Source experiments.** All run on work-dir copies. Metrics are ratio, candidate/target
instructions, and references ok/problems.

| Variant | Change | Frame | Metrics | Homes |
|---|---|---|---|---|
| canonical | none | 0x6c | 66.6667%, 1311/1338, 363/5 | none |
| y2 | `if (creatures[i].lifecycle_stage == 16.0f)` right after the pointer assignment | 0x70 | 67.5452%, 1318, 365/6 | lifecycle, weight 3, at esp+0x24 |
| y3, y4, y5 alone | the same pattern for health, collision or size | 0x6c | unchanged | none |
| y6 | the pattern for health, lifecycle, collision and size | 0x80 | 65.8180%, 1333, 345/8 | health 5, lifecycle 3, collision 3, size 2, plus a &target_player home of weight 4 |
| **y10** | y6 plus `if (creatures[i].attack_cooldown > 0.0f)` | 0x80 | **68.2963%, 1362, 370/6** | creature_index **17**, health **5**, lifecycle **3**, collision **2**, size **3**, &attack_cooldown in **EBP** (as native) |

The whole COFF objects are byte-identical, apart from the timestamp, to the earlier compiler
interventions:
- **y6** equals `four-homes`;
- **y10** equals `five-values`.

Both are from [creature-pool-review](../../evidence/creature-pool-review-2026-09-23/README.md),
reproduced here with its verifier. So those "retain through both mechanisms" diagnostics are
reachable from ordinary source.

y10 is the complete y10 diff. It changes five first reads, each now a direct field access:

| Line | Original first read |
|---|---|
| 133 | `*health` |
| 226 | `*lifecycle_stage` |
| 228 | `*collision_flag` |
| 526 | `*size` |
| 559 | `*attack_cooldown` |

**Remaining difference, from the model.** y10 still spills `&target_player` twice:
- a 13-reference address temporary across the retarget block, source lines 180..222;
- a 3-reference home in the contact block.

Native keeps that value in EBX. Removing just those two objects from y10's own compiler data and
repacking gives a 0x7c frame with every 4-byte slot at the native offset:
- creature_index 0x10, distance+size 0x14, phase+interaction 0x18, move 0x1c, alternate 0x20;
- health+corpse temp 0x24, lifecycle 0x28, int temp 0x2c, collision+fild temps 0x30.

The frame residual is therefore exactly the `&target_player` allocation. No source form tried here
put it in EBX.

Negative controls, none of which retain the pointers:
- redefining `health` with the same tree (x6);
- moving the cooldown definition up (x8);
- moving the health definition after the first test (y1);
- global `creature_pool[...]` bases instead of `creatures[...]` (v2): frame 0x78 but 55.23%,
  because it breaks the scaled addressing;
- hoisting the definitions: x4 and x10 retain only lifecycle, as a weight-4 home, 67.24% and 67.02%.

The y10 edits are the same memory reads written differently. No execution fixtures were run on
the variants.

## 7. Acceptance (b): `projectile_render`

- **Candidate frame, 0x184.** The model reproduces all 182 objects: 52 local slots plus the
  parameter slot, density-sorted, all offsets exact. Local bytes are 0x184 > 0x80.
  - Slot weights range from 39 (a 4-byte slot of `step`, 5×`segment_index`, `pulse_scale` and
    three temps, density 9750) down to seven 8-byte `$T` slots of weight 2 (density 250) at the
    top of the frame.
- **Native frame, 0x19c, decoded** from esp-tracked references with no depth conflicts:
  - five 4-byte slots and 49 8-byte slots (412 bytes);
  - the candidate has seven 4-byte slots and 45 8-byte slots (388 bytes);
  - the native order is density-descending when final-code reference counts stand in for weights:
    - a 4-byte slot of density ~9000 at esp+0x10;
    - then 5500, then an 8-byte slot of 4500 ({`$T4977`, `segment_index`×5, `fade`×2, `step`});
    - and so on down to 8-byte slots with 2 references at the top.

  **The native layout obeys the model.**
- **Comparison.** An alignment of candidate listing symbols to native instructions maps 155
  candidate objects to native homes. 31 of them already sit at the native bottom-relative offset.
- **Weights alone cannot reach the native layout.** The frame size is fixed by packing, not
  weights, and stayed 0x184 under every weight change tried. A hill-climb on the compiler's own
  interference graph raises the match from 31 to 53 of 155 objects. It changes:

  | Object | Weight change |
  |---|---|
  | `phase_120_sin` | 3 → 8 |
  | `segment_index` $4538 and $4604 | 3 → 6 |
  | `strip1` | 10 → 12 |
  | `arc` | 11 → 9 |
  | `step_y`, `step_x`, `direction_result`, `draw_pos` and three temporaries | ±1 |
- **What must change is interference, not only weights.** Native absorbs two 4-byte groups into
  8-byte slots and needs four more 8-byte slots. The native slot at bottom 0x08 holds `$T4977`
  together with the `segment_index`/`fade`/`step` group. In the candidate, `$T4977` found a newer
  compatible 8-byte slot first. That requires the native 8-byte temporaries to conflict with the
  newer 8-byte slots, which points at different spill temporaries (allocation), as in (a).

## 8. Corrections to existing notes

- [frame.md](frame.md) §1.3, [frame.md](frame.md) matching implication 1, the
  [README.md](README.md) digest, and the comment on `count_stack_object_references`: memory
  effects add to alias-set members only in **inline-asm tuples** (kind 0x15, IL op 0x191).
  **Calls add nothing.**
- [core.md](core.md) §4 lists `c2_symbol` +0x28 only as a free-list link and +0x34 only as the CSE
  list. During stack layout they are the frame offset of class-3 objects and the reference weight.
  +0x2c/+0x30 are the order-list links and +0x38 the frame index. `c2_types.h` already names them.
- [regalloc.md](regalloc.md) §2 and `c2_types.h` `c2_live_range`: inside 0x306c1, +0x38
  (`def_tuple`) is the "definition seen" marker, and +0x14 (`next`) holds the last use and then the
  range end. flags5 bits in this role:

  | Bit | Meaning |
  |---|---|
  | 0x04 | excluded from forward substitution |
  | 0x02 | split at block entries |
  | 0x10 | regional split done |
  | 0x20 | requeued piece |
  | 0x40 | deferred once |

## Open questions

- Why the value-numbered address temporary of a field pointer is not forward-substituted. It is
  not a named range at 0x306c1. Extending the operand dump to unnamed ranges would show which
  phase-1 rule excludes it.
- Which source form keeps `&target_player` in EBX, native's choice, without the retarget-block spill.
- The `flags5` 0x08 writer, `flags6` 0x02, `c2_symbol` +0x18 and +0x3c..+0x4c, and
  `c2_fe_symbol` +0x30/+0x31 beyond the 0x26 temporary marker.
- Native `projectile_render` has no references at bottom 0x15c..0x167, and `alpha` (7 references)
  sits at bottom 0x168 among the weight-2 slots. Were references added or removed after layout,
  or is this a tracker error?
