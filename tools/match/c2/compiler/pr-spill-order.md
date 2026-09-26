# projectile_render: the ion-loop pointer spill and the 4-byte slot order (C2.DLL 8966)

This note answers two questions left open by [native-slot-partition.md](native-slot-partition.md):

1. Why native keeps the ion-loop `projectile` pointer as a spilled range (`lea edi,[ebx-0x14]; mov
   [esp+0x38],edi` at 0x42418c and three reloads) while our build folds it into `ebx`-relative operands.
2. Why native's conventional-trail staging temps (weight 8) share fading `along`'s 4-byte slot while ours
   join the shared `half_size`.

It also records two source changes found on the way that bring the frame to native's 0x19c.

Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000), `/O2 /GB`. Evidence
labels: **verified** means observed in a compile or in the preserving observer of
[`frame_predict.py`](../../../../scripts/c2/frame_predict.py) `--decisions`; **read** means static reading
in Binary Ninja; **inferred** means consistent with every compile below but not traced.

See also [frame-model.md](frame-model.md) §2 and §5 (weights, list order, pointer homes),
[regalloc.md](regalloc.md) §3.1 (colouring driver), [iv-cursor-merge.md](iv-cursor-merge.md) (IV merge #2),
[slot-sharing-symbols.md](slot-sharing-symbols.md) §4 (function-scope aggregates).

## 1. Short answer

1. **The pointer is live after the ion loop in native.** The fire-overlay loop reads
   `projectile->pos.tail.vy.type_id` through the ion loop's stale pointer: native 0x4253cf is
   `cmp dword ptr [edi+0x20], ebp`, with `edi` still holding `&projectile_pool[0x5f]` from the last ion
   iteration. The scratch had decompiled that read as `fire_type_owner = &projectile_pool[0x5f]`.
   [verified]
2. **Live-out of the loop blocks forward substitution.** The pointer is a single-definition `lea` range.
   `forward_substitute_single_def_ranges` 0x107306c1 folds such a range into its uses unless
   `has_intervening_base_definition` 0x10731a50 finds a definition of the `lea` base in a block where
   the range is live. The base is the loop IV (`ebx`, `add ebx,0x40` in the latch). Once the pointer
   is live after the loop it is live through the latch, the check returns 1, and the range survives.
   [verified: `substitution base check -> 0` in the base, `-> 1` with the change]
3. **The surviving range is unprofitable and becomes a class-3 home.** It spans the ion loop and the
   plague loop but is used only in the ion tails and the fire loop. Its pieces reach
   `handle_unprofitable_live_range` with benefit −2 and priority −409, and are demoted.
   The home has weight 4: one store at the loop head and three reloads. That is native's slot at
   bottom 0x28, shared with the three conventional-trail temps of weight 3. [verified]
4. **The 4-byte order needs `half_size` at weight 12, or at weight 8 or less.** The packer puts the
   weight-8 staging temps into the newest compatible 4-byte slot. They reach native's slot, fading
   `along` (weight 11), only if `half_size`'s slot is not newer at that point. The replay window is
   weight ≤ 8 or ≥ 12; weights 9–11 give our grouping. [verified by replay and compile]
5. **Native's `half_size` has weight 12.** Native's `half_size` slot (bottom 0x94) also carries the
   pulse arm's `scale * 16.0f` store and load (0x42423f `fstp [esp+0xa4]`, 0x424250 `mov eax,[esp+0xa4]`).
   So the pulse arm writes the size into `half_size` (10 + 2 = 12). [verified]
   - Negative control: a per-block `half_size` (weight 5 each) also moves the staging temps to fading
     `along`. But the 0.4-block copy then joins `fade`'s slot, not 0x94, so it is not native's source.
6. **Frame 0x19c.**
   - With `direction` declared at function scope, `direction` is an address-taken aggregate that
     interferes with everything before its use ([slot-sharing-symbols.md](slot-sharing-symbols.md) §4).
     So nothing joins its slot, as in native bottom 0x44. The 8-byte `$T` cascade then shifts to
     native's grouping, and one more 8-byte slot opens. [verified]
   - Reusing function-scope `point0..point3` for the ion arc strips fixes `point3`'s slot and the
     conventional `$T` cascade. [verified]

## 2. Mechanism: why the base build has no pointer

The source is `projectile_t *projectile = &projectile_pool[projectile_index];` at the top of the ion
loop. The tail code of both ion blocks reads through it.

1. **Global optimizer.** IV merge #2 keeps the `+0x14` field IV (`ebx`, init `&pool+20`) and rebuilds
   the loser `&pool[i]` (two uses) at the loop head as `t = lea [ebx-0x14]`. The `active` test reads
   `[t]`, and `projectile = t` is a copy. After the optimizer the pointer still has five uses: the 0.4
   tail (`angle`, `pos_y`, `pos_x`) and the fading tail (`pos_y`, `&pos_x`). All pre-loop field reads are
   already `ebx`-relative. [verified: `iv_merge_chain.py` and `store_trace.py --symbol _projectile`]
2. **`coalesce_copy_live_ranges` 0x10730308.** The copy's destination has one definition, and the
   source is not redefined inside the destination's range. `projectile` is therefore merged into `t`
   and the copy is deleted. The pointer symbol is gone between the dumps at 0x10730308 and 0x107306c1.
   [verified by store_trace; conditions read]
3. **`forward_substitute_single_def_ranges` 0x107306c1.** For `t` (def `lea [ebx-0x14]`, address uses only):
   - phase 1 does not exclude it: no use before the definition, no value use, one definition, a
     foldable address (`sub_10731bbf` accepts any use when the definition's address is the base+disp
     form 0x14c);
   - phase 2 calls `has_intervening_base_definition(ebx, def, end, lr)`. The end is the last use, or the
     end of the last block when the range is live-out there. The check walks backward from the end
     to the definition, and only tuples in stretches where the range is live are tested. The live flag
     is reloaded from the block bitset at +0x44 at every block marker, and the range's own definition
     clears it. A destination operand with the same parent symbol as the base, or an alias class that
     contains it, returns 1 [read].

   In the base the range dies in the fading tail. The latch's `add ebx,0x40` is never walked with the
   range live, the check returns 0, and every use becomes `[ebx-0x14+k]`. [verified: decisions
   `substitution base check -> 0`, `forward-substituted` at IL line 516]

What native needs is one of the exclusions. Two of them were checked:

- **A value use.** Storing the pointer to a global (diagnostic D1) sets lr+5 bit 4 in phase 1.
  - The pointer then survives in `esi`, and the head gets native's `mov al,[ebx-20]; lea esi,[ebx-20]`.
  - No spill follows, because the range ends in the fading tail: benefit 32, priority 50.
  - So exclusion alone gives the head shape but not native's home.
- **Liveness past the latch.** This is what native has (§3).

## 3. The source that reproduces the spill

```cpp
    projectile_t *projectile;                 // before the ion loop
    for (projectile_index = 0; projectile_index < 0x60; ++projectile_index) {
        projectile = &projectile_pool[projectile_index];
        ...
            if (projectile->pos.tail.vy.type_id != PROJECTILE_TYPE_FIRE_BULLETS) {   // fading tail
        ...
    }
    ...                                        // plague loop declares its own `projectile`
    for (projectile_index = 0; projectile_index < 0x60; ++projectile_index) {   // fire overlay
        if (projectile_pool[projectile_index].active
            && projectile->pos.tail.vy.type_id == PROJECTILE_TYPE_FIRE_BULLETS
            && ...
```

The stale pointer equals `&projectile_pool[0x5f]` after the ion loop, so the behaviour is unchanged.
Emitted code, which matches native instruction for instruction:
- head: `mov al,[ebx-20]; lea edi,[ebx-20]; test al,al; mov [esp+x],edi; je latch`;
- 0.4 tail: `mov edi,[esp+x]; mov edx,[edi+4]; ... fadd [edi+12] ... fadd [edi+8]`;
- fading tail: `mov esi,[esp+x]; fadd [esi+12]; lea ebp,[esi+8]; ... cmp [esi+32],45`;
- join before the latch: `mov edi,[esp+x]`;
- fire loop: `cmp [edi+32], ebp`.

The fading-tail type test must read through `projectile` too; native has `cmp [esi+0x20],0x2d`. Without
that, the reload in the fading tail goes to `eax`.

## 4. The 4-byte list order

The list order is size ascending, then weight descending. Ties go to the object that reached the count
first in walk order ([frame-model.md](frame-model.md) §2). In the base the 4-byte head of the list is:

`scale` 32, `fade` 16, `distance` 12, `along` (0.4) 11, `along` (fading) 11, `half_size` 10, the two
conventional staging temps 8 and 8, the ion temp 8, `projectile_index` 8, …

Each object joins the newest slot with no conflict ([frame.md](frame.md) §1.3). The staging temps
belong to an earlier loop, so they conflict with no ion object. They therefore land in whichever of
fading `along`'s and `half_size`'s slots is newer.
[`frame_whatif.py`](../../../../scripts/c2/frame_whatif.py) replays that choice for each `half_size`
weight, with references added or removed at the end of its walk:

| `half_size` weight | staging temps join | native? |
|---|---|---|
| ≤ 8 | fading `along` (the temps reach 8 earlier in walk order) | yes |
| 9, 10, 11 | `half_size` | no |
| 12, 13 | fading `along` (`half_size` is placed before both `along`s) | yes |

Native's own references decide between the two windows. The native slot at bottom 0x94 has ten
`half_size` references (five per ion block, the same as ours) and the pulse arm's `scale*16` pair. In
our base that pair is a separate weight-2 temp mapped to 0x94. One variable with twelve references is
the only reading that fits both the slot and the order. The split reading (≤ 8) is refuted by
test 2.4 below.

## 5. Frame size: `direction` at function scope, and `point0..3` shared with the arc strips

After §3 and §4 the frame was still 0x194.

- **`direction`.** Native bottom 0x44 holds `direction` alone (23 references).
  - In our build, the first conventional `$T` that finds no other slot joins `direction`'s slot. Every
    later 8-byte `$T` then lands one slot off native, and the last one never needs a new slot.
  - With `projectile_render_vec2_t direction;` at function scope, `direction` is an address-taken
    aggregate that interferes with every object placed before its last use
    ([slot-sharing-symbols.md](slot-sharing-symbols.md) §4). Nothing joins it.
  - The cascade shifts back, and `$T4975` opens the 47th 8-byte slot (native 0x11c with `$T4931`).
  - Frame 0x19c. [verified]
- **`point0..point3`.** Native 0x2c and 0x5c each hold one conventional point and one ion strip
  (`point2`/`strip2`, `point3`/`strip3`). 0x34 and 0x4c hold `strip0` and `strip1` together with
  conventional-loop 8-byte stores (0x423252, 0x423272).
  - In our build `point3` joined `end_result`/`half_width`, and six `$T`s followed one slot off.
  - Declaring `point0..point3` at function scope and using them for the arc strips makes each pair one
    object. The conventional `$T` cascade then matches native. [verified]
- **`span`/`along` initialisation.** Native assigns `span = distance; along = 0` in an else branch
  (0x42461e..0x42462a, which had no candidate object before). Rewriting both blocks as if/else
  explains those six references. [verified]

Remaining differences, not attempted here:
- The plasma `step_x`/`step_y` (weight 2) land in `first`/`ion_scale` slots instead of the two `along`
  slots.
- The arc-loop product temp (native 0x54, five references with no candidate object).
- The equal-density order of four weight-16 slots, and of the two secondary draw-position slots.

## 6. Acceptance tests

Every variant is a copy of 84ccd4ab3's scratch. The predictions were written before the compile.
Refs are ok/unresolved/mismatch.

| # | Change | Prediction | Observed | Match, refs, frame |
|---|---|---|---|---|
| 1.1 | fading type test via `projectile` only | still substituted; code identical | identical | 74.17%, 537/0/0, 0x194 |
| 1.2 | `active` read by index, pointer assigned after the test | coalesced into the IV-merge temp, substituted; identical | identical | 74.17% |
| 1.3 | `(float *)projectile + 2` for `&pos_x` | still an address use; identical | identical | 74.17% |
| 1.4 | diagnostic: `g_probe = projectile;` in the fading tail | phase-1 exclusion (value use), pointer range kept | kept in `esi`, head `lea esi,[ebx-20]`, no spill (priority 50) | 74.17%, 536/0/0 |
| 1.5 | hand cursor `++projectile` in the for increment | loop-carried pointer | separate type-id IV `esi` (step operand differs from the index IVs), spilled; not native | 72.37%, 530/0/0 |
| 1.6 | `projectile = &projectile_pool[++projectile_index]` in the increment | loop-carried pointer | IVs `ebx=pool+32`, `esi=pool`; not native | 70.76%, 529/0/2 |
| 1.7 | **stale pointer read in the fire loop (F)** | live-out, base check → 1, split and demoted; class-3 home w4 at native 0x28; fire loop `cmp [edi+0x20],ebp` | all as predicted; `base check -> 1`, `demoted-unprofitable` (benefit −2, priority −409) | 74.71%, 526/0/2 |
| 1.8 | F + fading type test via pointer (V) | fading reload into `esi` | `mov esi,[spill]; ...; cmp [esi+32],45` | 75.04%, 531/0/2 |
| 2.1 | replay: `half_size` weight 12 on the base | staging temps join fading `along` | yes | (replay) |
| 2.2 | F V + pulse arm writes `half_size` (P) | weight 12; staging temps with fading `along`; pulse temp gone | yes | 74.58%, **535/0/0**, 0x194 |
| 2.3 | + `direction` at function scope (D) | `direction` alone in its slot; `$T` cascade shifts; frame 0x19c | yes | 75.51%, 524/0/3, **0x19c** |
| 2.4 | negative: per-block `half_size` (w5 each) | staging temps with fading `along`, but the 0.4 `half_size` joins `fade` | yes (and `phase` joins the fading `half_size`) | 73.08%, 539/0/0 |
| 2.5 | F V P D + shared `segment_index` (S) | `segment_index` joins `fade` (0x8) | yes; every native 4-byte group reproduced as a group | 81.00%, 531/0/1 |
| 2.6 | + `point0..3` reused by the strips (Q) | `point3` in the strip3 slot; conventional `$T` cascade native | yes | 81.91%, 537/0/2 |
| 2.7 | + if/else `span`/`along` (E) | native branch shape; 6 native refs explained | yes | 81.95%, 537/0/2 |

Leave-one-out from F V D S Q E, without P (81.79%, **541/0/0**, 0x19c):

| Dropped | Result |
|---|---|
| F and V | 75.71%, 532/0/0 |
| V | 81.62%, 541/0/0 |
| D | 75.71%, 522/0/2, 0x194 |
| S | 76.94%, 531/0/0 |
| Q | 80.14%, 531/0/1 |
| E | 81.75%, 541/0/0 |

**Objects at their native bottom offset** (`native_slots.py`):
- base: 42/174;
- F V D S Q E: 83/169;
- with P: 85/168.

Unexplained native references: 34 in the base, 24 in both.

The mismatches in the P variants are alignment pairings, not different code. They pair target
`fld [camera_offset_x]` with our `fld [camera_offset+4]` at 0x4245c5 and 0x4248f3, where both bodies
compute `base.x` and then `base.y` identically. The cause is that `half_size`'s slot and `base`'s slot
(both weight 16) come out of the density sort in the opposite order to native.

## 7. Predicting it from source

- A single-definition pointer or field pointer computed from a loop IV (`p = &pool[i]`) is folded into
  the uses in either of these cases:
  - it is not used after the loop;
  - it is copied only into ranges that coalesce with it.

  It survives as a register range if it is used after the loop, which blocks the base check. It also
  survives if it is used as a value: a store, a push, or a compare of the pointer itself.
- A surviving range that spans more loops than it is used in has low benefit. It is split and demoted,
  and gets a class-3 home. The home's weight is one store per definition plus one reload per region
  that uses it.
- For 4-byte slot sharing across loops, compute each candidate's weight and walk order, then apply
  newest-compatible-slot. `frame_whatif.py --weight` gives the window of weights that produces a given
  grouping. Check the result against every native reference of the slot (§4) before changing the source.
- A function-scope, address-taken aggregate interferes with everything before its last use. Use it when
  native shows an 8-byte slot with a single member.

## 8. Tool

```sh
uv run python scripts/c2/frame_whatif.py <scratch> --out <new-dir> [--source v.cpp] --weight '_half_size$4649=12' --size 4
uv run python scripts/c2/frame_whatif.py --reuse <dir> --conflict '_point3$4429,_half_width$4399'
uv run python scripts/c2/frame_whatif.py --reuse <dir> --add 'SPILL:4:_along$4702:anon@-392@673' --add-native 0x28
```

It compiles through `native_slots.py`'s mapping once. It then replays `order_stack_object` and
`pack_stack_slots` with edited weights, extra conflicts or an extra spill home, and prints the frame
size, the count of objects at their native offset, and every slot with each member's native base. On
the base it reproduces native_slots' 42/174.

## 9. Open questions

- The exact live-flag source in `has_intervening_base_definition`: `[marker+0x14]+4` → `+0x44`. It is
  read as the live-out set of the block walked next. Only its effect is verified.
- Why `ion_scale` (function-body level, constant stores only, never killed) does not interfere with
  the plasma loop before it, while a `direction` declared at the top of the function interferes with
  everything before its use. This is presumably the declaration point, a scope start that the front
  end emits. Not traced.
- Native's weights for the equal-density runs (`direction` 23 and the `along` + `step_x` slot sort
  differently in native) and the plasma `step_x`/`step_y` placement.
