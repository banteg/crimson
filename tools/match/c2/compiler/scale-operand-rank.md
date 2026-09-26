# Where a vector-scale operand ranks: part-record creation order (C2.DLL 8966)

This note covers `Vec3 r = v * s` for an inlined `tVector::operator*(float)` whose `v` is a member of a
scalarized local aggregate, such as `transform.basis_right * local_x`. Each lane is a commutative `fmul`
of a field leaf and the scale leaf. The lane loads whichever sorts first, so a lane gives
`fld st(0); fmul [field]` when the scale sorts first and `fld [field]; fmul st(1)` when the field does
([x87-scheduling.md](x87-scheduling.md) §5). For two symbol leaves the key is the slot id, so the lane
order is the order in which the two symbol records were **created**. This note explains who creates the
field records and when.

"Verified" means preserving traces of real compiles (`scripts/c2/part_origin_trace.py`,
`il_stage_trace.py`, `sched_trace.py`) and the snail matcher. "Inferred" means it fits every trace but
the code path was not read.

Short version:

1. A field of a scalarized aggregate is a pool-B part record `^parent+off z4`. It gets its id at the
   first of three events [verified]:
   - **The reader.** The first explicit member read in source order, such as `m.basis_right.y`. A
     read at a nonzero offset creates two records in lockstep: first the address part `^m+4 z60`
     (the rest of the aggregate from that offset), then the field `^m+4 z4`.
   - **The inliner.** An offset-0 member of an inlined `this`, such as `this->x` in `operator*=` or
     `operator*`, is looked up or created while the call is expanded.
   - **Globopt.** A nonzero member of an inlined `this`, such as `this->y`, stays an address
     expression until canonicalization creates `^m+4 z60`. Value numbering then creates the field
     at `cse1`.
2. A named local gets its id at its first IL reference (the reader). An inline formal copy (the
   `scale` of `v * (a - b)`) is allocated when its call expands. It comes from pool B's LIFO free list,
   so it usually reuses an id freed by an earlier expansion and ranks **below** records created since
   then [verified]. A named local passed as the actual gets no copy: the formal is replaced by the
   local itself.
3. Therefore the Y lane of `v * s` loads the field only if `v.y`'s record was created after `s`'s. If
   every earlier explicit read of `v.x`, `v.y` and `v.z` comes before the definition of `s`, the scale
   sorts first in every lane.
4. The lockstep address parts fill the id gaps between explicit fields: fields x/y/z are 0x14d/0x14f/0x151
   and the parts are 0x14e/0x150. No authored local can take those ids.

## 1. Records and who creates them

Pool B (classes 4/5: locals, parameters, inline copies and aggregate parts) hands out ids in 32-id
chunks shared with the other pools. It has a LIFO free list ([address-order.md in snail-mail]; crimson
`symbol_alloc` 0x107017eb). Part records come from `symbol_get_part` 0x10703ba0, which looks up the part
for (type, size, offset) or allocates it (call to `symbol_alloc` at 0x10703c34) [read: call site only].

Observed creation points in traverse_path_follow_golb. The origin column is the first IL dump that
contains the record: the reader dump at `function_prepare_temps` 0x107180fd, an inliner dump, or a
globopt stage:

| Record | Created by | Evidence |
| --- | --- | --- |
| `transform.basis_right.x/.y/.z` read explicitly in the kind-42 branch | reader: 0x14d, then 0x14e `^+4 z60`, 0x14f, 0x150 `^+8 z56`, 0x151 | base build |
| `local_x` (named) | reader, 0x1eb | base build |
| `this->x` of `transform.basis_right *= s` when nothing reads `.x` explicitly | inline expansion #23: 0x245 | variant e4 |
| `^transform+4 z60`, `^+8 z56` for `this->y`, `this->z` | `canon.ret`: 0x2a4, 0x2a5 | variant e4 |
| `^transform+4 z4`, `^+8 z4` (the y/z fields) | `cse1`: 0x2a6, 0x2a7 | variant e4 |
| the `scale` copy of `basis_right * (a - b)` | inline expansion #26: **0x1fd**, a reused id below 0x245 | variant e4 |

The `&transform` that C1 passes to out-of-line calls is also a `^transform+0 z4` record (0x142 in the
base build). It is never reused as the float field: an explicit `.x` read creates a new one (0x14d).
The lookup key includes the type [inferred from `symbol_get_part`'s comment].

## 2. The lane rule

For `r = v * s`, inlined, with `v` a scalarized aggregate member and `s` a float leaf on the x87 stack:

- Lane L emits `fld [v.L]; fmul st(1)` iff `id(v.L) > id(s)`. Both are pool-B leaves below 0x800
  (key `id << 5`) [verified].
- The last lane, where `s` dies, is `fmul [v.z]` either way ([x87-scheduling.md](x87-scheduling.md) §5.2).
- If the lane's scale operand is an **expression** rather than a leaf, the scale sorts first whatever
  the ids are. An example is the assignment `(local_x = a - b)` written inside the X product
  [verified].

A class-3 temporary as the scale would compare as `(id << 6) & 0xffff` (id mod 1024). No tested spelling
made the scale a temporary. A spelled-out component-wise recompute of `a - b` made it a CSE temporary,
but with the wrong rank.

## 3. traverse_path_follow_golb (snail-mail)

Native, target index 327 onward: X `fld st(0); fmul [esp+0x44]`, Y `fld [esp+0x48]; fmul st(1)`,
Z `fmul [esp+0x4c]`. At 99.53% the candidate had `fld st(0); fmul [esp+0x48]` in Y.

Base keys (`sched_trace.py`, C2 line 166): scale `local_x` 0x1eb (0x13d60) against fields
0x14d/0x14f/0x151 (0x129a0/0x129e0/0x12a20). All fields are older than `local_x`, so every lane loads
the scale. Native needs x < scale < y. The only ids in that gap are 0x14e, the reader's `^+4 z60`
lockstep part, or a temporary with id mod 1024 = 0xa7.

What moves the ids (all measured on copies with the snail matcher):

| Change | Y lane | X lane | Why |
| --- | --- | --- | --- |
| anything in the ordinary branch only: pointer or reference `right`, component products, a parenthesized or cast scale, block copies | scale first | ok | the kind-42 branch has already created x,y,z at 0x14d–0x151 |
| kind-42 **and** ordinary scaling as `transform.basis_right *= lateral_scale` | **field first** | **flips** | there are no explicit reads before `local_x`; the publish reads x,y,z after it (0x1ea/0x1ec/0x1ee > 0x1e6) |
| the same, plus the scale as the expression `(input_position->x - center_x)` | scale first with the explicit publish; field first with a block publish | ok with the explicit publish; flips with a block publish | the copy is created at inline time (0x241), above the publish's reader fields. With a block publish it reuses 0x1fd, below the inline `this->x` (0x245) |
| a 54-variant grid: kind-42 × ordinary ∈ {explicit, `*=`, `= v * s`}, publish ∈ {explicit, `*p = v`, member assign}, scale ∈ {named, inline} | only the `*=`/`*=` rows change Y | always flips with them | as above |
| both `*=`, plus a codeless `transform.basis_right.x;` before `local_x` | field first | ok | creates x before `local_x`: 0x1e5 < 0x1e7 < 0x1ec. **100.00%**, not authored |
| both `*=`, plus a component product with the assignment in X (below) | field first | ok | X's scale is an expression; y is read after `local_x` (0x1ec > 0x1e8) |

The retained shape:

```cpp
transform.basis_right *= lateral_scale;          // both branches
...
float local_x;
Vec3 right_offset;
right_offset.x = transform.basis_right.x * (local_x = input_position->x - center_x);
right_offset.y = transform.basis_right.y * local_x;
right_offset.z = transform.basis_right.z * local_x;
```

The operands can be in either order (`(local_x = …) * transform.basis_right.x` compiles the same).
This gives the native product exactly. It also adds read-time records, because the parts of
`right_offset` and `transform` are now read in the ordinary branch. That moves two later ids that
native also constrains:

- **The terminal `*anchor + terminal[-1].transform.position` fadd (target 105).** It needs its
  inline reference copy at id ≡ 0 mod 8, so that it ties with `anchor` (0x10) and source order wins.
  With the new product alone the copy lands at 0x226, which flips the fadd (99.53%). Removing six
  read-time pool-B records puts it at 0x240 and gives **100.00%**. Measured knobs:
  `shot->flight_transform.basis_forward = transform.basis_forward;` or the same for `basis_up`
  (−5 each), and dropping the `Vec3* motion` or `Vec3* output` alias (−1 each). Exactly one of the two publishes plus exactly one
  alias works; the `basis_right` publish form does not matter (8 of the 32 combinations per operand order).
- **C0, the first CSE slot.** The −6 route empties the reader's last pool-B chunk, so C0 drops from
  0x300 to 0x2e0. The alpha `fdiv [eax+edx+0x8c]` at +0x46c then swaps its SIB base and index. That
  is a byte-level difference only; the normalized listing is equal. Adding two records instead keeps
  C0 at 0x300, and the copy lands at 0x228. With two dead-stored ints as a proof, the result is
  100.00% with only the three SIB swaps base already has (+0x254/+0x28a/+0x2c0). No authored +2 was
  found.

## 4. update_track_attachment_follow_state (snail-mail)

It has the same shape. The kind-42 branch reads `basis_right.x/.y/.z` explicitly (0x117/0x119/0x11b)
before `local_x` (0x1bb). The Y product at target 510 is scale-first.

- With both scalings as `*=` and the same component product, region 496–511 matches and the terminal
  fadd (203) does not flip [verified].
- In this function the kind-42 `*=` changes the kind-42 schedule: the integer stores of `output->x/y`
  move. The kind-42 region was already mismatched at 362, and it grows from 30 to 52 diff lines, so
  the total drops from 97.93% to 96.42%. That region needs its own fix before this one pays off.
- With the ordinary branch alone as `*=`, Y stays wrong, as the rule predicts: the kind-42 branch
  still reads y first.

## 5. Tool

```sh
uv run python scripts/c2/part_origin_trace.py <scratch> --out <new-dir> --lines 160-170
uv run python ../crimson/scripts/c2/part_origin_trace.py --snail <scratch> --out <new-dir> --lines 160-170
```

For every float add/sub/mul/div on the given C2 lines at lowering entry, it prints each symbol operand
with its class, `^parent+offset`, name, leaf key, and the dump that first contains it:

- `reader`;
- `inline #k` (k-th inliner expansion);
- a globopt stage (`canon.ret`, `cse1`, …).

It uses the preserving observer: whole COFF, replay and missing-stream checks unchanged.

## 6. Corrections to other notes

- snail-mail `x87-order.md` / traverse NOTES: the scale operand 0x1eb is the named `local_x`, not an
  `operator*` inline copy. The formal is replaced by the local. 0x14e is the reader's `^transform+4 z60`
  part, created in lockstep with the y field; it is not a free slot.
- [x87-scheduling.md](x87-scheduling.md) §5 "Slot ids": inline copies do not always take later
  blocks. A formal copy takes pool B's most recently freed id. That can be a slot in the reader's last
  chunk, such as 0x1fd, below parts that earlier expansions created.

## Open questions

- Which inliner step frees the formal records, and in which order the formals are allocated within one
  expansion. The traces only show that the copy reuses an id freed before its expansion.
- An authored way to add exactly two read-time pool-B records in traverse_path_follow_golb, which
  would keep C0 at 0x300.
- The kind-42 store schedule of update_track_attachment_follow_state under `*=`.
