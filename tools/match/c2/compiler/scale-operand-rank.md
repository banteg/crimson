# Where a vector-scale operand ranks: part-record creation order (C2.DLL 8966)

This note covers `Vec3 r = v * s` for an inlined `tVector::operator*(float)` whose `v` is a member of a
scalarized local aggregate, such as `m.basis_right * s`. Each lane is a commutative `fmul`
of a field leaf and the scale leaf. The lane loads whichever sorts first, so a lane gives
`fld st(0); fmul [field]` when the scale sorts first and `fld [field]; fmul st(1)` when the field does
([x87-scheduling.md](x87-scheduling.md) §5). For two symbol leaves the key is the slot id, so the lane
order is the order in which the two symbol records were **created**. This note explains who creates the
field records and when.

"Verified" means preserving traces of real compiles (`scripts/c2/part_origin_trace.py`,
`il_stage_trace.py`, `sched_trace.py`) and a matcher. "Inferred" means it fits every trace but
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
4. The lockstep address parts fill the id gaps between explicit fields: explicit reads of x, y and z
   in order take ids k, k+2 and k+4, and the parts take k+1 and k+3. No authored local can take those
   ids.

## 1. Records and who creates them

Pool B (classes 4/5: locals, parameters, inline copies and aggregate parts) hands out ids in 32-id
chunks shared with the other pools. It has a LIFO free list (`symbol_alloc` 0x107017eb). Part records
come from `symbol_get_part` 0x10703ba0, which looks up the part for (type, size, offset) or allocates it
(call to `symbol_alloc` at 0x10703c34) [read: call site only].

The creation points, by the first IL dump that contains the record: the reader dump at
`function_prepare_temps` 0x107180fd, an inliner dump, or a globopt stage [verified on Snail Mail's
traverse_path_follow_golb]:

| Record | Created by |
| --- | --- |
| a field read explicitly, such as `m.basis_right.y` | reader, together with its lockstep address part (`^m+4 z60` before `^m+4 z4`) |
| a named local | reader, at its first IL reference |
| `this->x` (offset 0) of an inlined member such as `operator*=` when nothing reads `.x` explicitly | the inline expansion |
| `^m+4 z60`, `^m+8 z56` for an inlined `this->y`, `this->z` | `canon.ret` |
| the `^m+4 z4`, `^m+8 z4` fields themselves | `cse1` |
| the formal copy of an inlined call whose actual is an expression | the inline expansion, usually a reused id from pool B's free list |

The `&m` that C1 passes to out-of-line calls is also a `^m+0 z4` record. It is never reused as the float
field: an explicit `.x` read creates a new one. The lookup key includes the type [inferred from
`symbol_get_part`'s comment].

## 2. The lane rule

For `r = v * s`, inlined, with `v` a scalarized aggregate member and `s` a float leaf on the x87 stack:

- Lane L emits `fld [v.L]; fmul st(1)` iff `id(v.L) > id(s)`. Both are pool-B leaves below 0x800
  (key `id << 5`) [verified].
- The last lane, where `s` dies, is `fmul [v.z]` either way ([x87-scheduling.md](x87-scheduling.md) §5.2).
- If the lane's scale operand is an **expression** rather than a leaf, the scale sorts first whatever
  the ids are. An example is the assignment `(s = a - b)` written inside the X product
  [verified].

A class-3 temporary as the scale would compare as `(id << 6) & 0xffff` (id mod 1024). No tested spelling
made the scale a temporary. A spelled-out component-wise recompute of `a - b` made it a CSE temporary,
but with the wrong rank.

## 3. Tool

```sh
uv run python scripts/c2/part_origin_trace.py <scratch> --out <new-dir> --lines A-B
```

For every float add/sub/mul/div on the given C2 lines at lowering entry, it prints each symbol operand
with its class, `^parent+offset`, name, leaf key, and the dump that first contains it:

- `reader`;
- `inline #k` (k-th inliner expansion);
- a globopt stage (`canon.ret`, `cse1`, …).

It uses the preserving observer: whole COFF, replay and missing-stream checks unchanged.

## 4. Corrections to other notes

- [x87-scheduling.md](x87-scheduling.md) §5 "Slot ids": inline copies do not always take later
  blocks. A formal copy takes pool B's most recently freed id. That can be a slot in the reader's last
  chunk, below parts that earlier expansions created.

## Open questions

- Which inliner step frees the formal records, and in which order the formals are allocated within one
  expansion. The traces only show that the copy reuses an id freed before its expansion.
