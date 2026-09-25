# Small aggregate copies and memory alias classes (C2.DLL 8966)

This note explains how VC6 C2 lowers an 8-byte aggregate copy such as `a->target_position = *position`,
why the two dword moves come out interleaved (`ld; st; ld; st`) or grouped (`ld; ld; st; st`), and how
to predict the choice from source. Addresses are C2.DLL virtual addresses (image base 0x10700000).
"Verified" means observed in a preserving compiler trace or confirmed by a compile; "read" means
static reading of the disassembly or HLIL only.

Short version:

1. An 8-byte copy is always lowered to two dword `mov r,[src+k]; mov [dst+k],r` pairs, low half first.
   The pre-schedule order is therefore interleaved. Only the scheduler can group the loads.
2. The scheduler groups them only if the store `[dst]` and the load `[src+4]` get no memory
   dependence edge. For two memory operands that is decided by their **alias class ids**, never by
   base registers or displacements.
3. Two memory operands are independent only if both are **fields** of the same alias class: the same
   named pointer variable, addressed as `pointer->field` (pointer plus a constant), with
   non-overlapping (offset, size) ranges. An `array[i].field` access gets the pointer's whole class
   and depends on every other access to the same object.

So `creature->target_position = creature->position;` (one named `creature_t *` for both sides) gives
native's `ld; ld; st; st`. `creatures[i].target_position = *position;` does not, whatever the copy's
type or spelling.

## 1. Lowering of the copy (verified)

Trace: `scripts/c2/aggregate_trace.py` over the HOLD_TIMER arm of `creature_update_all`.

| Stage | IL for `creatures[i].target_position = *position` |
|---|---|
| C1 (globopt entry) | two 0x16b tuples of type 0x5008: `t <- [position]` and `[t663] <- t`, where `t663 = creatures + i*152 + 80` |
| `globopt_canonicalize_tuples` | both become 0x15b copies of type 0x5008 |
| phase-1 CSE sweep (`cse1`) | the pair folds into one memory-to-memory copy `[t663] <- [position]`; the 8-byte temp is dead and removed |
| `globopt_finalize_tuples` | the copy is 0x16b again |
| lowering (0x10729c3c case 5) | `lower_small_block_copy_as_scalar` 0x10751e0d rewrites it to a 0x15b of type 0x5008 and calls `lower_tuple`; the size is 8, so the __int64 path 0x1075ac4f splits it into halves |

After lowering the window holds, in this order: `mov edx,[edi]`, `mov [t+0x50],edx`,
`mov eax,[edi+4]`, `mov [t+0x54],eax`. Both halves keep type 0x5004 and the alias class of the
8-byte operand they came from. The source spelling of the copy does not change this. `vec2f_t`
assignment, a `creature_vec2_t` cast copy and a union member copy all reach lowering as the same
0x16b. Member-wise `x`/`y` float assignments should give two dword copies in the same
`ld; st; ld; st` order: under /Ot, lowerflt retypes memory-to-memory float copies to integer moves.
This is inferred, not traced. Variant p1 in §5 schedules exactly like the block copy.

## 2. Which operands depend on each other (read + verified)

`sched_memory_deps_on_stores` 0x1073a471 adds an edge from each earlier store for which
`operands_may_alias` 0x10702771 returns true. Edge kinds are 0x20 (store before load), 0x40 (load
before store) and 0x80 (store before store). For two kind-6 memory operands, `operands_may_alias`
returns `alias_classes_intersect(a+0x1c, b+0x1c)` (0x10702d60). Displacements and base registers are
never compared: `[esi+0x88]` and `[esi+0x50]` depend on each other if their classes intersect.

`alias_classes_intersect` 0x107026f4 (read):

- equal ids, or either id 1: intersect;
- ids at or above `g_alias_class_count` 0x1079d670 are **field classes**. Record
  `g_alias_secondary_records[id - count]` is `{parent class, bit, overlap mask}`;
- two field classes with the **same parent** (and 0x107adff0 set, observed 1): intersect iff
  `mask(a) & (1 << bit(b))`, which means the byte ranges overlap;
- anything else: the parents' symbol sets (`g_alias_class_symbol_sets` 0x1079d678) are ANDed. Every
  class that can point into `creature_pool` has the set {creature_pool}, so they all intersect.

### Where the class of a memory operand comes from

Classes are assigned in `compute_alias_classes` 0x10718eaf, before the global optimizer, on the IL
as C1 wrote it.

1. **Base class.** `compute_alias_points_to` 0x10719707 calls 0x1075d2d5 for each kind-6 operand
   when /Oa is off. 0x1071ae81 walks the base temp's definition tree back to named pointer
   variables (register candidates, flags5 & 8). If there is exactly one such root, the class is
   `alias_class_for_symbol_set(root, points-to set)` 0x1075d456, which is cached **per root
   pointer**. `creatures[i].f` and `creatures[i].g` share the class of `creatures`; `*position`
   gets the class of `position`. Both sets are {creature_pool}, yet the ids differ (180 and 207 in
   the base trace).
2. **Field class.** `alias_collect_field_classes` 0x1071afd0 then asks
   `memory_operand_field_range` 0x1075d788 for an (offset, size) range. It succeeds only when:
   - the base is a named register-candidate pointer: offset = displacement; or
   - the base is a temp defined as `add`/`sub` of such a pointer and a constant: offset = ±constant
     + displacement.

   Size is the operand type's size, so the 8-byte copy registers one field (0, 8). Each distinct
   (offset, size) under a parent class gets a new id, and overlapping fields of a parent get each
   other's bits. The walk stops adding fields once `0x400 - g_alias_class_count` fields exist.
   Bit indices saturate at 31 (read). `creature_update_all` uses 8 to 10 fields of a 616 budget,
   so the budget is not a factor here, unlike [spawn-exact](../../evidence/spawn-exact-2026-09-13/README.md).

`creatures[i].field` reaches alias analysis as `[(creatures + i*152) + off]`. The base temp's
definition is `add(temp, off)`, not `add(pointer, const)`, so it never gets a field and keeps the
whole class of `creatures`. Later passes (CSE, address-mode folding, forward substitution) rewrite
bases and indexes but keep each operand's +0x1c class.

The flags are fixed by the scratch configuration (`/O2 /GB /W3 /GR-`, no /Oa or /Ow). With /Oa,
0x1074e598 replaces 0x1075d2d5 and the field collector skips collection (`arg4`). /Ow only affects
calls. VC6 has no `restrict`. None of these were compiled here.

## 3. Scheduling the window (verified)

Windows here are small: 5 and 8 nodes, each ending at the arm's `jmp`. The 81-node cap plays no
part. On /G5, priority is `height<<13 + 65536*reads_memory + 65536*float_store`, with ties going
to the lower `seq` ([layout.md](layout.md), [x87-scheduling.md](x87-scheduling.md)).

Radius arm, fields of one pointer (all three classes are fields of a265, bits 0/1/2), from
`scripts/c2/sched_trace.py`:

| seq | tuple | h | priority | cycle | emitted |
|---|---|---|---|---|---|
| 1 | `fld [radius]` | 9 | 139264 | 0 | 0 |
| 2 | `fsub [frame_dt]` | 7 | 122880 (load bonus) | 1 | 1 |
| 3 | `fstp [radius]` | 2 | 81920 (float store bonus) | 5 | 6 |
| 4 | `mov ecx,[edi]` | 5 | 106496 | 2 | 2 |
| 5 | `mov [target_x],ecx` | 3 | 24576 | 3 | 4 |
| 6 | `mov edx,[edi+4]` | 4 | 98304 | 2 | 3 |
| 7 | `mov [target_y],edx` | 2 | 16384 | 3 | 5 |

The only memory edges left are `fld -> fstp` (0x40) and `st lo -> st hi` (0x80, same field). `fsub`
issues alone because x87 ops pair only with fxch. The two loads pair in cycle 2 and the two stores
in cycle 3. `fstp` waits for fsub's latency. This is native exactly: `fld; fsub; ld; ld; st; st; fstp`.

In the 99.78% source, the store classes are the whole class of `creatures` (180) and the loads are
field (0,8) of `position` (408, parent 207). The window gets `fstp -> ld` (0x20), `fstp -> st`
(0x80) and `st lo -> ld hi` (0x20). The heights become a chain (15, 13, 8, 7, 5, 4, 2), which
forces `fld; fsub; fstp; ld; st; ld; st`.

## 4. How to predict from source

For each pair of memory accesses in a window, reduce both to their alias-analysis form:

1. Find the **root**: the one named pointer variable the address is computed from. An array
   variable, an `&global`, several roots or an unknown value give other classes (not needed here).
2. Is it a **field**? Yes for `p->f`, `*p`, `p[const]` and `*(T *)&p->f`. No for `p[i].f` with a
   variable `i`, and no for any address with a non-constant term.
3. The pair is **independent** only if both have the same root and both are fields with disjoint
   byte ranges measured from that root. Everything else gets a dependence edge in program order.
4. For the order, apply the /G5 priorities: loads +8 levels, float stores +8 levels, ties in
   source order. Or run `scripts/c2/alias_trace.py`.

Consequences:

- Two different pointers to the same object never disambiguate, even with obviously disjoint
  fields. `creature->target = *position` stays interleaved.
- One pointer with overlapping ranges does not either: `p->v = p->v2` with overlapping vectors.
- The type of the copy (`vec2f_t`, a cast struct, member-wise floats) only changes the field sizes,
  not the rule.
- Whether the load then uses the `position` register (`[edi]`) or a recomputed address
  (`[esi*8+creature_pool+0x14]`) is a separate CSE question (§5, v1 and p1).

## 5. Acceptance tests (predictions written before compiling)

All runs are copies of `/tmp/claude/c2-tools-from-crimson-main/creature_update_all_99_78.cpp`
(99.7758%, 1338/1338, refs 437/0/0, prefix 494) with the canonical `scratch.conf`. Except for
"base", v1 and v3, they also replace `vec2f_t *position = &creatures[creature_index].position;`
with `creature_t *creature = &creatures[creature_index]; vec2f_t *position = &creature->position;`.

| variant | radius arm / link arm source | prediction | observed |
|---|---|---|---|
| base | `creatures[i].radius -= dt; creatures[i].target_position = *position;` | interleaved (classes 180 vs field of 207) | 99.7758%, as described, alias trace confirms |
| n1 | base arm, new declarations only | unchanged: interleaved, fstp first | 99.7758%, same two regions ✓ |
| n2 | `creature->radius -= dt; creature->target_position = *position;` | interleaved: two roots | 99.7758% ✓ |
| n3 | `creatures[i].radius -= dt; creatures[i].target_position = creature->position;` | interleaved: the store is a whole class | 99.7758% ✓ |
| n4 | `creatures[i].radius -= dt; creature->target_position = creature->position;` | link arm exact; radius arm `fld fsub fstp ld ld st st` | 99.9253%, exactly that; alias trace: radius a181 whole, copy fields of a267 ✓ |
| **v2** | `creature->radius -= dt; creature->target_position = creature->position;` | both arms native | **100%, body_byte_exact** ✓ |
| p2 | v2 with `*(creature_vec2_t *)&creature->target_x = *(creature_vec2_t *)&creature->pos_x;` | 100% | 100%, byte-exact ✓ |
| p1 | v2 with `creature->target_x = creature->pos_x; creature->target_y = creature->pos_y;` | 100% | order correct, but the Y load is `[esi*8+ADDR]` instead of `[edi+4]` (92.23%) ✗: only the whole-vector address `creature+0x14` is CSE'd with `position` |
| v1 | `creature` declared inside the arm; `position` unchanged | none written | order native, loads `[esi*8+ADDR]` (92.08%): the address is recomputed in the arm, not CSE'd with `position` |
| **v3** | `creature` declared just before the unchanged `position` declaration; v2 arm | loads like v1 (not CSE'd) | **100%, body_byte_exact** ✗ prediction: the dominating declaration is enough for CSE |

The v2 alias trace shows target (0x50,8), position (0x14,8) and radius (0x88,4) as bits 0, 1 and 2
of one parent class (a265). The loads are still `[edi]`: the global optimizer value-numbers
`creature + 0x14` to the owner that `position` already holds.

The spellings the other session tried are the base, n2 and n3 rows. A `creature_vec2_t` temporary
gives grouped loads through data dependence, not alias analysis, but it costs a frame slot.

## 6. Tool

```sh
uv run python scripts/c2/alias_trace.py <scratch-dir> --out <new-dir> --lines A-B
```

This is `sched_trace.py`'s preserving observer (the whole COFF must match) plus, for every kind-6
operand in each scheduling window:

- the alias class, with the field record `{parent, bit, overlap mask}`;
- the parent's symbol-id set;
- the function's `g_alias_class_count`, `g_alias_class_max` and the two field flags.

For each window it prints the memory dependence edges (0x20/0x40/0x80). C2 line labels are relative
to the function's opening line (here source line − 112).

## Open questions

- v1 against v3: why an arm-local `creature` loses the value-numbered `creature + 0x14` owner that a
  declaration dominating `position` keeps. The `fold.ret` stage of `aggregate_trace.py` shows v1
  materialising a new temp (#1307) where v3 keeps the owner (#2307). The kill that separates them
  was not traced.
- 0x1071acfd returns the class of a directly addressed object when the base is `&symbol + ...`
  (read only). Global-array accesses (`creature_pool[i].f`) presumably get creature_pool's own class.
  That path was not exercised.
- The meaning of 0x107adfe0, which gates the symbol-part checks in `operands_may_alias`, beyond
  "observed 1". The rule for 0x107adff0 being 0 was not observed.
- /Oa (0x1074e598 path, no field collection) was not compiled.
