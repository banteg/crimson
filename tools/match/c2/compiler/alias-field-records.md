# Alias field records: the 96-per-class cap and the 0x400 class budget (C2.DLL 8966)

This note explains which memory accesses get an alias **field record**, when a class runs out of
records, and the separate per-function budget of 0x400 alias **classes**. Both limits bite in very
large functions, and both change code without any visible source difference nearby. Addresses are
C2.DLL virtual addresses (image base 0x10700000, SHA-256 `d50100ac…5dda4a`). "Verified" means
observed in a preserving compiler trace or confirmed by a compile. "Read" means static reading of the
disassembly or HLIL only. [small-aggregate-copies.md](small-aggregate-copies.md) covers how the
scheduler uses classes and fields. Snail-mail's `tools/match/c2/scheduler.md` §2a covers how records
become scheduler edges.

Short version:

1. A memory access's **class** belongs to its root pointer symbol, such as `_this`, a pointer local
   or an inlined callee's parameter. Every `this->a.b[3].c` access in a member function has the class
   of `_this`.
2. A **field record** is keyed by `(class, start offset, size)`. The type is not part of the key.
   Each distinct range gets one record, the first time it appears in IL order (destinations before
   sources within a tuple).
3. A class gets **at most 96 records**. Later new ranges get none: those accesses keep the bare class
   and conflict with every access to the object.
4. A function gets **at most 0x400 classes**. After that, every new root/points-to pair is given
   **class 1** and conflicts with everything. In a function that sits at this limit, adding or
   removing a handful of classes anywhere earlier moves which late pointers collapse. That can flip
   global register allocation for the whole function.

## 1. Where a memory operand's class comes from (read, verified by trace)

`compute_alias_classes` 0x10718eaf → `compute_alias_points_to` → `alias_class_for_memory_base`
0x1075d2d5 for every kind-6 operand (/Oa off):

- `alias_find_base_pointer_roots` 0x1071ae81 walks the base temp's defining tuples down to named
  pointer symbols with `sym+5 & 8`. A parameter, a pointer local and an inlined callee's surviving
  parameter all qualify. It returns the number of roots, or -1 for an unknown source, such as a
  non-pointer local used as an index.
- **One root:** `alias_class_for_symbol_set` 0x1075d456 looks the class up in the root's cache list
  (`sym+0x30`→`+8`). Each node comes from `alias_cache_node_new` 0x1071ae54: `{next, class id,
  symbol set, key}`. A hit needs an equal points-to set and an equal key. A miss allocates
  `g_alias_class_count++`. **If the count is already ≥ 0x400, it returns class 1** (`cmp eax,0x400;
  jae` at 0x1075d4dd, result at 0x1078a7ee). The empty set returns 2.
- **-1 (unknown source) with a non-empty set:** a fresh class per operand, with no cache and no
  0x400 check (0x1075d350..0x1075d3c6). An access through a constant-propagated index variable
  (`int k = 24; path_pairs[k].x`) takes this path, because the index is still a variable at pass 2.
  Each such access adds one class (verified from class-count shifts, below).
- Symbol classes (`assign_symbol_alias_classes`) are numbered before pointer classes, and pointer
  classes follow in IL order. An added `int` local plus k variable-index accesses shift the late
  pointer classes by exactly 1 + k (verified, k = 2, 3, 4), so a new local that reaches C2 costs
  one class.

## 2. The field collector (read; walk cap and ordering verified by trace)

`alias_collect_field_classes` 0x1071afd0 (called at 0x10719013 with arg3 = the symbol-class count
saved at 0x10718f3c, and arg4 = `g_opt_assume_no_alias`).

**Candidates.** For each real tuple (flag 1) in IL order, it walks the destination list (+0x1c)
first, then the source list (+0x18). Each kind-6 operand is a candidate when /Oa is off, its class
is ≥ arg3 (a pointer class, not a direct symbol), and `op+0x10 & 0x80` is clear.
`memory_operand_field_range` 0x1075d788 gives `(start, size)`:

- **Base defined as `root ± constant`** (`0x16d`/`0x16e` whose first source is a kind-2 root with no
  defining tuple and `sym+5 & 8`, and whose second source is a constant):
  `start = ±constant + disp`.
- **Base is the root itself:** `start = disp`.
- **Anything else** (a variable index, a pointer loaded from memory, or a nested temp): no range.

`size` is `type & 0xfff`. The key compares only `start` and `size` (0x1071b1fe..0x1071b268), so a
float and an int at the same offset share a record, while a byte view and a dword view get two.

**Per-class list.** A new range is **prepended** to its class's list. The lookup walks the list from
the head, counting entries. At `cmp ecx,0x60; jge skip` (0x1071b20e), once 96 entries exist, a new
range is refused. No record is made, and nothing else changes. A range already in the list is always
found, because the list never grows past 96. So later accesses to recorded fields keep their records
after the cap (verified: 18 reuses in the census below, some after the cap).

**Global budget.** A tuple is walked only while `records_created < 0x400 - g_alias_class_count`
(0x1071b0e5, unsigned). When the class count exceeds 0x400, the subtraction wraps and the check is
inert. initialize_game_assets_and_world has 0x417 classes.

**Survival.** `bitset_set(bs, class)` runs only on the destination pass (0x1071b24b). A class with no
ranged destination access has its records thrown away (0x1071b30c → `j_8[n] = 0`). Its id is then
canonicalised to the first class with an equal symbol set and key. This was verified in
creature_update_all: `_alternate_pos` loads (class 0xd1, sources only) appear in the scheduler as
`a3`, with no field ids.

**Ids and bits.** Kept records get ids from `g_alias_class_count` upwards, in class order and then in
list order (head first). So in each class the **newest record gets the lowest id**, and its bit is
`min(position, 31)`. `g_alias_secondary_records` 0x1079d6bc holds `{class, bit, overlap mask}`. A
second walk (0x1071b5bd..0x1071b645) rewrites each ranged operand's `+0x1c` to its record id.
Accesses without a record keep the (canonicalised) class.

## 3. What counts against `this`'s class (verified on initialize_game_assets_and_world)

| Source form | Class / record |
|---|---|
| `m = …`, `a.b.c`, `arr[3].f`, `sub.path_pairs[0].primary.object` | `_this`; range `(K + disp, size)` |
| a non-inlined member call (`slots[i].SetObject(…)`, `viewports[1].SetCamera(…)`) | no memory access here, so no record |
| an inlined function or method whose reference or pointer parameter is bound to `*this` / `this` (`init_fog(*this)`) | the parameter is substituted, so the accesses count against `_this` (census unchanged) |
| an inlined parameter bound to `&this->member`, **used once** in the body (`set_strip(Object*& slot, v) { slot = v; }`) | substituted, so it still counts against `_this` |
| an inlined parameter bound to `&this->member`, **used two or more times** (`zero_position(tVector&)`, `link_root_bod(BodNode&)`, `set_base_strip(cRPath&)`) | the parameter survives as a root: its own class (one per call), and those accesses do **not** count against `_this`. Each such call adds about 3 classes (measured: 2 calls shift late classes by +6, and each expanded `zero_position` by −3) |
| a pointer local (`Path* path = &…; path->x`) | the local's class; does not count against `_this`, but its points-to set intersects `_this`, so the two classes conflict |
| a variable index, even when constant-propagated (`int k = 24; path_pairs[k].x`) | no range; a fresh class per access; no record; conflicts like a bare access |

A surviving parameter or pointer local can also become a register candidate. That changes the code:
`strips0` and `vk:1,4` below turn `[ebp+K]` into `[edi+…]`/`[ecx+…]`. So moving accesses out of
`_this` through a helper is code-neutral only when the allocator leaves the parameter in memory, as
it does for `zero_position`.

## 4. Scheduling consequence

The scheduler asks `operands_may_alias`. Two records of one class are independent unless their bits
overlap. A bare class conflicts with every record and bare access of its object. Class 1 conflicts
with everything. So once `_this` reaches 96 records, every later new member range acts as "may alias
anything in `this`": a load stays below every earlier `this` store in its window. The same classes
drive the global optimizer's kill sets, so a class-1 collapse also changes CSE and register
allocation well away from the collapsed accesses. Class 1 also blocks forward substitution of `lea`
pointers: a store through a class-1 root makes `has_intervening_base_definition` return 1 for any
base, so the pointer stays in a register ([unfolded-field-pointers.md](unfolded-field-pointers.md)).

## 5. Walkthrough: initialize_game_assets_and_world (Snail 0x40acf0)

Snail source at snail-mail 0b2ce0ed9 (the scratch is identical at 06a979fac). Physical scratch.cpp
lines. The base result is 99.56%, 5,411/5,411, prefix 3,567 and structural 13/13.

**Census** (`field_records.py --snail`; it reproduces snail's `schedtrace --fields` table exactly).
Class 0x2d3 is `_this`, with 301 ranged accesses: 96 new, 18 reuse and 187 capped. Records 1–94 come
before line 1718. Line 1718 (pair 53 primary → pair 2 primary transition) gets records 95 and 96.
Lines 1720, 1722 and 1724 (6 accesses) and all later strip blocks are capped.

**What native needs.** Native emits:

```
ld 53p.obj; ld 2p.obj; ld 53s.obj; st 2p.trans; st 2p.base; st 2s.trans; ld 2s.obj; mov ecx; st 2s.base
```

The loads from lines 1720 and 1722 rise above the stores from lines 1718 and 1720, so the accesses
on lines 1718–1722 must have records. The line-1724 load (`2s.obj`) stays below the line-1722 store.
It is not register-bound there, so it must have **no** record. With the cap, that means 4 or 5 fewer
`_this` ranges before line 1718, **not 6**. Verified, with the pair-2 window matching native exactly
in each case:

| Records before 1718 | Control | Pair-2 window |
|---|---|---|
| 94 | base | ours: `ld st ld st ld st …` |
| 90 | `set_base_strip` on pair 0 (b4); `vp` index on viewport 0 x/y/w/h (g3); `fringe_pair` index on pair 24 (g1) | native order |
| 89 | `vp` index on viewport 0 camera+x/y/w/h (g5) | native order |
| 88 | `link_entry_strips` on pair 0 (strips0); `vp` index on 6 viewport-0 fields (g6) | over-hoisted: `ld 2s.obj` rises above `st 2s.trans` |

The removed ranges must not come from pairs 0 or 1. Native hoists their loads too, and an unranged
pair 0 (`i-0-p-b`) breaks pair 0's own order.

**The class budget.** In the base, `g_alias_class_count` reaches 0x417. The late roots get:

| Root | Classes |
|---|---|
| `_animation_slot` | 0x3f8–0x3fa |
| `_golb_shot` | 0x3fb–0x3fc |
| `_texture_ref` | 0x3fd–0x3ff, then class 1 (19 lookups) |
| `_fringe_bod`, `_border`, one temp | class 1 |

The margin is 3 classes. Causal test: accesses to pair 26's strips (after the cap, so bare either
way) are spelled through `int late_pair = 26`. With 0, 1 or 2 such accesses (1 + k classes) the result
is 99.56% unchanged. With 3 or more, `_golb_shot`'s second class becomes class 1, and the function
drops to **80.67%, 5,418 instructions**. This is the "degraded state" that snail's notes attribute
to symbol count (`0x200` kept in a register at `link_root_bod`). Too few classes also degrades it:
at −12, `_fringe_bod` and `_border` get real classes, and the result is 80.64%, 5,418. Shifts from −2
to +3 were clean. Expanding a third `zero_position` (line 1959, −9 in total) costs 0.04% in every
variant tried, and its own stores and its class shift were not separated.

**Working controls on a copy** (each adds 1 local plus 4–5 variable-index accesses, about +5 to +6
classes; expanding the last one or two `zero_position` calls into three stores gives back 3 classes
each):

| Variant | Result |
|---|---|
| `int fringe_pair = 24;` for pair 24's four reads (lines 1389–1395), plus expanding line 1971's `zero_position` | **99.59%**, 5,411/5,411, prefix 4,444, structural **11/11**, 1,881 clean references |
| `int vp = 0;` for `viewports[vp]` camera, x, y, w, h (lines 117–121), plus expanding line 1971 | 99.59%, the same residual |
| `int vp = 0;` for x, y, w, h, plus expanding lines 1968 and 1971 | 99.59%, the same residual |
| any of these without the expansion | 80.6–80.7%, 5,418 (budget overflow) |

The remaining 11 are the weapon-1 channel residue that snail already documents. The pair-2 block is
exact. These controls prove the mechanism; they are not a claim about native's spelling.

Helper-based removals change the code: a surviving parameter gets a register, or local store order
changes.

| Variant | Result | What changes |
|---|---|---|
| `set_base_strip` ×2, with budget compensation | 80.9%, 5,402 | `loader` loses esi to `landscape` |
| `set_viewport_rect(viewports[0], …)` | 99.54% | viewport stores move locally |
| `set_viewport_keys` on viewports 1 and 4 | 98.2% | the param is CSE'd into ecx |

## 6. Tool

`scripts/c2/field_records.py` hooks `memory_operand_field_range` at 0x1071b1df and
`alias_class_for_symbol_set` at 0x1075d33d (both as return hooks) under the preserving observer. It
prints, per class, the new, reused, capped and no-range counts, and whether the class's records
survive. For one class it lists each record in IL order with the access line, base root and range.
It also prints the class count and the roots that were collapsed to class 1, or that sit within
0x10 of the budget.

```
uv run python scripts/c2/field_records.py tools/match/scratches/<name> --out <new-dir>
cd ../snail-mail && uv run python ../crimson/scripts/c2/field_records.py <scratch-dir> --out <new-dir> --snail . --line-offset <first line>
```

It was run on creature_update_all (Crimson, exact, 0x196 classes, nothing collapsed) and on the Snail
copies above.

## 7. Corrections to earlier notes

- [optimizer.md](optimizer.md) (compute_alias_classes): "the field-class budget (0x1071afd0, 0x400
  ids)" is incomplete. There are three limits:
  - a per-class walk of 0x60 records;
  - a per-function field total of `0x400 − class_count`, which is inert above 0x400 classes;
  - a class budget of 0x400, above which `alias_class_for_symbol_set` returns class 1.
- [small-aggregate-copies.md](small-aggregate-copies.md) §2: "The walk stops adding fields once
  `0x400 - g_alias_class_count` fields exist" also needs the 96-per-class cap, and the rule that
  records survive only for a class with a ranged destination access.
- Snail `scratches/initialize_game_assets_and_world/NOTES.md` (2026-09-25): "native creates at least
  six fewer distinct `this` field ranges … Six is the natural target" should read **four or five**.
  Six over-hoists the line-1724 load (verified). The allocator's "sensitivity to symbol count" is
  the 0x400 class budget: `_golb_shot`'s classes crossing 0x400. Dead `int` locals that C1 drops
  change nothing.
- Snail `tools/match/c2/scheduler.md` §2a: records are created in IL order at alias time (pass 2),
  not in scheduled order. Also, a class's records are discarded when it has no ranged destination
  access.

## 8. Open questions

- Why class 1 for `_golb_shot` (or real classes for `_fringe_bod`/`_border`) moves the `0x200`
  constant into a register has not been traced. The candidate path is CSE kill sets, then the
  loop-benefit deduction in `score_live_ranges` 0x10724b25.
- The cache key word (`alias_cache_node_new` arg4) and why one inlined reference parameter costs
  about 3 classes are not decoded.
- The lower edge of the class window is only sampled: −2 is clean, −9 costs 0.04% (confounded with
  the expanded stores), −12 degrades.
- Native's actual spelling of the 4–5 missing ranges, and a code-neutral way to get them without a
  budget compensation, remain open.
