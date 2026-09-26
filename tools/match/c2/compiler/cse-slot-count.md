# CSE slot count: what creates a CSE temporary id (C2.DLL 8966)

The hash of a CSE temporary is its id: `(id << 6) & 0xffff` as a symbol leaf, and `((id & 3) << 14) + 7`
inside a load leaf `[T]` ([sib-operand-order.md](sib-operand-order.md)). The id is `C0 + n`, where n is the
temporary's position in the order value numbering creates slots. This note says what creates a slot, and in
what order. It then uses that to fix Hill/Valley's nine SIB swaps.

"Verified" means seen in preserving traces (`scripts/c2/cse_slot_trace.py`), read in Binary Ninja, or checked
by a compile and the snail matcher. "Intervention" means a `--phantom` run: the same compile with extra
pool-E ids burned at a chosen slot, then matched. "Inferred" means it fits the data but the code was not read.

Short version:

1. **Every CSE slot comes from `cse_insert` 0x10707e22.** It calls 0x10707ebc (at 0x10707e51), which calls
   `symbol_alloc(0xf)` (at 0x10707ec1) and marks the record class 3. Pool E (class 15) has no free list. Its
   ids are consecutive from C0 in 32-id chunks. In Hill/Valley that is 723 slots, 0x4e0 to 0x7b2, with no gaps
   and no reuse [verified].
2. **Freed CSE records do get reused, but only by ordinary temporaries.** `symbol_free_chain` 0x10706247 puts
   any class-3 record, including a CSE record, on `g_temp_symbol_free` 0x1079bc60. Pool A (class 3/6) pops that
   list LIFO. Pool E never does. In Hill/Valley, 900 of the 3003 class-3 allocations after `globopt_run` entry
   got recycled pool-E ids, and 480 of those came before the address pass [verified]. So a later compiler
   temporary can carry an id inside the CSE range, but a new CSE slot never takes a freed id.
3. **The order is the tuple order of `assign_expression_owners` 0x10711209.** It walks the tuples once. For each
   tuple it numbers:
   - each memory operand of the sources (call at 0x1071124b), then of the destinations (0x1071128c), as
     `0x14c(base operand +0x28, alias class +0x1c)`;
   - then the tuple itself:
     - a pure computation (add, sub, mul, cvt, and 0x15d load) through `operand_new_cse_sym` (0x107115d7);
     - a branch compare through `number_compare_expression` (0x10711555);
     - an intrinsic (0x11328) or 0x18f (0x11431).

   Plain assignments are numbered only in a second sweep over all 0x15b tuples, after the whole function
   (`number_assignment` at 0x10711671). In Hill/Valley that sweep starts at n = 415. A slot is created only
   when `cse_lookup` misses: same opcode, compatible type and the same key operands, or swapped key operands
   for a commutative opcode [verified: decompiled, and every slot traced with its key operands].
4. **So a first store `this->f = v` costs two slots, and a repeat store costs none.** C1 emits the member
   address as its own tuple `t = this + off`, which costs one pure `add` slot. The store's memory operand `[t]`
   then costs one 0x14c location slot, keyed by (t, alias class of f). The 0x14c slot is the "partner that
   never appears in the IL". Nothing discards it:
   - `assign_expression_owners` stores it in the operand's storage field (`j->storage`);
   - kill sets and load CSE use it;
   - no tuple ever uses it as an operand.

   The other header statements cost one slot each:

   | Statement | Slot |
   | --- | --- |
   | `(int)length` | cvt |
   | `steps + 1`, `last + 1` | add |
   | `(float)(last + 1)` | cvt |
   | `if (centered)` | compare, keyed `0x17e(param, 0)` |

   A first load through a member pointer, such as `primary_samples[0].x`, costs five: add, 0x14c, 0x15d
   load, `add(ptr, off)`, 0x14c.

## 1. Addresses

| Address | Name | Role |
| --- | --- | --- |
| 0x10711209 | `assign_expression_owners` | Value-numbering walk. Memory operands first, then the tuple. Then a second sweep over assignments. |
| 0x10707f1b | `cse_find_or_make` | Compares go to `get_compare_expression_symbol` 0x10707ff3. Other expressions call `cse_set_key_operands(2)` and then 0x10707fc4. |
| 0x10707fc4 | (unnamed) `cse_find_or_insert` | `hash_expression` + `cse_lookup`; on a miss, `cse_insert`. Returns entry+0x10, the expression symbol. |
| 0x10707e22 | `cse_insert` | ecx = hash bucket, edx = opcode, [esp+4] = type. Allocates the entry and the symbol (0x10707e51). 0x14c entries also join `g_address_expr_list`. |
| 0x10707ebc | (unnamed) `cse_new_expression_symbol` | `symbol_alloc(0xf)` at 0x10707ec1. Sets type and size, cls = 3, parent = self. `cse_insert` is its only caller. |
| 0x10707edc | (unnamed) `cse_claim_key_operands` | Copies `g_expr_operand_scratch` 0x10799620 into the entry's operand list. |
| 0x107017eb | `symbol_alloc` | Class 15 uses the pool-E chunk 0x1079bc74 (case 0x107018f9) and never pops a free list. |
| 0x10706247 | `symbol_free_chain` | Class 3, which includes CSE records, goes to `g_temp_symbol_free` 0x1079bc60. |
| 0x10708c14 | `number_assignment` | 0x15b numbers. Called from the second sweep and later from CSE, loops and strength reduction. |

## 2. Hill/Valley: what the nine swaps need

The canonical scratch is 100% normalized with nine encoded SIB swaps. C0 = 0x4e0. The three temporaries that
matter are:

| n | id | Temporary | First created |
| --- | --- | --- | --- |
| 6 | 0x4e6 | `this+0x54` (width_cells address) | header store `width_cells = width_cells_` |
| 21 | 0x4f5 | `this+0x58` (primary bank address) | then-arm of `if (centered)` |
| 45 | 0x50d | `this+0x5c` (secondary bank address) | `secondary_samples[0].transform.Identity()` |

The 21 slots before 0x4f5, from `cse_slot_trace.py`:

```text
n0-7   kind, is_mirrored_x, side_exit_mode, width_cells: add(this,off) + 0x14c each      (8)
n8     cvt(length)                                                                        (1)
n9-10  width_or_scale: add + 0x14c                                                        (2)
n11    add(steps, 1)        n12 add(last, 1)                                              (2)
n13-14 segment_count: add + 0x14c                                                         (2)
n15    cvt(last+1)          n16-17 segment_count_f: add + 0x14c                           (3)
n18-19 has_entry_mesh_transition: add + 0x14c                                             (2)
n20    compare 0x17e(centered, 0)                                                         (1)
n21    add(this, 0x58)  <- primary
```

Interventions on the canonical compile. `K:M` burns M pool-E ids before fresh slot K:

| Phantom | primary n | secondary n | Result |
| --- | --- | --- | --- |
| none | 21 (≡1) | 45 (≡1) | 100%, 9 swaps |
| `21:3,22:1` / `21:3,45:1` / `21:7,22:1` | 24 or 28 (≡0) | 49 (≡1) | **byte exact** |
| `21:3` | 24 (≡0) | 48 (≡0) | 100%, 8 *new* swaps at +0x39b/+0x3ff/+0x43f/+0x4cc/+0x4d3/+0x4d7/+0x50e/+0x51e |
| `21:3,46:1` … `21:3,300:1` | ≡0 | ≡0 | the same 8 new swaps (later temporaries shifted by 3 do not matter) |
| `21:2,22:2` | ≡3 | ≡3 | 95.88% |
| `7:3,22:1`, `11:3,22:1`, `14:3,22:1` | ≡0 | ≡1 | **byte exact** (n7–n20 are free) |
| `6:3,22:1`, `0:3,22:1` | ≡0 | ≡1 | 99.70% (the width_cells temporary n6 moved to ≡1) |
| `0:1,7:2,22:1` | ≡0 | ≡1, n6 ≡3 | **byte exact** |
| `0:2,7:1,22:1` | ≡0 | ≡1, n6 ≡0 | 99.70% |

The requirement (verified by these interventions, at C0 ≡ 0 mod 32):

```text
n(this+0x58) ≡ 0 (mod 4)        primary bank address: load leaf hash 7, so offset first at all 9 swap sites
n(this+0x5c) ≢ 0 (mod 4)        secondary sites are native bank-first: leaf hash 0x4007/0x8007/0xc007 > local 0xf's 0x1e0
n(this+0x54) ≡ 2 or 3 (mod 4)   width_cells address load leaf (0x8007 or 0xc007)
```

Two corrections to [sib-operand-order.md](sib-operand-order.md) §4 follow:

- All nine swaps are primary sites. `+0x430` is not a 0x50d site: `21:3` alone fixes it.
- Native does **not** want T & 3 = 0 for 0x50d. Moving both temporaries by −1/+3 fixes nine sites and
  breaks eight.

## 3. Code-neutral ways to move the count

Each row was compiled, and its function bytes were compared with a phantom build of the canonical source
that makes the same shift (`cmpobj`: byte-identical, so the source change affects ids only).

| Source change | Δ slots | Where |
| --- | --- | --- |
| `segment_count = last; ++segment_count;` | +2 | n13 (reload 0x15d + `add(load,1)`; CSE forwards the store and drops the reload) |
| `segment_count = last; ++segment_count; segment_count_f = (float)segment_count;` | +1 | n13 (`last + 1` is gone, reload and `cvt(load)` are added) |
| parenthesized float store in the else arm: `((float)width_cells * 0.5f - 4.0f)` or `((float)width_cells * 0.5f) - 4.0f` | +1 | n30 (FROUND 0x162); byte-identical to phantom `30:1` |

No change in count (C1 canonicalizes these):
- `centered != 0`, `(int)centered`, `!!centered`, `!(centered == 0)`;
- `primary_samples->center_x` and `= 0` in the then arm;
- `(int)(length)`;
- `int last = steps; ++last;` and `last += 1`;
- `(float)(1 + last)`, `(float)(int)(last + 1)`, and an implicit float conversion;
- `width_or_scale = 1`, `has_entry_mesh_transition = false`;
- swapping the segment_count/segment_count_f stores.

Count changes that also change code:

| Source change | Δ slots | Result |
| --- | --- | --- |
| `segment_count_f = (float)segment_count` alone | 0 | `last` becomes single-use and is folded to `steps + 2`: 93.94% |
| `centered & 1` | +1 | 95.43% |
| `centered == true` | 0 | 99.70%, `cmp al, 1` |
| FROUND on `segment_count_f` | +1 | 667 instructions |
| swapped arms | +4 | branch layout changes |
| `switch (centered)` | — | the arms are tail-merged |
| a `primary` binding before the `if`, used at least twice | primary n20 ≡ 0 | C0 drops to 0x4c0 when the binding stays a local (verified). Even with C0 restored by phantom `0:32`, or when C0 does not move, it is 96.03%: the terminal `Identity` receiver comes out bank-first. The cause may be the shift in later local ids [inferred] |
| a new index local before the branch | — | 85–96% |

Rule for a source edit:
- the slots it adds before n21, from n7 on, must total ≡ 3 (mod 4);
- n6 may move by 0 or +1;
- the total at the secondary must stay ≢ 0.

With the tools above that needs +3 in the header and ≥ +1 after the primary. The two segment_count forms give
only +1 or +2, so no single natural header spelling reaches +3. A double `segment_count_f` store does
(`s1f2_fr`, below).

## 4. Verified byte-exact source (copy of the canonical scratch)

```cpp
    int last = steps + 1;
    segment_count = last;
    ++segment_count;
    segment_count_f = (float)(last + 1);
    segment_count_f = (float)segment_count;
    ...
    else
        primary_samples[0].center_x = ((float)width_cells * 0.5f - 4.0f);
```

Result: primary n24 (0x4f8), secondary n49 (0x511), n6 unchanged.
`snail match scratch`: 100.00%, 668/668, "encoded body: match". The `((float)width_cells * 0.5f) - 4.0f` form
is also byte exact. The header is +3: reload +1, `add(load, 1)` +1, `cvt(load)` +1. The overwritten first
store is dead and gets removed. This is a proof of the rule, not a claim about the authored source.

## 5. The other six path builders

Each has one swap, at a `+0x90` access. `cse_slot_trace --sums` and interventions show that none is the
load-leaf/T & 3 case:

| Function | Swap | Ranked operands (key) | Intervention |
| --- | --- | --- | --- |
| TurnoverDouble | +0x2b1 | `temp 0x4bc` n28 (0x2f00) vs local 0x13 (0x260) | `28:836` moves 0x4bc to 0x800: byte exact |
| HalfPipe | +0x2f9 | `temp 0x4fc` n92 (0x3f00) vs local 0x17 (0x2e0) | `92:772`: byte exact |
| Turnover | +0x28b | `temp 0x531` n113 (0x4c40) vs local 0x15 (0x2a0) | `113:719` fixes it but flips +0x272 (endpoint temporary n111) |
| LoopBow | +0x327 | `temp 0x5fd` n125 (0x7f40) vs iv 0x94b (0x52c0) | `125:515` fixes it, flips +0x311 |
| LoopTheLoop | +0x316 | `temp 0x576` n118 (0x5d80) vs iv 0x890 (0x2400) | `118:650` fixes it, flips +0x300 |
| LoopOut | +0x2e7 (load) | three `load+0x90` sums: iv 0x7d8/0x864/0x92a vs `[temp 0x560]` (leaf, hash 7) | residue shifts of 0x560 or the iv give 94–96%; not resolved |

In those five, the bank at the swap site is the loaded pointer value as a CSE temporary, a symbol leaf with
hash `(id << 6) & 0xffff`. A symbol leaf needs `id mod 1024` inside a small window. That takes hundreds of
ids, not a residue mod 4. This is the window table in snail's address-order.md. Their bank-address load
leaves (this+0x58: 0x4da, 0x4ba, 0x560, 0x5a0, 0x500, 0x4ae) already sort like native. So one T & 3 rule, or
one shared header edit, cannot cover all seven. Hill/Valley is the only builder whose swaps are load leaves
through the address temporary.

## 6. Tool

```sh
# from the snail-mail checkout
uv run python ../crimson/scripts/c2/cse_slot_trace.py <scratch> --out <new-dir> [--source overlay.cpp] \
    [--upto 0x4f6] [--lines A-B] [--sums] [--phantom K:M[,K:M]]
```

The tool prints, for each pool-E slot:
- n, id, `id & 3`, opcode and key operands (0x14c keys show `#alias`);
- whether the id is still an IL operand at the address pass;
- the line label and tuple opcode being numbered, and the return-address chain.

It then prints the matcher result and the encoded SIB swaps. `--phantom` is the intervention mode: it
compiles again with burned pool-E ids and matches that object instead.

## Open questions

- A natural authored spelling that adds +3 (or −1) slots between n7 and the `if (centered)` then-arm without
  changing code. The ones measured give 0, +1 or +2. A double store does it.
- LoopOut's swap site: which of the three `load+0x90` sums it is, and why native puts the bank first there.
  One possibility is a load/expr, meaning the bank address is not available at that site [inferred].
- Why a primary binding before the branch lowers C0 by 32. Pool A's peak there is exactly 0x4c0; one fewer
  C1 temporary would drop a chunk [inferred].

## Corrections to other notes

- optimizer.md, `purge_unreferenced_temps`: "temp ids are recycled LIFO" is true for pool A. CSE expression
  symbols (pool E) never take a recycled id. Their records are freed onto the same list, though, so later
  class-3 temporaries can carry ids inside the CSE range.
- snail address-order.md, "This includes candidates it later discards": nothing is discarded. The
  never-in-IL slots are the 0x14c memory-location numbers, which are kept in the operand's storage field, and
  the second-sweep 0x15b assignment numbers.
- sib-operand-order.md §4:
  - The nine swaps are all 0x4f5 (primary) sites.
  - Native needs 0x50d ≢ 0 (mod 4), not ≡ 0.
  - The line-293 FROUND (99.70%) does not change code; its 99.70% is the id shift alone (byte-identical to
    phantom `30:1`).
  - The line-285 FROUND does change code (667 instructions).
