# CSE slot count: what creates a CSE temporary id (C2.DLL 8966)

The hash of a CSE temporary is its id: `(id << 6) & 0xffff` as a symbol leaf, and `((id & 3) << 14) + 7`
inside a load leaf `[T]` ([sib-operand-order.md](sib-operand-order.md)). The id is `C0 + n`, where n is the
temporary's position in the order value numbering creates slots. This note says what creates a slot, and in
what order, and how to test which id shift a sort order needs.

"Verified" means seen in preserving traces, read in Binary Ninja, or checked by a compile and a matcher.
"Intervention" means a phantom run: the same compile with extra pool-E ids burned at a chosen slot, then
matched. "Inferred" means it fits the data but the code was not read.

Short version:

1. **Every CSE slot comes from `cse_insert` 0x10707e22.** It calls 0x10707ebc (at 0x10707e51), which calls
   `symbol_alloc(0xf)` (at 0x10707ec1) and marks the record class 3. Pool E (class 15) has no free list. Its
   ids are consecutive from C0 in 32-id chunks, with no gaps and no reuse [verified on Snail Mail's
   initialize_hill_valley_path_template_pair].
2. **Freed CSE records do get reused, but only by ordinary temporaries.** `symbol_free_chain` 0x10706247 puts
   any class-3 record, including a CSE record, on `g_temp_symbol_free` 0x1079bc60. Pool A (class 3/6) pops that
   list LIFO. Pool E never does. So a later compiler temporary can carry an id inside the CSE range, but a new
   CSE slot never takes a freed id [verified].
3. **The order is the tuple order of `assign_expression_owners` 0x10711209.** It walks the tuples once. For each
   tuple it numbers:
   - each memory operand of the sources (call at 0x1071124b), then of the destinations (0x1071128c), as
     `0x14c(base operand +0x28, alias class +0x1c)`;
   - then the tuple itself:
     - a pure computation (add, sub, mul, cvt, and 0x15d load) through `operand_new_cse_sym` (0x107115d7);
     - a branch compare through `number_compare_expression` (0x10711555);
     - an intrinsic (0x11328) or 0x18f (0x11431).

   Plain assignments are numbered only in a second sweep over all 0x15b tuples, after the whole function
   (`number_assignment` at 0x10711671). So copies never move the ids of expressions. A slot is created only
   when `cse_lookup` misses: same opcode, compatible type and the same key operands, or swapped key operands
   for a commutative opcode [verified: decompiled, and every slot traced with its key operands].
4. **So a first store `this->f = v` costs two slots, and a repeat store costs none.** C1 emits the member
   address as its own tuple `t = this + off`, which costs one pure `add` slot. The store's memory operand `[t]`
   then costs one 0x14c location slot, keyed by (t, alias class of f). The 0x14c slot is the "partner that
   never appears in the IL". Nothing discards it:
   - `assign_expression_owners` stores it in the operand's storage field (`j->storage`);
   - kill sets and load CSE use it;
   - no tuple ever uses it as an operand.

   A conversion, an add or a branch compare (keyed `0x17e(x, 0)` for `if (x)`) costs one slot each. A first
   load through a member pointer, such as `bank[0].x` with `bank` a member, costs five: add, 0x14c, 0x15d
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

## 2. Testing an id shift (intervention)

A phantom run hooks pool-E allocation in the preserving observer. Before fresh slot K it calls
`symbol_alloc(0xf)` M extra times (`K:M`), then lets the compile finish and matches the object. Several
`K:M` pairs can be combined. `0:M` shifts every CSE temporary together.

- A phantom build shows which residues or windows of `n` a sort order needs, without any source change.
- A source change that moves ids only compiles to function bytes identical to the phantom build with the same shift.
  That separates "this spelling changes the code" from "this spelling only moves ids".
- A single-slot push moves only the temporaries created at or after K. It can flip a second site where the
  pushed temporary was compared with one created before K. `0:M` avoids that ([cse-id-push.md](cse-id-push.md)).

## 3. What source changes cost

Measured with phantom builds for comparison [verified on Snail Mail's Hill/Valley path builder]:

- **Slot-neutral spellings.** C1 canonicalizes these, so the count does not change: `x != 0`, `(int)x`,
  `!!x` and `!(x == 0)` for a bool test; `int n = a + 1`, `int n = a; ++n;` and `n += 1`; `(float)(1 + n)`,
  `(float)(int)(n + 1)` and an implicit float conversion; the order of two independent stores.
- **A store followed by an increment of the member** (`f = v; ++f;`) adds two slots: a reload (0x15d) and `add(load, 1)`.
  CSE forwards the store and drops the reload, so the code is unchanged.
- **A parenthesized non-leaf float expression** adds one FROUND (0x162) slot and nothing else
  ([codeless-tuples.md](codeless-tuples.md)).
- **An overwritten store** is dead and gets removed, but its slots stay: value numbering runs first.

## Corrections to other notes

- optimizer.md, `purge_unreferenced_temps`: "temp ids are recycled LIFO" is true for pool A. CSE expression
  symbols (pool E) never take a recycled id. Their records are freed onto the same list, though, so later
  class-3 temporaries can carry ids inside the CSE range.
