# CSE id push: what C0 is made of, and what moves it (C2.DLL 8966)

A CSE temporary that sits in an address sum or a commutative operand list is ranked by its id: as a symbol
leaf by `(id << 6) & 0xffff`, so by `id mod 1024` ([cse-slot-count.md](cse-slot-count.md),
[sib-operand-order.md](sib-operand-order.md)). When native's order needs a temporary just past a multiple of
1024, the question is which source constructs move the id, and by how much. This note says what the id is
made of and what the measured constructs cost.

"Verified" means a compile checked by a matcher. "Intervention" means a phantom run, which burns extra pool-E
ids in a traced compile ([cse-slot-count.md](cse-slot-count.md) §2). "Inferred" means it fits the data but was
not traced.

## 1. What an id is made of

`id = C0 + n`:

- **C0** is the symbol-id counter `g_next_symbol_id` 0x1079bc4c when the first CSE slot is allocated. Every pool
  takes 32-id chunks from the same counter (`symbol_chunk_new` 0x107079c3). So C0 = 32 × (chunks opened before
  value numbering), and it moves only in whole blocks.
  - `symbol_pools_reset` 0x1071b9b0 sets the counter to 0 and opens the first chunk of pools B, C, A and D
    [read].
  - Most chunks before C0 are opened while the IL is read: `reader_binary_op` / `tuple_new_binary_temp`,
    `reader_read_call`, `node_alloc`, parts, `fe_symbol_get_storage` and compares. A few are opened later, by
    tree simplification (`emit_tree_as_tuples`, `fold_constant_operands`, `simplify_conversion`) [verified on
    Snail Mail's initialize_turnoverdouble_path_template_pair].
  - So C0 tracks the IL size of the **whole function**, including code after the site that the id decides.
    Deleting a region of the function removes the blocks its IL opened [verified].
- **n** is the slot's position in value numbering. Only tuples before it count, at the costs in
  [cse-slot-count.md](cse-slot-count.md).

Temporary hashes use `id mod 1024`. A C0 change of −k blocks therefore ranks every CSE temp exactly like a
+(32 − k)-block change. A `0:M` phantom (burn M ids before slot 0) reproduces that for all temps, but locals do
not move.

Pool-B chunks opened by locals and parts move C0 as well ([pu-id-delta-profile.md](pu-id-delta-profile.md)).

## 2. What moves C0 with the same instructions

Measured on compiles that keep the instructions identical [verified on Snail Mail's path builders]:

- **Inlined helpers are id-neutral.** An expansion reuses freed temporaries (LIFO), so writing a loop as a
  forceinline helper, or a helper back into the body, leaves C0 unchanged.
- **`(unsigned int)` instead of `(char *)` byte casts** add C1 temporaries: +7 blocks in two path builders.
- **A component constructor or a differently structured mesh helper** can add one block.
- **Pointer-type casts** (`T *` instead of another pointer type, `(*(T *)…).f` instead of `((T *)…)->f`),
  extra locals such as a named total or a named zero, and index spellings like `a + 2 * (row * w + column)` add
  nothing.

Nothing measured lowers C0 without changing code. Because C0 rounds to whole chunks, the costs do not simply
add up.

A change of C0 is ≡ 0 (mod 4), so it keeps every load leaf `[T]` (hash `((T & 3) << 14) + 7`) in the same
order. A change of n before such a temporary can change it.

## 3. Single-slot and whole-function shifts

A `K:M` phantom moves only the temporaries created at or after slot K. When the temporary that decides a site
is pushed alone, a second site where it was compared with an earlier temporary can flip. A `0:M` shift moves
every temporary together and avoids those flips. It is the shift that a C0 change would make [intervention].

## Open questions

- Why tree simplification (`simplify_conversion`, `emit_tree_as_tuples`) opens chunks past the reader's peak
  (six in Snail Mail's TurnoverDouble builder). It is the only part of C0 that is not a direct count of the IL.
