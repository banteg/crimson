# SIB base/index order when one register is a loaded pointer (C2.DLL 8966)

This note covers `[a + b + disp]` addresses in which one operand is a pointer loaded from memory, such as
`p->bank[i]`: the bank `p->bank` and the offset `i * sizeof(*bank)`. A sum of two plain symbols is a pure
hash compare. This note adds the other operand kinds, most importantly a load whose address is or is not a
CSE temporary.

"Verified" means observed in preserving traces of real compiles (an address-pass observer over the sorted
sums, and `sort_trace.py`), in Binary Ninja, and in matcher results. "Inferred" means it fits every trace,
but the code path was not read.

Short version:

1. The first operand of the sorted address sum becomes the SIB base and the second becomes the index. The
   sort is `compute_tree_cost_and_sort` 0x1070d90c. It calls `merge_sort_operand_list` 0x1070f584 with
   `compare_operand_cost_desc` 0x1070f6ae (at 0x1070da8d), which is stable and unsigned descending on the
   key `need<<24 | size<<16 | hash16` [verified: read, and both orders compiled].
2. A load `[addr]` gets one of two kinds of key [verified: 0x1070d9c4–0x1070da11 read, all keys re-derived]:
   - **Its address is still an expression temporary** (C1's `p + 0x5c`, not CSE'd). The load takes the
     address tree's cost: need ≥ 1, size ≥ 2. It then sorts above every leaf, so the **bank is the base**.
   - **Its address is a symbol** (a CSE temporary T, or a local or parameter p when the field is at offset 0).
     The load is a leaf: need 0, size 1, and hash `(fold(disp) + (0x14c − 0x145) + (hash(addr) << 8)) & 0xffff`.
     For disp 0 this is `((T & 3) << 14) + 7` for a class-3 temporary and `((p & 7) << 13) + 7` for a local
     or parameter below 0x800. The load then competes with the other register by hash.
3. `p + off` becomes a CSE temporary when the same address is **available**: it was computed on every path
   since the last definition of `p`. An assignment to `p`, even of the same value, kills it. So does a first
   computation that sits in only one arm of a branch (verified on Snail Mail's traverse_path_follow_golb).
   Stores and calls do not kill it, because it is register arithmetic (verified: an address temporary lives
   across calls in Snail Mail's Hill/Valley path builder).
4. The instructions are the same either way: the address temporary folds back into `mov esi, [edx+0x5c]`.
   Only the SIB byte shows which kind of key the load had.

## 1. The key of each operand kind

`compute_tree_cost_and_sort` sets `operand+0x0c` for every operand of a tuple, sorts commutative tuples, and
sets the tuple's own key to `hash_operand(t) | pack_expression_cost(t)`.

| Operand | Key | Source |
| --- | --- | --- |
| symbol leaf (kinds 2–4, no def) | need 0, size 1, `hash_operand` (class 3: `id << 6`; class 4/5 below 0x800: `id << 5`) | 0x1070da9a, 0x1070dc01 |
| symbol with a def (kind 1/2 expression temporary) | the def tree's key | 0x1070d9a6–0x1070d9ba |
| memory (kinds 5/6) whose base is a symbol with a def | the base's def-tree key: need ≥ 1 | 0x1070d9c4–0x1070da11 |
| memory whose base is a symbol without a def | leaf: need 0, size 1, hash `fold(disp) + opcode − 0x145 + (hash(base) << 8)`, 16 bits | 0x1070da9a, 0x1070dbc5 |
| constant | need 0, size 0, hash of the value | 0x1070da9a |
| tuple | size 1 + Σ size; need = max(need) plus 1 on ties, in sorted order; hash `Σ childhash << (i & 7) + opcode − 0x145` | 0x1070da9a, 0x1070dc8f |

A tuple such as `local + const` already has need 1 and size 2. So any expression operand outranks any leaf.

The memory operand's opcode is 0x14c, so its hash term is +7. The shift by 8 keeps only the base hash's
low byte. So a load through a class-3 temporary T hashes to `((T & 3) << 14) + 7 + fold(disp)`, and through
a local p below 0x800 to `((p & 7) << 13) + 7 + fold(disp)`.

## 2. Where the sort happens, and stale keys

The expression pass runs before and after globopt. Its last event for a tuple fixes the order that the
address pass (0x107281cd) sees, and lowering encodes that order. A sum can change order between the two
events: `(i * 0xa8) + [p+0x5c] + 0x8c` sorts the product first before globopt, but after CSE the product is a
temporary (need 0) and the load comes first. `sort_trace.py` shows both events.

Tuples built after the last expression pass, by strength reduction or address folding, keep key 0 on their
new expression operands. Their order comes from whoever built them, not from this sort.

## 3. Rule

```text
key(op) = need<<24 | size<<16 | hash16, compared unsigned, descending, stable; first = SIB base
symbol leaf s            : (0, 1, H(s))            H: class 3 -> (id<<6)&0xffff; class 4/5 id<0x800 -> id<<5
load [s + disp], s leaf  : (0, 1, (fold(disp) + 7 + (H(s) << 8)) & 0xffff)
load [e], e an expression: key(tree(e))  -> need >= 1: always first
expression e             : key(tree(e))  -> need >= 1: always first
```

Whether the address of `p->f` is a leaf: it is a CSE temporary iff `p + off(f)` was computed on every path
since the last assignment to `p`, or `off(f) = 0` and `p` itself is a symbol. CSE temporaries number C0 + n
in first-occurrence order ([cse-slot-count.md](cse-slot-count.md)).

A model of the sort has to drop the trailing register uses of memory operands in the address pass's sums:
one per nonzero base (+0x28) or index (+0x2c). It has to accept kinds 1 and 6 as ranked operands, classify
loads as `load/leaf` or `load/expr` from the base's kind and def, and re-derive the leaf hash. Sums whose
ranked keys are 0 or out of order are stale (§2).

## Open questions

- The code that builds the stale-key sums (strength reduction or address folding) and which order it keeps.
- Whether CSE numbers the address temporary at its first occurrence or at its first redundancy. The traces
  fit first occurrence: in Snail Mail's traverse_path_follow_golb the address temporary keeps its n whether
  or not a later reassignment kills it.
