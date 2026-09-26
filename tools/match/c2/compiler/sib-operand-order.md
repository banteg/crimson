# SIB base/index order when one register is a loaded pointer (C2.DLL 8966)

This note covers `[a + b + disp]` addresses in which one operand is a pointer loaded from memory, such as
`p->bank[i]`: the bank `p->bank` and the offset `i * sizeof(*bank)`. snail-mail's `address-order.md` and
`addrorder.py` model a sum of two plain symbols. This note adds the other operand kinds, most importantly a
load whose address is or is not a CSE temporary.

"Verified" means observed in preserving traces of real compiles (`scripts/c2/sib_operand_trace.py`,
`sort_trace.py`), in Binary Ninja, and in snail matcher results. "Inferred" means it fits every trace, but
the code path was not read.

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
   computation that sits in only one arm of a branch [verified in traverse_path_follow_golb]. Stores and calls
   do not kill it, because it is register arithmetic [verified: Hill/Valley's `this+0x58` temporary lives
   across calls].
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
address pass (0x107281cd, snail `ADDRESS_PASS_HOOK`) sees, and lowering encodes that order. Pre-globopt,
traverse's `delta_length` sum is `(sample_index * 0xa8) + [ct+0x5c] + 0x8c` with the product first. After CSE
the product is temporary 0x309 (need 0), so the load comes first. `sort_trace.py` shows both events.

Tuples built after the last expression pass, by strength reduction or address folding, keep key 0 on their
new expression operands. `sib_operand_trace.py` marks such sums `keys stale`. Their order comes from
whoever built them, not from this sort. Hill/Valley's `compute_path_deltas` loop has four of them.

## 3. traverse_path_follow_golb (snail-mail)

The residual: native has `fdiv dword [eax+esi+0x8c]` at +0x254/+0x28a/+0x2c0, and the canonical build has
`[esi+eax+0x8c]`. The sites are the three `progress / current_template->secondary_samples[sample_index].delta_length`
interpolations (source lines 77/88/99, C2 labels 70/81/92). The alpha at +0x46c (line 165) has the same shape.

The address pass shows this sum in each else-arm (base build, C0 = 0x300):

```text
ADD  [expr(local 5 current_template + 0x5c)]  key 0x01020180 (need 1, size 2, hash 0x180 = 0xa0 + 0x5c<<1 + 0x28)
     temp 0x309  key 0x0001c240   (pool E CSE temporary n=9: sample_index*0xa8; 0x308 n=8 is the sample_index load)
ADD  t + 0x8c  -> fdiv [t]
```

The bank load is an expression operand, so it is the base: `esi`. The cause is source line 69,
`current_template = template_record;`. It redefines local 5 after lines 13 and 64 computed
`current_template + 0x5c`. After it, the first computation of that address is in the first else-arm, which
does not dominate the second or third, so CSE never makes it available.

**Delete line 69.** `current_template` is already the same pointer, and the listing does not change: native
and ours both use edx without a reload. Then `current_template + 0x5c` from line 13 is available everywhere,
as CSE temporary 0x303 (n=3). Each site becomes

```text
ADD  temp 0x309  key 0x0001c240
     [temp 0x303] key 0x0001c007   (leaf: ((0x303 & 3) << 14) + 7)
```

That puts the offset first, which is native's `[eax+esi+0x8c]`. Results on copies:

| Build | Normalized | Encoded | State |
| --- | --- | --- | --- |
| canonical | 99.53%, prefix 327 | not compared | wip (Y-lane operand order) |
| canonical − line 69 | 99.53%, prefix 327, identical diff | the three bytes flip to native `d8 b4 30 8c`; the object differs from canonical only in those 3 bytes (plus timestamp and COMDAT checksum) | wip |
| scale-operand-rank `P_pad2` (Y-lane fix + two padding ints) | 100% | 3 SIB swaps | audit |
| `P_pad2` − line 69 | 100%, 425/425 | **byte exact** | **match** |
| `K_both` (C0 = 0x2e0) − line 69 | 100% | 4 swaps: +0x254/+0x28a/+0x2c0/+0x46c | audit |

The `K_both` row was predicted before it was compiled. At C0 = 0x2e0 the offset is 0x2e9, hash 0xba40, and the
bank address is 0x2e3, whose leaf hash 0xc007 is larger. So all four loads sort first.

The margin: with n(offset) = 9 and n(address) = 3, offset-first needs `(C0 + 9) mod 1024 ≥ 0x301`, which
means C0 mod 1024 ≥ 0x300 for a C0 that is a multiple of 32. Two other ways to satisfy it:
- move the address temporary to n ≢ 3 (mod 4), which makes its leaf hash 7, 0x4007 or 0x8007;
- keep C0 at 0x300, as P_pad2's +2 does.

## 4. Hill/Valley check (initialize_hill_valley_path_template_pair)

The canonical build is 100% normalized with 9 SIB swaps (C0 = 0x4e0). `addrorder.py` lists none of them.
`sib_operand_trace.py` shows that each sorted swap site is a load leaf through the bank-address CSE
temporaries 0x4f5 (`this+0x58`, n=21) and 0x50d (n=45), against the byte-offset local 0xf or cursor local 0x1c9:

```text
ln82  load+0x90   base [temp 0x4f5] 0x14007   index local 0xf 0x101e0     (+0x28e)
ln83  store-0xa8  base [temp 0x4f5] 0x14007   index local 0xf 0x101e0     (+0x2f1)
ln83  store-0xa8  base [temp 0x50d] 0x14007   index local 0xf 0x101e0     (+0x430)
ln89  store+0x8c  base [temp 0x4f5] 0x14007   index local 0x1c9 0x13920   (+0x4c2)
```

Swap offsets are matched to sums by access and displacement [inferred]. The other swaps (+0x313/+0x317/+0x31b/+0x358/+0x4b3) look like `lea`s and accesses of the same sums, including sums whose result is passed to an inline member rather than dereferenced, which the tool does not list [inferred].

- **Native order.** The offset comes first, which needs the load leaf's hash below 0x1e0. That means
  T & 3 = 0 for the primary temporary (see the correction below).
  Alternatively, the offset local needs id ≥ 0x201.
- **Consistent sites.** The same function has sites where native agrees with the rule and ours matches:
  - `local 0xf` (0x1e0) before `[local 0x10]` (hash 7, because 0x10 & 7 = 0), at labels 69–81;
  - `[local 0xd]` (0xa007) before `local 0xf`;
  - temp 0x516 (0x4580) before `[temp 0x4f5]`.
- **Authoring.** The parenthesized-expression shifts measured move n by +1 but change the listing: a FROUND
  at line 285 gives 95.58%, one at line 293 gives 99.70%. So Hill/Valley is characterized, but not fixed.
- **Correction** ([cse-slot-count.md](cse-slot-count.md)). All 9 swaps are primary (`this+0x58`) sites.
  Native needs the primary n ≡ 0 (mod 4) and the secondary n ≢ 0: shifting both temporaries adds 8 new
  swaps at the secondary sites. The line-293 FROUND leaves the code unchanged; its 99.70% is the id shift
  alone. Only the line-285 FROUND changes code.

## 5. Rule for addrorder.py

```text
key(op) = need<<24 | size<<16 | hash16, compared unsigned, descending, stable; first = SIB base
symbol leaf s            : (0, 1, H(s))            H: class 3 -> (id<<6)&0xffff; class 4/5 id<0x800 -> id<<5
load [s + disp], s leaf  : (0, 1, (fold(disp) + 7 + (H(s) << 8)) & 0xffff)
load [e], e an expression: key(tree(e))  -> need >= 1: always first
expression e             : key(tree(e))  -> need >= 1: always first
```

Whether the address of `p->f` is a leaf: it is a CSE temporary iff `p + off(f)` was computed on every path
since the last assignment to `p`, or `off(f) = 0` and `p` itself is a symbol. Temporaries number C0 + n in
first-occurrence order, as in address-order.md.

In `address_sums`, drop the trailing register uses of memory operands: one per nonzero base (+0x28) or
index (+0x2c). Accept kinds 1 and 6 as ranked operands. Classify loads as `load/leaf` or `load/expr` from
the base's kind and def, and re-derive the leaf hash. Mark sums whose ranked keys are 0 or out of order as
stale. `scripts/c2/sib_operand_trace.py` implements this on top of addrorder's observer.

## 6. Tool

```sh
# from the snail-mail checkout
uv run python ../crimson/scripts/c2/sib_operand_trace.py <scratch> --out <new-dir> [--lines A-B] [--source overlay.cpp]
```

For each sum whose result addresses memory, it prints the C2 line label, the access and displacement, and
the ranked operands with key, kind (`sym`, `load/leaf`, `load/expr`, `expr`) and identity (class, slot, CSE
n). It then prints C0 and, at 100% normalized, the matcher's SIB swaps. It fails if a leaf key disagrees
with the re-derived hash.

## 7. Corrections to other notes

- snail `address-order.md`, "What source changes do": "A reloaded member is an expression operand … stores
  come out offset-first". A reloaded member is an expression, and so sorts **first** (bank = base), only
  while its address is not a CSE temporary. When `p + off` is available, the load is a leaf, ranked by
  `((H(T) & 0xff) << 8) + 7`.
- snail `address-order.md`, kinds table: the memory hash row is right. Note that the key is not
  `0x10000 | hash` when the base has a def: then the load carries the address tree's need and size.
- crimson `scale-operand-rank.md` §3 says the three SIB swaps "base already has" remain. They are removed by
  deleting line 69; P_pad2 − line 69 is byte exact.

## Open questions

- The code that builds the stale-key sums (strength reduction or address folding) and which order it keeps.
  Hill/Valley's ln89 `store-0x28`/`-0x1c` sums use it.
- Whether CSE numbers the address temporary at its first occurrence or at its first redundancy. The traces
  fit first occurrence: 0x303 is n=3 whether line 69 is present or not.
