# Which call runs first in `f(a) == f(b)` (C2.DLL 8966)

This note explains how C2 orders two call subtrees that are the operands of one binary operator, for
example `if (RstrASC(key) == RstrASC(g_old_key))`. Addresses are virtual addresses in the pinned
C2.DLL (image base 0x10700000). "Verified" means confirmed by a preserving compiler trace
([`scripts/c2/su_order_trace.py`](../../../../scripts/c2/su_order_trace.py), IL dumps through
`il_stage_trace.py` hooks) or by compiles with a matcher result. "Read" means static reading only.

Short version:

1. The frontend emits the calls in source order. The expression-tree pass reorders them. Calls are
   tree-substituted into their single use like any other temp definition, so `f(a) == f(b)` becomes
   one tree `cmp(call f(a), call f(b))`.
2. `==`/`!=`/`<` are IL 0x17d. That opcode is **not** in the commutative sort set, so the operands keep
   their source order. It is in the reorderable set, so `emit_tree_as_tuples` 0x1070e114 emits the
   **right operand's subtree first when its packed key is strictly greater** than the left one's (a
   Sethi-Ullman choice). Float-typed nodes are never reordered.
3. The key is `need<<24 | size<<16 | hash16`. Two calls of the same function with one plain argument
   have equal need (8) and size (5), so **hash16 decides**.
4. A call's hash16 is `callee + 2*arg + 0x3f`, truncated to 16 bits. `callee` is the xor-folded
   frontend id of the called function, a translation-unit-wide declaration counter. `arg` is the
   argument leaf's hash plus 0x15. A symbol's hash is about `id<<5`, where locals are numbered 1..31
   and globals from 32 in each function.
5. So `f(local) == f(global)` normally runs `f(global)` first, whatever the operand order, because the
   global's id is larger. **But the 16-bit sum can wrap.** When the callee's frontend id lies in a
   window just below 0x10000, the global side wraps to a small hash and `f(local)` runs first. Whether
   that happens depends on how many declarations precede the callee's declaration in the TU.
6. The simplifier runs twice, before and after globopt (`optimize_expression_trees` 0x1070fc45 modes 1
   and 2). Both passes re-substitute the calls and decide again. The **second (post-globopt)
   decision is final**.

## 1. Mechanism

| Step | Function | What happens (verified unless noted) |
|---|---|---|
| Reader | `il_read_tree` 0x10714b7f | The call tuples, their 0x15a argument copies and the int promotions appear in source order: left call first. Swapping the `==` operands swaps the IL order. |
| Tree build | `build_nary_expression_tree` 0x1070c148 | Each single-def temp whose def is marked substitutable (`+0x12 == 2`, `decide_tree_substitution` 0x1070bd4e) is pulled into its use. **Call tuples (kind 0xe) are substituted**: the compare's operands become the two call subtrees. The int promotions are narrowed away, so the compare becomes `0x17d ty1001(call, call)`. |
| Cost | `compute_tree_cost_and_sort` 0x1070d90c, `pack_expression_cost` 0x1070da9a, `hash_operand` 0x1070db59 | Every operand's key is the packed cost of the tree reached through its temp's `sym->def`, recursively. Materialized defs are followed too. The commutative sort (0x107062ef set) does not include 0x17d. |
| Order | `emit_tree_as_tuples` 0x1070e114, call sites 0x1070e320 (substituted node) and 0x10792d4a (materialized root) | `if is_reorderable_binary_opcode(node) && compare_operand_cost_desc(A, B) > 0 && (type & 0xf000) != 0x4000` then emit B's subtree, then A's. `compare_operand_cost_desc` 0x1070f6ae returns 1 only for `key(A) < key(B)` (unsigned), so ties keep A first. Operand order in the tuple is unchanged, so `cmp A, B` keeps its direction. |
| Pass 2 | `optimize_expression_trees(ctx, 2)` after globopt | The call temps are substituted again and step "Order" runs again on the post-globopt IL. Traced: both runs report the same keys for a plain local and global; the volatile case below differs between runs and the pass-2 order wins. |

`is_reorderable_binary_opcode` 0x1070e560 (byte table 0x1070e850) is true for 0x16d-0x16f and
0x171-0x183 except 0x179-0x17c, so it covers compares, subtraction, shifts, division and the logical
ops. Only 0x170 and the loop-IV ops 0x179-0x17c keep left-to-right order.

## 2. The packed key of a call

`pack_expression_cost` (read, and every number below was checked in traces):

- Leaf: size 1 (0 for the constant kinds 7-9), need 0.
- Node: size = 1 + sum of child sizes. `need` starts at child 0's need; each later child with a larger
  need sets `need = child + 1`, and one with an equal need adds 1. Kind 0xe (call) adds 7, and kind
  0x12 (intrinsic) adds 5.

A call `f(x)` has the sources `[callee (kind 4), arg temp (0x15a def), memory effect (kind 0xb)]`. The
argument subtree `0x15a(x)` has size 2 and need 0, so the call has **need 8 and size 5**.

`hash_operand` dispatches on operand kind through byte table 0x1070e800 and jump table 0x1070e7e0
(read, and verified numerically):

| Kind | hash16 |
|---|---|
| 1, 2 symbol (not class 3) | `v = id>>16 ^ id&0xffff`; `((v & 0x7ff) << 5) ^ ((v << 5) >> 16)`, which is `id<<5` for id < 0x800 |
| 1, 2 class-3 temp without a def | `id << 6` |
| 1, 2 temp with a def | the def tree's hash |
| 3 `&sym` | folded id, unshifted |
| **4 code address (callee, label)** | **`v = fe->id (+0x28)`; `v>>16 ^ v&0xffff`** |
| 5, 6 memory | `fold(disp) + addrform - 0x145 + hash(base) << 8` |
| 7 int constant | fold of the 64-bit value |
| 9 float constant | fold of the handle |
| 0xa, 0xb | 0 |
| tuple | `(sum(child_hash << (i & 7)) + opcode - 0x145) & 0xffff` |

For `f(x)` this gives

```
hash(call f(x)) = (callee + 2 * (hash(x) + 0x15) + 0x3f) mod 0x10000
```

`fe->id` is the frontend record id (core.md, fe record +0x28). Verified behaviour: it grows by 1 per
enumerator and by 2 per `void f(int);` declaration placed **before** the callee's declaration. Padding
placed after the declaration changes nothing. In the snail scratch it is 0x10a with the project
headers only, 0xa3cf with `<windows.h>` in front, and 0xb60d with windows, mmsystem, ddraw, dinput,
dsound, stdio, stdlib, string and math in front.

## 3. Symbol ids

Verified with IL dumps on small functions:

- Ids are per function and assigned when the reader first sees the symbol, not at its declaration. A
  local declared first but assigned later gets a later id.
- `symbol_alloc` 0x107017eb takes ids from 32-entry chunks, one pool per class. In every function the
  **locals take 1..31 and the globals start at 32**, even when a global is referenced first or the
  function has no locals. Temps come after that. A 32nd local opens a new chunk (192 in the probe),
  above the globals.
- Globals referenced by earlier functions in the same TU do not keep their ids.

So a plain global argument (hash ≥ 0x400) outranks any of the first 31 locals (hash ≤ 0x3e0), unless the
16-bit call-hash sum wraps.

## 4. The rule, and how to predict it

For `lhs == rhs`, where both sides are `f(one plain symbol argument)` of the same function:

- `lhs` runs first iff `hash(call lhs) >= hash(call rhs)`, as unsigned 16-bit values. The compare
  stays `cmp lhs_result, rhs_result`. The first result goes to a scratch register copy (`mov dl, al`)
  and is spilled around the second call.
- With `c` = callee fe id folded, `L = 2*(hash(lhs_arg) + 0x15) + 0x3f` and `R` likewise:
  `lhs first  <=>  (c + L) mod 2^16 >= (c + R) mod 2^16`.
- For a local argument (id `l` < 32) against a global (id `g` ≥ 32), the local call runs first exactly
  when `c + R` wraps and `c + L` does not: `0x10000 - R <= c < 0x10000 - L`. That is a window of
  `R - L = 64*(g - l)` fe ids.
- Swapping the source operands never changes which call runs first. It only flips the `cmp` direction.
- Anything that adds a node to one call's argument tree in **pass 2** makes that call run first by
  size. Verified: `volatile` on the local makes `globopt_canonicalize_tuples` 0x10713989 split its
  read into a materialized load (0x15d, later 0x15b). Pass 2 sees `size 6` and runs the local call
  first. It also moves the local and narrows the push load, so it does not help matching. A pointer
  borrow `*p` splits the same way in pass 1, but `globopt_fold_adjacent_copies` 0x10726654 folds the
  load back before pass 2, so it is neutral.

## 5. Snail-mail: `read_repeating_text_input_key_code` (0x4327e0)

Native tail:

```
mov eax, dword [esp+8]   ; key (stack home)
push eax
call RstrASC
mov cl, byte [g_last]
mov dl, al               ; first result, expression temp
push ecx
mov byte [esp+0xf], dl   ; spilled around the second call
call RstrASC
mov dl, byte [esp+0xf]
add esp, 8
cmp dl, al               ; cmp key_fold, last_fold
```

Traced keys in the scratch (`RstrASC(key)` on the left):

| Build | fe id `c` | key(key call) | key(global call) | Order |
|---|---|---|---|---|
| retained two-byte source (`repeat_code` #2, global #33) | 0x10a | 0x080501f3 | 0x080509b3 | global first (99.09%, or 99.32% with the global on the left) |
| one `result` variable (#1) | 0x10a | 0x080501b3 | 0x080509b3 | global first |
| two-byte source, 64044-enumerator enum before `#include "rstring.h"` | 0xfb37 | 0x0805fc20 | 0x080503e0 | **key first, 100.00%** |
| one variable, 64044-enumerator enum before `#include "rstring.h"` | 0xfb37 | 0x0805fbe0 | 0x080503e0 | **key first, 100.00%** |

Window checks with the two-variable source and `RstrASC(repeat_code) == RstrASC(g)` (L = 0xe9,
R = 0x8a9, predicted window 0xf757..0xff16): c = 0xf756 gives 99.09%, 0xf757 gives 100.00%, 0xff16 gives
100.00% and 0xff17 gives 99.09%. With one variable (L = 0xa9) the predicted upper edge 0xff56 holds:
0xff56 gives 100.00% and 0xff57 gives 99.09%. Padding after the includes gives 99.09%. With the global
on the left inside the window, the calls run in native order but the compare becomes `cmp al, dl`
(99.77%). The native source therefore had the key on the left, as the Android and iOS ports do.

Also verified: the separate `repeat_code` byte is not needed. Dropping it and comparing
`RstrASC(result)` gives exactly the same 440 instructions. The `[esp+8]` byte and the `mov [esp+8], bl`
after every assignment are the register allocator's memory home for `result`. That matches the
mobile ports, which have one key variable.

Rejected shapes, all with the calls in the wrong order (compiled, on copies): casts and no-op
arithmetic on either argument or result (`(char)`, `(int)`, `(unsigned char)`, `(short)`, `+0`,
`|0`, `^0`, `&0xff`, `*&x`, `(&x)[0]`, comma), `!(a != b)`, `(char)(a - b) == 0`, callee spelled
`(*f)`/`(&f)`, parameter or global signedness changes, one-byte array or struct wrappers, pointer and
reference borrows, and global definitions in the TU. These are all folded before costing, or they add
the same node to both sides. Wider returns and int parameters change the frame. Inline helpers give
their parameters stack homes, and subtraction changes the frame. A named fold local runs the key call
first, but stores AL to its home instead of the `mov dl, al` temp (98.98%).

## 6. Open questions

- Which declarations the original RShell translation unit had before `RstrASC`. The window is 1984 fe
  ids wide in the two-variable scratch and 2048 in the one-variable scratch. For ids 0x10000..0x1ffff
  the fold is `(id & 0xffff) ^ 1`, so the next window is shifted with its edge ids swapped pairwise.
  VC6's own Win32 and DirectX 5 headers reach 0xb60d; snail-mail matched it with the DirectX 8.1 SDK
  headers plus a counted stand-in.
- Resolved: which declarations consume ids is measured in [frontend-ids.md](frontend-ids.md).
  Parameters are numbered before their function, and a callee's first declaration fixes its id.
- The same wrap affects every tree that contains a call or label operand. It can reorder mixed
  call/non-call operands only when needs and sizes tie, which is rare. It has not been surveyed in
  Crimson.
