# By-value struct results, copy temporaries and tail merging (C2.DLL 8966)

This note explains when a by-value vector result costs a stack temporary and a copy, and when C2
deletes the copy. It also covers two layout rules traced with the same tool: switch-tail
cross-jumping (§6) and the block order of a short-circuit `if` (§7). Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000).

Evidence labels:

- **Verified** means seen in a preserving trace
  ([`scripts/c2/il_stage_trace.py`](../../../../scripts/c2/il_stage_trace.py)) or proven by compiles
  with the named variant.
- **Read** means read in Binary Ninja only.
- **Inferred** means the rule fits every compile but the C2 code for it was not traced.

## 1. Short version

1. VC6 has no NRVO. An inline `tVector operator+(...) { tVector result; ...; return result; }` always
   has a real `result` local per expansion, and `return result;` copies it into the hidden return
   slot. [Verified]
2. The copy's IL form depends on the class, not on the operator:
   - a trivially copyable class gives one **block copy** (IL 0x16b, 12 bytes);
   - a user-declared copy constructor, or `tVector(float*)`, or explicit `a.x = b.x` statements give
     three **field copies** (IL 0x15b on the float parts). [Verified]
3. CSE phase 1 (`cse_replace_operands` 0x107098ea → `find_available_copy_source` 0x10709b5a)
   rewrites every later read of the copy's destination into a read of its source. It works for
   block and field copies, into field reads, and it follows chains. DCE then deletes the copy, and
   the destination never gets a stack slot. This is why most operator temporaries cost nothing.
   [Verified]
4. A copy survives in two cases:
   - **its destination is used as a whole aggregate** (the source of a later block copy). Field
     copies then stay as field copies; block copies stay as block copies. [Verified]
   - **its availability is killed** before a later read. A write to any part that overlaps the
     destination (or the source) kills a block copy's availability for all lanes. The lanes read
     before the write are still rewritten. [Verified]
5. What survives looks different in the final code:
   - a surviving **block copy** is lowered to `memcpy` (`lower_block_copy` 0x10756732) and becomes
     three dword `mov`s. The x lane is copied too, from memory. [Verified]
   - surviving **field copies** keep the first lane on the x87 stack: the x result is stored
     straight into the destination (or never stored), and only the y and z lanes go through
     `mov r,[src]; mov [dst],r`. [Verified; which late pass does the x-lane forwarding was not traced]
6. So the signature "x lane not stored, y and z copied by integer moves" in native code means
   field copies, never a block copy.

## 2. How C1XX materializes a by-value result

Observed in the globopt-entry dump (after inlining) of a mini scratch and of a real vector-heavy
function (Snail Mail's Worm path builder):

| Source | IL after inlining |
|---|---|
| `Vector3 v = a + b;` | `result.{x,y,z} = ...` in the inlined body, then `blkcopy v <= result`. The hidden return slot is `v` itself. |
| `f(a + b)`, `a + b + c`, `x = a + b` | the return slot is an unnamed `$T` local (class 4, no name), then `blkcopy $T <= result` |
| `return tVector(x, y, z);` | the constructor writes the return slot directly: no `result`, no copy |
| user-declared `tVector(const tVector&)` | every copy above becomes three field copies (`= ty4004` on `^parent+0/4/8` parts) |
| `Vector3 b(&a.x)` (the authored `tVector(float*)` constructor) | three field copies. `&a.x + 4` is folded to the part `a.y` before globopt |
| by-value `tVector` parameter of an inline function | `blkcopy param <= argument`; a temporary argument is constructed in place |
| by-value parameter when the class has a user-declared copy constructor | **not inlined**: the operator and the copy constructor become calls |

Each inline expansion gets its own `result` symbol, each with its own alias class (§5).
`purge_unreferenced_temps` does not touch them; only CSE plus DCE removes them.

## 3. How the copies disappear

`--preset globopt` of the tool dumps the IL after each globopt sub-pass. With a copy-constructor
header, `base_plus_right = pos + t` produces `bpr.{x,y,z} = result.{x,y,z}`:

- `canon`..`vn`: the three field copies are still there, and `vertex = bpr + up` reads `bpr` parts.
- `cse1`: the reads of `bpr.x/y/z` are rewritten to `result.x/y/z`.
- `dce1`: the three copies are deleted (their destination is dead).

With the stock trivial copy, the same happens to `blkcopy bpr <= result`: the field reads of `bpr`
are rewritten through the parent's copy list (`find_available_copy_source` walks from a part to its
parent at `*(sym+8)` and checks the parent's copy list `+0x3c`), and the block copy dies.

Two corrections to the symbol comments follow from this:

- `find_available_copy_source` does propagate **aggregate copies** into field reads. What it refuses is
  aggregate *constants*.
- Chains are followed. `Vector3 b(&a.x); Vector3 v = b + up;` with a by-value `lhs` (`param = b`,
  `b = a`) ends with reads of `a`; neither `b` nor the parameter keeps a slot.

## 4. What keeps a copy

### 4.1 Aggregate use of the destination

`vertices[i] = vertex;` reads `vertex` as a whole (IL 0x16b source). A field read can be rewritten, but
an aggregate read cannot be rewritten into three different field sources. So:

- trivial copy: `vertex = result` (block) → CSE rewrites `vertices[i] = vertex` into
  `vertices[i] = result` (aggregate to aggregate) and `vertex` dies. **No temporary.**
- copy constructor or `tVector(float*)`: `vertex.{x,y,z} = result.{x,y,z}` (fields), and
  `vertices[i] = vertex` keeps all three copies. **One temporary.** In the final code the x lane is
  stored straight into `vertex.x` from st(0) and the y and z lanes are copied with integer moves:

```
fstp [result.y]  ...  fstp [result.z]
fstp [vertex.x]                 ; x never stored in result
mov  eax,[result.y]  mov ecx,[result.z]
mov  [vertex.y],eax  mov [vertex.z],ecx
```

A copy-constructor header and the stock header with `vertices[k] = Vector3(&vertex.x)` both give
this shape, with the same listing. [Verified on Snail Mail's Worm path builder, where it matches
native's copy exactly]

### 4.2 A write that kills availability

`avail_transfer_tuple` 0x1070a0d8 (read, and verified by the case below): writing a symbol clears
its kill set `+0x44` and the kill sets of every part of the same parent that overlaps it
(`sub_10750fe8`). A block copy is recorded on the parent, so a write to *any* field of the
destination kills it.

```cpp
Vector3 vertex = s->pos + t;   // blkcopy vertex <= result
vertex += up;                   // vertex.x = vertex.x + up.x; vertex.y = ...
```

Trace (`--lines`): the `vertex.x` read becomes `result.x`, then the `vertex.x` write kills the copy,
and the `vertex.y`/`vertex.z` reads stay. The block copy survives and is lowered to three dword moves,
**x lane included**, and the x store is dead but still emitted.

Field copies are recorded per part, so an in-place write to `b.x` does not kill `b.y = a.y`.

`avail_transfer_tuple` also clears `g_alias_class_kill_sets2[class]` on writes to memory-resident
parts, so a memory write in the copy's alias class kills it too.

### 4.3 What does not keep a copy

None of these kept a copy whose destination has only field reads (controls on one function, each
compiled with both headers):

Named versus unnamed intermediates, `v = v + x`, `+=`, `const&` binding, declare-then-assign,
function-scope declarations, a pointer to the output, by-value `lhs`/`rhs`/both, member `operator+`,
constructor-return `operator+`, `result = lhs; result += rhs`, a user destructor, and
`tVector(float*)` round trips through named pointers.

## 5. A field copy that survives only in part

Native code can show a copy with the field-copy signature (no x lane; y and z by integer moves) whose
destination has **only field reads**, which are then re-read from the copy:

```
mov r,[esp+a]; mov [esp+b],r; …; fld/fadd [esp+b]
```

By §3 and §4 such a copy is rewritten away unless its availability dies between the x-lane read and
the y-lane read, or its field reads cannot be rewritten. A kill there needs a write that overlaps the
source or the destination, or a memory write in one of their alias classes (§4.2). Each inline
`result` has its own class, so separate operator results do not kill each other.

No source form that produces this has been found. About 300 variants (the §4.3 controls crossed with
both headers) all rewrote the copy away. [Verified negative, on Snail Mail's Worm path builder]

## 6. Switch tails: which case tails merge

`--preset jumpopt` reports every cross-jump attempt. Rules (verified on Snail Mail's
set_immediate_blend_mode, a switch whose cases each make one or two device vtable calls):

1. **Registers decide identity.** `tuples_equal` 0x1073d365 compares opcode, size, destination and
   source chains (and a call's `+0x20`). Loads that get their register from the local rotation
   ([regalloc.md](regalloc.md) §4) follow the IL order. A case block with an odd number of rotating
   loads flips the next block between ecx-first and edx-first, so identical case bodies can get
   different registers depending on their source position, and the case order in source decides
   which tails can merge.
2. **`cross_jump_into_fallthrough` 0x1073d701 has no size threshold.** Any jump whose code before
   `jmp L_exit` ends like the block that falls into `L_exit` (the last case) is merged, even for
   one matching tuple. Short merges are later undone: block mover loop 2 copies the ≤20-byte tail
   back.
3. **`cross_jump_label_refs` 0x1073d211** takes the references of `L_exit` in list order (newest
   jump first). Each reference in turn is an anchor tried against every later one with
   `cross_jump_pair` 0x1071dfc6. Word counters at `jmp+0x12` are cleared on entry.
4. **Profitability of `cross_jump_pair` under /Ot** (disassembly 0x1071e15c..0x1071e20f):
   - If the first unmatched tuple on either side is an unconditional `jmp` or `ret`, the whole block
     is covered and it merges at any size. Two identical case blocks therefore always merge.
   - Otherwise it adds the encoded lengths of the matched real tuples, starting at the first matched
     tuple, and **stops as soon as the sum reaches 20**. It then adds `max(counter(J1), counter(J2))`
     and merges only if the total is **> 20**. A merge sets the anchor's counter to
     `max(20, total + counter(J2))`.
   - So a common tail of exactly 20 bytes, or any tail whose running sum lands exactly on 20, is
     never merged when the counters are zero. Widening one matched instruction (a `push` of a value
     that needs 5 bytes instead of 2) makes such a tail merge. [Verified]

So when native merges a tail that the candidate does not, or keeps two identical case blocks apart,
the IL at jump-optimizer time differed: a tuple that a later pass deletes, or a different operand
symbol. Neither shows in the final bytes. `break` versus `return`, returning the call result, an
explicit `default`, and case-selector arithmetic folded by the switch branch facts do not change the
IL here. [Verified]

## 7. Short-circuit `if`: why the first arm can land last

The C1XX reader emits `if (!a || (c = …) == 0) A; else B;` in source order: T1
`jcc(a==0) → LA`, T2 `c = …; jcc(c!=0) → LB`, A, `jmp J`, B, J. (Trace: `branch_trace.py` phase
`read`.)

`cfg_build_edges` walks blocks in order. For each block it prepends the fall-through edge, then one
edge per reference to the block's label. So:

- T1's successors are [A, T2]: the A edge is made when block A is processed, after T2.
- T2's successors are [B, A].

The DFS in `cfg_dfs_rpo` visits the list head first. It reaches A from T1 before T2, so A finishes
early and lands after B. The resulting order is T1, T2, B, A, J; T2's branch is inverted to `je A` and
falls into B. Every one-copy spelling that keeps A before T2 in source gives the same lists.

The order `je A; …; jne B; A; jmp J; B` needs T1's successor list to be [T2, A] and T2's to be
[B, A]. Then DFS goes T1 → T2 → B → J, then A. That needs A **before** T2 in the reader IL, with T2
reaching A by a **backward** jump, which in C means a backward `goto`:

```cpp
if (!a) {
first:
    A;
} else {
    c = …;
    if (c == 0)
        goto first;
    B;
}
```

Verified: reader IL T1 → `LA_else`, A (`first`), `jmp J`, T2 (`jcc(c!=0) → B; jmp first`), B. After
`optimize_flow_graph_initial` the order is T1, T2, A, B, J. The block mover does not touch it.

Spelling the condition as an embedded assignment, `else if`, `a == 0` or `!c` compiles to the same
object. A forward `goto` or a label alone is byte-neutral elsewhere. The backward goto did change code
outside the branch in the traced function (a local rotation step and an x87 spill); why was not
traced.

## 8. Open questions

- **Partial field copies (§5).** Which construct makes a field copy survive with only the x lane
  rewritten? The trace needs a kill between the x and y reads (overlap or alias class) or
  unrewritable reads. Next step: trace the alias classes (`@a` in the tool) of a candidate that forces
  a shared class, for example two operator results of the same inline expansion bound through one
  reference.
- **Hidden case-tail differences (§6).** Candidates for an IL difference that is invisible after
  scheduling and the late passes: a tuple that `late_register_value_cse` 0x10736b27 or the mover later
  deletes (a redundant load would add bytes and change the rotation), or a different operand
  expression per case.
- The x-lane forwarding of surviving field copies happens after globopt (the IL still has
  `D.x = C.x` at `final`). The lowering copy propagation `propagate_lowered_copy` 0x1072a632 and the
  allocator's `forward_substitute_single_def_ranges` 0x107306c1 are the candidates.
- **Backward goto (§7).** Why it moves the local rotation and x87 spills outside the branch.

## 9. Tool

```sh
# globopt stages for a line range
uv run python scripts/c2/il_stage_trace.py <scratch> --out <new-dir> --lines 189-191
# every tail-merge attempt
uv run python scripts/c2/il_stage_trace.py <scratch> --out <new-dir> --preset jumpopt
```

- `--reuse <dir>` re-renders a trace without compiling.
- `branch_trace.py` can raise `TypeError` in `lineage()` on a `repair.jmp.ret` event with no new
  jump. Its trace data is still written and readable.
