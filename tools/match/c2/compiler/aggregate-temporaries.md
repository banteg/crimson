# By-value struct results, copy temporaries and tail merging (C2.DLL 8966)

This note explains when a by-value vector result costs a stack temporary and a copy, and when C2
deletes the copy. It also answers two snail-mail layout questions (§6 and §7) that were traced with
the same tool. Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000).

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

Observed in the globopt-entry dump (after inlining) of a mini scratch and of Worm:

| Source | IL after inlining |
|---|---|
| `Vector3 v = a + b;` | `result.{x,y,z} = ...` in the inlined body, then `blkcopy v <= result`. The hidden return slot is `v` itself. |
| `f(a + b)`, `a + b + c`, `x = a + b` | the return slot is an unnamed `$T` local (class 4, no name), then `blkcopy $T <= result` |
| `return tVector(x, y, z);` | the constructor writes the return slot directly: no `result`, no copy |
| user-declared `tVector(const tVector&)` | every copy above becomes three field copies (`= ty4004` on `^parent+0/4/8` parts) |
| `Vector3 b(&a.x)` (the authored `tVector(float*)` constructor) | three field copies. `&a.x + 4` is folded to the part `a.y` before globopt |
| by-value `tVector` parameter of an inline function | `blkcopy param <= argument`; a temporary argument is constructed in place |
| by-value parameter when the class has a user-declared copy constructor | **not inlined**: the operator and the copy constructor become calls |

Each inline expansion gets its own `result` symbol (`#1123`, `#1132` in the Worm trace), each with its
own alias class (§5). `purge_unreferenced_temps` does not touch them; only CSE plus DCE removes them.

## 3. How the copies disappear

`--preset globopt` of the tool dumps the IL after each globopt sub-pass. For Worm with a
copy-constructor header, `base_plus_right = pos + t` produces `bpr.{x,y,z} = result.{x,y,z}`:

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

Worm, verified: the copy-constructor header (87.80%, frame 0x74) and the stock header with
`vertices[k] = Vector3(&vertex.x)` (87.80%, frame 0x74, the same normalized listing) both reproduce native's
`C → D` copy exactly (`fstp [0x34]; mov eax,[0x8c]; mov ecx,[0x90]; mov [0x38],eax; mov [0x3c],ecx`
in native).

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

### 4.3 What does not keep a copy (Worm controls, all at 0x68 or 0x74)

Named versus unnamed intermediates, `v = v + x`, `+=`, `const&` binding, declare-then-assign,
function-scope declarations, a pointer to the output, by-value `lhs`/`rhs`/both, member `operator+`,
constructor-return `operator+`, `result = lhs; result += rhs`, a user destructor, and
`tVector(float*)` round trips through named pointers. Headers that add a user-declared
`operator=` change unrelated code (695 instructions) and were dropped.

## 5. The Worm vertex (snail-mail `initialize_worm_path_template_pair`)

Native `0x4207e8..0x420958`, candidate frame 0x68 against native 0x80. Four 12-byte objects, named
here by role (stack offsets in the native frame):

| Object | Offsets | What native does |
|---|---|---|
| A = `pos + t` (`result` of the first `operator+`) | 0x70..0x78 | x kept in st(0); y and z stored |
| B | 0x7c..0x84 | `B.y = A.y`, `B.z = A.z` by integer moves; **no B.x**; y and z re-read by the next add |
| C = `B + up` | 0x88..0x90 | x kept in st(0); y and z stored |
| D | 0x34..0x3c | `D.x` from st(0), `D.y/D.z` by integer moves, then the block copy to `vertices[k]` |

The candidate has only A and D (D is the second `result`). The stock header deletes both copies.

- `C → D` is §4.1: field copies whose destination is block-copied. Both the copy-constructor header
  and `vertices[k] = Vector3(&vertex.x)` reproduce it. [Verified]
- `A → B` has the field-copy signature (no x lane). But B's only uses are field reads, and every field
  copy with field-only uses was rewritten away in every variant tried. None of the roughly 300 compiled
  variants (the controls in §4.3, crossed with both headers and both D forms) produced B.
  [Verified negative]

Native therefore needs a field copy `B = A` whose availability dies after the x-lane read and before
the y-lane read, or field reads that CSE cannot rewrite. The first candidate write between those two
reads is `C.x`. Such a kill needs C to overlap A or B, or a memory write in A's or B's alias class
(`avail_transfer_tuple` also clears `g_alias_class_kill_sets2[class]` on writes to memory-resident
parts). In the traced copy-constructor candidate A, C, `up_component` and `vertex` have distinct classes (92, 93, 63
and 67), so no kill happens. Which native construct produced that kill is still open (§8).

A scan of the 785 functions listed in snail-mail STATUS.md found this signature (`mov r,[esp+a];
mov [esp+b],r; …; fld/fadd [esp+b]`) only in Worm, so no exact sibling shows the source form.

Practical guidance for Worm: the retained source should stay. The copy-constructor header and
`Vector3(&vertex.x)` both recover native's D copy but lose score without B (87.80% against 90.64%).
The best frame-correct control found, a by-value `operator+` with `tVector(float*)` operands, reaches
0x80 and 91.38%. It does so by copying `position` into the parameter, which native does not do, so it
matches the frame by coincidence and is not evidence.

## 6. `set_immediate_blend_mode`: which case tails merge

`--preset jumpopt` reports every cross-jump attempt. Rules, verified on this function:

1. **Registers decide identity.** `tuples_equal` 0x1073d365 compares opcode, size, destination and
   source chains (and a call's `+0x20`). The vtbl loads get ecx/edx from the local rotation, which
   follows the IL order. Every case block has an odd number of rotating loads, so blocks alternate
   ecx-first/edx-first in source order. The source order `0, 1, 2, 4, 14, 6, 9/12, 5/8/11/13,
   3/7/15` reproduces native's register pattern in every block.
2. **`cross_jump_into_fallthrough` 0x1073d701 has no size threshold.** Any jump whose code before
   `jmp L_exit` ends like the block that falls into `L_exit` (the last case) is merged, even for
   one matching tuple. That is how cases 2 and 14 join the 3/7/15 tail at `push 0x13`, in native and in
   the candidate. Short merges (case 0, 9/12) are later undone: block mover loop 2 copies the ≤20-byte
   tail back.
3. **`cross_jump_label_refs` 0x1073d211** takes the references of `L_exit` in list order (newest
   jump first). Each reference in turn is an anchor tried against every later one with
   `cross_jump_pair` 0x1071dfc6. Word counters at `jmp+0x12` are cleared on entry.
4. **Profitability of `cross_jump_pair` under /Ot** (disassembly 0x1071e15c..0x1071e20f):
   - If the first unmatched tuple on either side is an unconditional `jmp` or `ret`, the whole block
     is covered and it merges at any size. This is why identical cases 1 and 4 always merge.
   - Otherwise it adds the encoded lengths of the matched real tuples, starting at the first matched
     tuple, and **stops as soon as the sum reaches 20**. It then adds `max(counter(J1), counter(J2))`
     and merges only if the total is **> 20**. A merge sets the anchor's counter to
     `max(20, total + counter(J2))`.
   - So a common tail of exactly 20 bytes, or any tail whose running sum lands exactly on 20, is
     never merged when the counters are zero. Case 6 against 5/8/11/13 is such a tail: `push 0x13` 2,
     `push eax` 1, `call [r+0xc8]` 6, `mov eax,[dev]` 5, `mov edx,[eax]` 2, `push 2` 2,
     `push 0x14` 2 → 20.
   - Control: changing the last value in both blocks to `0x102` (a 5-byte push) makes the running sum
     21, and case 6 then merges at exactly native's point (`mov eax,[dev]; push 2; mov ecx,[eax];
     jmp L144`). [Verified]

Native merges cases 2 and 14 into 3/7/15 and case 6 into 5/8/11/13, and keeps cases 1 and 4 as two
full blocks. With uniform `switch`/`return` source this cannot happen:

- every one of the 2,880 source orders that give native's registers (5! × 4! orders with ecx-first
  blocks at even positions) was compiled. None reproduces native; the best is native's own order at
  77.70% (127 instructions), because 1 and 4 merge and 6 does not. [Verified]
- `break` instead of `return`, returning the call result, an explicit `default`/`case 10`, and
  case-selector arithmetic for the values (`blend_mode + 4`, folded by the switch branch facts) are
  byte-identical. [Verified]
- Loading the device through a *different symbol* in case 4 (same address) keeps 1 and 4 apart and
  reproduces native's whole jump table, except the case-6 merge (86.98%, 146 instructions).
  [Verified; the extra symbol is not evidenced and was only a control]

So in native, cases 1 and 4 differ in IL at jump-optimizer time, and the case-6 tail is longer than 20
bytes then, or its anchor had a counter. Neither difference shows in the final bytes. See §8.

## 7. `update_subgoldy` ghost z: why `records[0]` comes second, and the source that fixes it

The C1XX reader emits `if (!anchor || (cursor = …) == 0) A; else B;` in source order: T1
`jcc(anchor==0) → LA`, T2 `cursor = …; jcc(cursor!=0) → LB`, A, `jmp J`, B, J. (Trace:
`branch_trace.py` phase `read`.)

`cfg_build_edges` walks blocks in order. For each block it prepends the fall-through edge, then one
edge per reference to the block's label. So:

- T1's successors are [A, T2]: the A edge is made when block A is processed, after T2.
- T2's successors are [B, A].

The DFS in `cfg_dfs_rpo` visits the list head first. It reaches A from T1 before T2, so A finishes
early and lands after B. The resulting order is T1, T2, B, A, J; T2's branch is inverted to `je A` and
falls into B. That is the candidate. Every one-copy spelling that keeps A before T2 in source gives
the same lists.

Native (`je A; …; jne B; A; jmp J; B`) needs T1's successor list to be [T2, A] and T2's to be
[B, A]. Then DFS goes T1 → T2 → B → J, then A. That needs A **before** T2 in the reader IL, with T2
reaching A by a **backward** jump, which in C means a backward `goto`:

```cpp
float ghost_z;
if (!anchor) {
first_record:
    ghost_z = MathType16to32(
        (unsigned short)TIME_TRIAL_RECORD_AT(record_block)->run_records[0].delta_z, 32.0f);
} else {
    cursor = TIME_TRIAL_RECORD_AT(record_block)->replay_start_cursor - anchor + cursor;
    if (cursor == 0)
        goto first_record;
    ghost_z = MathType16to32(
                  (unsigned short)TIME_TRIAL_RECORD_AT(record_block)->run_records[cursor].delta_z,
                  32.0f)
            + g_subgoldy_ghost_z;
}
```

Verified: reader IL T1 → `LA_else`, A (`first_record`), `jmp J`, T2 (`jcc(cursor!=0) → B; jmp
first_record`), B. After `optimize_flow_graph_initial` the order is T1, T2, A, B, J, and every branch
and label in the block equals native's (`je L1c2c`, `jne L1c43`, `jmp L1c62`). The block mover does not
touch it.

Spelling the condition as an embedded assignment, `else if`, `anchor == 0` or `!cursor` compiles to
the same object. A forward `goto` or a label alone is byte-neutral elsewhere.

Cost, on a copy of the current scratch: structural 99.28% → **99.55%** (changed 14/16 → 8/11), raw
99.28% → 96.06%, 2,089 → 2,090 instructions. The drop comes from two things outside the branch
structure:

- the local rotation is one step behind native from `records[0]` onwards (`rotation.py`: native
  cursor minus ours goes +0 → +1 at the `records[0]` temporary and back to +0 at line 1031);
- the two completion clamps before it now keep `speed` in `[esp+0x10]` (`fst`) instead of re-reading
  `velocity.z`.

Why a backward goto changes those was not traced.

## 8. Open questions

- **Worm B.** Which construct makes `B = A` (field copies) survive with only the x lane rewritten?
  The trace needs a kill between the x and y reads (overlap or alias class) or unrewritable reads.
  Next step: trace the alias classes (`@a` in the tool) of a candidate that forces a shared class,
  for example two operator results of the same inline expansion bound through one reference.
- **blend case 6 / cases 1 and 4.** What IL difference, invisible after scheduling and the late
  passes, separates 1 from 4 and lengthens the 6 ∥ 5/8/11/13 tail past 20 bytes?
  Candidates: a tuple that `late_register_value_cse` 0x10736b27 or the mover later deletes (a
  redundant device load would add 5 bytes and change the rotation), or a different device
  expression per case.
- The x-lane forwarding of surviving field copies happens after globopt (the IL still has
  `D.x = C.x` at `final`). The lowering copy propagation `propagate_lowered_copy` 0x1072a632 and the
  allocator's `forward_substitute_single_def_ranges` 0x107306c1 are the candidates.
- **Ghost z.** The rotation step and the `speed` spill that the backward goto introduces.

## 9. Tool

```sh
# globopt stages for a line range (snail-mail scratch, run from the snail-mail checkout)
uv run python ../crimson/scripts/c2/il_stage_trace.py --snail <scratch> --out <new-dir> --lines 189-191
# every tail-merge attempt
uv run python ../crimson/scripts/c2/il_stage_trace.py --snail <scratch> --out <new-dir> --preset jumpopt
```

- `--match-root` compiles against another `tools/match` root, for example one with an edited
  `include/vector3.h`.
- `--reuse <dir>` re-renders a trace without compiling.
- Crimson scratches work without `--snail`.
- Crimson's `branch_trace.py` currently raises `TypeError` in `lineage()` on `update_subgoldy` (a
  `repair.jmp.ret` event with no new jump). Its trace data is still written and readable.
