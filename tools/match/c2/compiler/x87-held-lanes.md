# Two vector lanes held on the x87 stack (C2.DLL 8966)

This note explains the native x87 shape where both lanes of a 2D vector are computed before either is
stored:

```
fld  [frame_dt]
fld  st(0)
fmul [edi+0x20]        ; y = dt * move_dy, computed first
fxch st(0), st(1)
fmul [edi+0x1c]        ; x = dt * move_dx
<argument pushes>      ; scheduler fill, see §5
fstp [vec.x]
fstp [vec.y]
```

It also explains when a source spelling reproduces it. Addresses are virtual addresses in the pinned
C2.DLL (image base 0x10700000). "Verified" means confirmed by a preserving compiler trace
([`scripts/c2/fwdprop_trace.py`](../../../../scripts/c2/fwdprop_trace.py),
[`scripts/c2/sched_trace.py`](../../../../scripts/c2/sched_trace.py)) or by compiles. "Read" means
static reading only. "Inferred" means the rule fits every compile below but the C2 code for it was
not traced.

Short version:

1. The shape comes from an **inline function with the two lane values as by-value parameters** that
   stores lane x, then lane y, into a vector. Parameters are evaluated right to left, so both
   parameter definitions come before both stores.
2. Forward propagation moves the x parameter's tree next to the x store, with a FROUND. It tries the
   same for y, but the **x store lies between y's definition and its use**. If that store may alias
   memory that y's tree reads, the move is refused and y stays where C1 put it. Then y is computed
   first and held on the stack. [Verified]
3. The x store may alias y's reads only when **all** of these hold [verified by compiles, mechanism
   inferred]:
   - the vector is an address-taken local (its address reaches a call) declared at **function
     scope**. A local declared in a nested `{}` block does not qualify, and neither does a helper's
     local or an operator's return temporary;
   - y reads memory **through a pointer that the function computes or loads**, such as
     `player = &player_state_table[index]`, a pointer read from a global, or an inline reference
     parameter bound to one. A read through an incoming parameter pointer, or a direct global read,
     is not aliased.
4. `fld dt; fld st(0)` needs the scale factor to be **one by-value inline parameter used by both
   lanes**. A reload of `move_dy` (native `fstp [edi+0x20]` ... `fmul [edi+0x20]`) needs the lanes
   to be **read through a reference** (`m.y`), not as `player->move_dy`.

## 1. Mechanism

`forward_propagate_definitions` 0x10711afa (see [x87-scheduling.md](x87-scheduling.md) §3) handles a
variable with one definition and one use. For each candidate pair it clones the definition's tree
(`clone_tuple_for_propagation` 0x107428f6). It then calls `range_free_of_conflicts` 0x10742ad4 up to
twice:

| Call site | Range checked | Purpose |
|---|---|---|
| 0x10712713 | the use's own root tree, with the propagated symbol removed | the use must not clobber the tree's inputs |
| 0x107125d8 | every tuple after the definition up to the use (skipped when the definition is the tuple just before the use) | nothing in between may write what the tree reads |

`range_free_of_conflicts(first /*ecx*/, last /*edx, the range ends at last->next*/, tree /*stack*/)`
returns 0 when, for any tuple in the range:

- a destination operand may alias a source or destination of the tree, or
- a source operand may alias a destination of the tree.

The test is `operands_may_alias` 0x10702771 (fastcall, ecx and edx). [Read and verified]

On success, `move_expression_tree_before` 0x1071d548 moves the tree, and 0x10712643 inserts a FROUND
for a float value. On failure nothing moves. The definition stays a temp with one use, the
x87 live-range allocator keeps it on the stack, and it is stored at its original use.

For a direct local such as `vec.x` against an indirect read `[player+0x20]`, the alias test is
`symbol_in_alias_class(vec, class of the indirect)`. So the question is which locals are members of
the alias class of that pointer dereference. The class is built by `compute_alias_classes`
0x10718eaf. `prune_unexposed_alias_members` 0x1071a38e drops every member whose address-taken flag
(symbol byte +5, bit 2) is clear. [Read]

### What the traces show

`fwdprop_trace.py` on the player_update variant S1 (below), definition of the y parameter:

```
range_between: CONFLICT
  def: y_param = frame_dt * [player + 0x20]      (kind 6, alias class 0x154)
  use: movement_input.y = y_param
  alias: [2:movement_input.x]  ~  [6: class 0x154]
```

The x definition sits right before its store, so only `range_use` runs for it, and it passes. That
gives one FROUND per site (x lane). In the sched trace for the same site, the order before scheduling
is `fld dt; fld st(0); fmul [edi+0x20]; fxch; fmul [edi+0x1c]; FROUND; fstp x; fstp y`. [Verified]

For their `pu_helper_c.cpp` (`player_move_vec2_t delta = frame_dt * player->movement;` inside an
inline helper), the y parameter's use is a store to the **operator's return temporary**, which is
not address-taken. The x store in between does not alias class 4 (`v`), so both lanes propagate:
`fmul [dx]; fstp x; fmul [dy]; fstp y`. The temporary is then copied into `delta`. [Verified]

## 2. Which lane is held, and argument order

For an inline `f(v, a, b)` whose body stores `A` and then `B`:

- The definitions are emitted last parameter first (C1 evaluates arguments right to left).
- Then come the body's stores.
- The lane stored **first** always propagates, since nothing sits between its definition and its
  store except the other definition, which writes no memory.
- The lane stored **second** is held if the first store aliases its operands.
- A held lane is computed before the propagated one, so the lane stored second is computed first.

| Micro | Setter | Prediction (written first) | Observed |
|---|---|---|---|
| K9 | `set2(&d, x, y)`, body `v->x = x; v->y = y` | y first, x, fstp x, fstp y | ✓ |
| N1 | `set_yx(&d, y, x)`, body `v->x = x; v->y = y` | same as K9: parameter order is irrelevant | ✓ |
| N2 | `set2(&d, x, y)`, body `v->y = y; v->x = x` | x held and first: `fmul dx; fxch; fmul dt; fstp y; fstp x` | ✓ |

Native's order (y computed first, x stored first) therefore means that **x is stored before y**.

## 3. Destination and pointer rules

Only a real escape (the local's address reaching a call) makes a local visible to alias analysis.
Inline pointer or reference parameters, a body `float *p = &x`, or `float &r = x` do not
([x87-memory-values.md](x87-memory-values.md)).

Every micro below is `player_update` compiled with the scratch flags. `d` is a `vec2f_t` passed to
`player_apply_move_with_spawn_avoidance`, the lanes are `frame_dt * p->move_dx/dy`, and the builder
is an inline setter unless stated otherwise.

| Micro | Variable | Result |
|---|---|---|
| B, C, D, E, H1-H5 | `p` is a pointer **parameter** (setter, ctor, `&V(...)` temp, const-ref wrapper, globals, param+local) | not held |
| A2, B2 | same, with `touch(&d)` escaping first | not held |
| K8 | pointer parameter | not held |
| K9, K2, K1 | `P *player = &player_table[idx]` | **held** |
| K6 | `P *player = player_ptr` (a pointer read from a global) | **held** |
| K10 | `&player_table[2]` (folds to direct global addresses) | not held |
| K7 | y reads only globals | not held |
| K5 | `d` never address-taken (`by_value(d.x, d.y)`) | not held |
| L4 | function-scope `d`, setter inside an `if` | **held** |
| L5 | `d` declared inside the `if` block, pointer defined outside it | not held |
| L6 | `d` and the pointer both declared inside the same block | **held** |
| K11 | function-scope `V d(a, b)` (ctor `: x(a), y(b)`) | **held** |
| K16, K15 | function-scope `M d = s * v;`, `DV d = s * v;` (init-list or D3DX body-assignment ctor; the return slot is constructed in place) | **held**, exact native shape |
| L2 | the same declaration wrapped in `{ }` | not held |
| K17, K18 | the same declaration inside an inline helper | not held (the return temp is copied into the helper's local) |
| K12, M2 | assignment `d = s * v;`, `d = DV(a, b);` to an existing local | not held (goes through a temp) |
| M1 | `d = v; d *= s;` (D3DX `operator*=`) | not held: copy through integer registers, then per-lane `fmul st(1); fstp` |

The scope rule (L4, L5, L6) is inferred. The likely place is the per-block exposure sets in
`build_block_alias_sets` 0x1071954a / `compute_alias_points_to` 0x10719707: the entry block
marks every numbered reference exposed. That code was not traced.

## 4. dt reuse and the move_dy reload

| Spelling of the lanes | x87 at the site |
|---|---|
| `set(&v, frame_dt * player->move_dx, frame_dt * player->move_dy)` | `fst [edi+0x20]` (move_dy forwarded from st0); `fmul [frame_dt]`; `fld [frame_dt]; fmul [edi+0x1c]` |
| same, with `const float movement_dt = frame_dt;` | `mov edx,[frame_dt]; mov [esp+0x20],edx; fmul [esp+0x20]; fld [esp+0x20]; ...` |
| `scaled(&v, frame_dt, player->movement)` with `scaled(v, s, const vec2f_t &m) { set(v, s * m.x, s * m.y); }` | `fstp [edi+0x20]; fld [frame_dt]; fld st(0); fmul [edi+0x20]; fxch; fmul [edi+0x1c]` — native |

A parameter used by both lanes is an inline copy with two uses, so it is never forward-propagated,
and it is kept on the stack (`fld; fld st(0)`). The reload of `move_dy` through `m` versus the
st(0) forwarding through `player->move_dy` is observed, not traced.

## 5. Where the fstp pair lands

The x87 order is fixed before scheduling ([x87-scheduling.md](x87-scheduling.md) §1). The scheduler
only places the integer argument pushes around it. `sched_trace.py` on the `scaled` variant, native
L1188-style site (the call in the same window):

```
seq 1 fld dt   2 fld st0   3 fmul [0x20]   4 fxch   5 fmul [0x1c]   6 FROUND   7 fstp x   8 fstp y
seq 9 lea &vec  10 push  11 push esi  12 mov ecx,[idx]  13 push  14 call
emitted: ... fmul [0x1c] (cyc 4); mov ecx (5); lea (6); push, push (7-8); FROUND (9); fstp x (10); push ecx (11); fstp y (12); call
```

The FROUND inherits the `fmul`'s 3-cycle latency, and `fstp x` depends on it, so ready integer
tuples fill cycles 5-8 ahead of the pair. How many pushes land before, between or after the pair
depends on what else is in the window and on its priorities. It does not depend on the source order
of the stores:

- In native's tail-merged arms (the `jmp L186c` / `jmp L15a7` sites), `lea/push &vec; push pos` sit far up inside the
  `fcos`/`fsin` code and only `mov r,[idx]; push r` precedes the pair.
- At the L1188 fall-through site, all three pushes follow the pair.

Native's placement needs the pushes in the same window as the arm's trigonometry, so the call must
be in the same branch as the vector build. [Verified for our windows. Native windows inferred from
the listing]

## 6. player_update results

The work copy is `tools/match/scratches/player_update` at 64.50%. It has 10 plain
`v.x = dt * move_dx; v.y = dt * move_dy;` pairs and one call after each if/else group. Native builds
the vector 11 times, always in the same stack slot.

| Variant | Score | Native-shape sites emitted |
|---|---|---|
| canonical | 64.50% | 0 |
| S1: `pu_move_set(&v, d * move_dx, d * move_dy)` at all 10 sites, `v` = `movement_input` / `move_delta` (function scope) | **66.31%** | y first at every site; dt not reused, move_dy forwarded |
| S1_block: the same, but into a `{ player_update_vec2_t block_vec; ... v = block_vec; }` (negative control) | 57.69% | x first at every site, as predicted |
| scaled: `pu_move_scaled(&v, d, player->movement)` at all 10 sites | 63.87% | the 4 emitted sites are exact. C2 cross-jumps the now-identical arms (6 builds disappear), and native keeps them |
| best per-site mix of plain / set / scaled (coordinate search) | 66.88% | 2 exact |
| pu_helper_c (other session) | 58.71% | 0. The helper's `delta` adds a frame slot (`sub esp,0x4c`) and propagates through the return temp |
| pu_helper_c with `player_update_apply_move(player, pos, &movement_input)` and `pu_move_scaled(delta, frame_dt, player->movement)` in the helper | 64.38% | all emitted sites exact, frame back to 0x48. The pushes still sink into the shared tail |

Conclusion for the source: build the vector with a two-lane inline setter (x stored first) into a
**function-scope** address-taken local, with the scale passed once by value and the lanes read
through a `const vec2f_t &`. The remaining player_update gap is block structure (which arms native
keeps separate), not x87 order.

## Tool

```sh
uv run python scripts/c2/fwdprop_trace.py <scratch-dir> --out <new-dir> [--lines A-B]
uv run python scripts/c2/fwdprop_trace.py --report-only <trace-dir> [--lines A-B]
```

For every forward-propagation range check, the tool prints the definition, the use, the verdict,
and the operand pairs that `operands_may_alias` reported. It uses the preserving `c2-trace` harness
with hooks at 0x10712713, 0x107125d8 and the three `operands_may_alias` calls in
`range_free_of_conflicts` (0x10742b0a, 0x10742b47, 0x10742b65). `ln` is C1's line record, which is
near the call site for inlined code. player_update takes about 10 s.

## Corrections to other notes

- [x87-scheduling.md](x87-scheduling.md) §3 and §6 say the store through `v` in an inline setter
  blocks propagating `y`. That holds only under the conditions of §3 here: an address-taken
  function-scope destination, and a y tree that reads through a pointer that is not a parameter. With a
  parameter pointer, or a block-scoped or temporary destination, both lanes propagate.
- The same survey says the setter site "shares CSE with its neighbours". Converting **all** vector
  sites of one kind raises the function (64.50% to 66.31%). The earlier drop came from changing a
  single site.

## Open questions

- Where C2 excludes nested-scope locals from a pointer's alias class (§3 L4-L6). Candidates are
  `build_block_alias_sets` and `compute_alias_points_to`.
- Why a lane read through a reference (`m.y`) reloads the just-stored `move_dy`, while
  `player->move_dy` is forwarded from st(0).
- Answered in [arm-local-builds.md](arm-local-builds.md): the /Ot local register rotation gives each arm's build different registers, so cross-jumping stops at the push unless the rotation distance is a multiple of 3. Original question: why native keeps the 11 arms separate where the `scaled` form lets C2 cross-jump them. The likely
  cause is per-arm push registers after allocation. See [layout.md](layout.md).
