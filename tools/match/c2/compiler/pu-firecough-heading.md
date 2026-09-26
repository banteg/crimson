# Fire Cough heading: what stops forward propagation of a float def (C2.DLL 8966)

This note decodes when `forward_propagate_definitions` 0x10711afa leaves a single-use float definition
where C1 put it. The worked case is the Fire Cough projectile heading in `player_update`
(native 0x413b7f..0x413bc2). It also gives a source spelling that computes the heading early and
spills it the way native does, and lists what that spelling still does not fix. Addresses are
virtual addresses in the pinned C2.DLL (image base 0x10700000), `/O2 /GB`.

"Verified" means confirmed by a preserving trace (`scripts/c2/fwdprop_trace.py`,
`scripts/c2/sched_trace.py`) or by compiles. "Read" means static reading only. "Inferred" means the
rule fits every compile below, but the C2 code for it was not traced.

Short version:

1. `propagation_def_use_eligible` 0x10711786 rejects only two things: a use that does not come after
   the def inside the same block, and a cross-block pair where the def block does not dominate the
   use block or the blocks are in different innermost loops. Everything else that refuses a
   propagation is in the surrounding walk or in the commit loop (§1). [Read, verified for the base]
2. The canonical heading passes every check. Both range checks are free, and C2 moves the tree to the
   argument (`0x1071273e -> 0x1071d548`). [Verified]
3. Storing the heading into the vec2_sub output vector (`scratch_pos.x`, an address-taken
   function-scope aggregate) keeps it at its statement. It is stored to that vector's slot and pushed
   with `mov eax,[slot]; push eax`, as in native. Native's heading home is also the vec2_sub
   destination (frame 0x18). [Verified]
4. Two native details are not reproduced. The returned-vector loads come out Y then X with no
   `fxch`, because the atan2f parameters now propagate. The `fsub` comes before the argument pushes,
   because the 81-node scheduling window ends right after `fpatan`. [Verified]
5. The whole-function score also moves through two side effects: class-3 temp ids shift, which flips
   the hash-ordered move-speed products, and label drift. Compare with labels masked (§5).

## 1. Every refusal in 0x10711afa

The walk visits the tuples of each block in RPO. Defs and uses are tracked per **parent symbol**
(+0x4c pending defs, +0x50 uses, +0x48 registered pairs). Only symbols in
`g_fwdprop_candidate_syms` 0x1079f0f4 take part. `globopt_canonicalize_tuples` fills that set with the
parent of every direct (kind 2) destination of a 0x15b assign whose root symbol has a front-end
symbol (0x107139ec..0x10713a13). [Read]

### 1.1 Registration, at a direct use (0x10711da9..0x10711f37) [read]

A (def, use) pair is registered, and the def's status +0x13 set to 0xa, only if all of these hold:

| # | Condition | Address |
|---|---|---|
| R1 | The parent has exactly one pending def, and this is the first use since that def. Otherwise every pending def of the parent gets 0xb | 0x10711df3, 0x10711dff, loop 0x10711e01 |
| R2 | The def is not already 0xb | 0x10711e6a |
| R3 | The def destination and the use are the same location (`operands_same_location` 0x1071d500) at the same symbol offset | 0x10711e79, 0x10711e8b |
| R4 | Neither type is aggregate (0x5000). No float (0x4000) under /Op or -basic | 0x10711ea2, 0x1078ff9f |
| R5 | Equal types, or both integral and the use no wider than the def | 0x10711ee0, 0x10711f82, 0x1078ffe9 |
| R6 | Neither the def destination operand nor the use operand is volatile (`node_has_side_effects` 0x10702f99 tests operand +0x10 & 0x40 and +0x11 & 8) | 0x10711eeb, 0x10711efc |
| R7 | `propagation_def_use_eligible(def, use)` 0x10711786 | call 0x10711f08 |
| R8 | Registering a def a second time (a second use in another tuple) sets 0xa + 1 = 0xb | 0x10711f31 |

`propagation_def_use_eligible` 0x10711786, in full:

- If def and use are in the same block (tuple +0x14 block), walk forward from the def. Reaching the
  use returns 1. Reaching a block-boundary tuple (kind 0x19) first returns 0.
- Otherwise it returns `bitvec_test(use_block+0x60 /*dominators*/, def_block+0x6c /*RPO index*/)`
  AND `def_block+0x68 == use_block+0x68` (same innermost loop).

It does not look at calls, stores, types, loops inside a block, or the use's position in a call.

### 1.2 Kills between def and use [read]

A pending def gets status 0xb when any of these happens:

| # | Event | Address |
|---|---|---|
| K1 | A source or destination operand of kind 6 (memory) or 0xb (memory effect) whose alias class contains the parent (`alias_class_members`, members with +0x32 & 8) | src 0x10711d44..0x10711d9a, dst 0x10711f90..0x10712098 |
| K2 | A direct store to the same parent. Pending defs at other locations of the parent (sibling fields) get 0xb, the lists are cleared, and the new store becomes the pending def | 0x107120a7..0x10712136 |
| K3 | That store is not a plain 0x15b assign. The store itself gets 0xb | 0x1071213c |
| K4 | A call tuple (kind 0x14 or opcode 0x187). Unregistered defs get 0xb. A registered def survives unless its first source is a temp or symbol with a defining tuple | 0x10711fd2, 0x10712149..0x1071219a |
| K5 | Block end. The parent is live out (block +0x30): registered defs get 0xb. The parent is aliased (+0x32 & 0x10, from `g_aliased_syms`): every pending def gets 0xb. There is also a back-edge overlap test | 0x107123bb, 0x107123c5, 0x10712391 |
| K6 | A block with other than one predecessor (a join). Each active parent that does not have exactly one def and one use loses its unregistered defs | 0x10711cd6..0x10711d25 |

### 1.3 Commit (0x107124e5..0x10712794) [read, verified for the base]

- Status must still be 0xa, and the use operand must carry the last-use mark (+0x11 & 0x10).
  0x107124e5.
- A pair whose def tuple still waits for propagations into it (tuple +0x12 counter) is deferred.
  0x10712699.
- `range_free_of_conflicts` 0x10742ad4 runs on the use's root tree (call site 0x10712713). Unless the
  def is the tuple just before the use, it also runs on every tuple between them (0x107125d8). The
  test is `operands_may_alias` 0x10702771.
- Then 0x1071273e `move_expression_tree_before` 0x1071d548 moves the tree. A 0x15f conversion is added
  for a type change, a 0x162 FROUND for a float (0x10712643), and 0x12794 deletes the original def.

So a float def fails exactly when R1-R8, K1-K6, the last-use mark or a range check fails. The use
being a call argument is not itself a condition. The argument is a 0x15a tuple with a register-temp
destination and no memory effect.

## 2. The canonical heading [verified]

`fwdprop_trace.py` on the canonical copy, line 171 (`shot_heading`) and line 181 (the call):

```
ln 171 range_use: free        def: shot_heading = fpatan(#2267, #2268) - c
ln 171 range_between: free    use: 15a arg #350 <= shot_heading (ln 181)
ln 171 range_between: CONFLICT  def: #2267 = [shot_delta+0]   use: cvt #3540
ln 171 range_between: CONFLICT  def: #2268 = [shot_delta+4]   use: cvt #3542
    alias: [2: move_delta.x] ~ [6: class 4]
```

The heading moves, so the atan2f parameters' conversion uses now sit after the `move_delta` stores.
Those stores may alias the returned pointer's class, so X and Y stay held. The result is X, Y, the
adds, `fxch`, `fpatan`, and a direct `fstp [esp]` into the argument.

## 3. Spellings that keep the heading early

| Spelling | Refusal | Heading | Loads |
|---|---|---|---|
| `scratch_pos.x = atan2f(..) - pi/2;` and pass `scratch_pos.x` | store to an address-taken function-scope aggregate is never forwarded (v23: even with no tuple between store and argument) | early, stored to the vec2_sub destination, `mov eax,[slot]; push eax` | Y, X |
| `float &h = scratch_pos.x; h = ...;` pass `h` (best.diff) | same | same | Y, X |
| `float h = ...; scratch_pos.x = h;` pass `scratch_pos.x` | same | same | Y, X |
| `random_offset.x = ...` | same | early | Y, X |
| heading used again after the call (diagnostic) | R1/R8 | early, spilled | Y, X |
| owner_id if/else between def and use (diagnostic) | K6 | early, spilled | Y, X |
| function-scope `float` with other defs, heading inline in the argument, `pu_add` in argument 1 | none | moved, identical object | X, Y, fxch |

For the aggregate store, the exact kill site was not traced. v23 moves the adds before vec2_sub, so
only the owner and type argument tuples sit between the store and the argument, and the store is
still kept. That leaves two candidates: the last-use mark, which is not set on an overlapping field
of a live aggregate, or a K1 kill. [Inferred]

Native's home agrees with this spelling. Native passes `lea ecx,[esp+0x28]` (frame 0x18) as
vec2_sub's destination at 0x413b37 and stores the heading with `fstp [esp+0x30]` after two pushes at
0x413b9e, also frame 0x18. The candidate passes `lea ecx,[esp+0x40]` and stores `fstp [esp+0x48]`
after two pushes. Both are the destination vector's x.

## 4. What is still different

**Load order.** With the heading at its statement, the parameters `_X = [d]` and `_Y = [d+4]` have
nothing between them and their conversions, so both propagate: `fld [eax+4]; fld [eax]; fpatan`.
Native's `fld [eax]; fld [eax+4]; fxch` needs X kept and Y propagated. That is the "deny X + heading"
mode of `evidence/player-angle-propagation-2026-09-22`. Holding both, through sibling fields of a
local vector (`v.x = d[0]; v.y = d[1]`), again gives Y, X (v05, v09), as the "deny all three" mode
did. No stock spelling was found that kills only X. The candidates in §1 would need a second use of
X, a join, a memory access in X's alias class, or a sibling store between X's def and Y's def.
Native has none of these between its two loads.

**`fsub` placement.** `sched_trace.py` on the escaped variant shows window 44 = 81 nodes (78
machine, 3 FROUND), lines 137-171, ending at the cap, and `fpatan` is its node 81. The FROUND and
`fsub` open window 45 with no pending latency, so they are emitted first. Moving the adds before
vec2_sub changes the window cut, and the native fill `fpatan; mov edx; lea ecx; push edx; push 0x2d;
fsub` appears (v23, v24). The placement is therefore a window-boundary effect. It depends on the node
count from the owner_id label on, and not on propagation. Native has one fewer machine instruction
before the call (no `add ebp, ADDR`). Window content is not known on the native side. [Verified for
the candidate, inferred for native]

**Temp ids.** Holding the heading changes by one the number of class-3 temps created before the
movement arms. In `sched_trace.py`'s float-op report, `t:0x14000` becomes `t:0x14040`, and field
leaves move between the keys 0x10007/0x14007/0x18007/0x1c007. The likely cause is the propagation
FROUNDs: two (X and Y) instead of one (the heading) [inferred]. The hash-ordered commutative products
then reorder, for example the move-speed factors (`fmul [edi+0x68]`). Named-local ids (`l0x...`) do
not change. Whether a given spelling flips them depends on
the id counts, so the plain `scratch_pos.x` form flips four lines on b7033a699 and the reference form
does not. [pu-factor-order.md](pu-factor-order.md) gives the key: owner id mod 4. A parenthesized
pair or the setter spelling there pins the order.

## 5. Acceptance tests

Predictions were written before each batch (work dir `predictions.md`). The window is the target
range 0x413b7f..0x413bc2. "changed" is the matcher's changed target instructions there.

Base 3e87ace74 (player_update of 919d90105): 74.66%, refs 857/0/0, window changed 20.

| Variant | Predicted | Observed | Result |
|---|---|---|---|
| v01 second use | early, Y/X | early, spilled, Y/X | ✓ |
| v02 join | early, Y/X | early, spilled, Y/X | ✓ |
| v03 `scratch_pos.x =` | early, Y/X | early, frame store and `mov/push`, Y/X, window 11 | ✓ (mechanism revised by v23) |
| v04 fields `v.x/v.y` only | late, X/Y/fxch | identical object | ✓ |
| v05, v06 fields + early heading | early, X/Y/fxch | early, Y/X | ✗ loads |
| v10 `double` X | X kept (conversion def) | 0x15b with a double destination, propagated, Y/X | ✗ |
| v15 `movement_heading` (multi-def) | – | identical object | neutral, as reported |
| v23 v03 with adds before vec2_sub | store forwarded into the argument | store and reload kept, native fill after `fpatan` | ✗ forwarding, ✓ fill |
| v24 named heading, adds first | propagated, Y/X | `fstp [esp]`, Y/X, native fill | ✓ |
| v20-v22 `pu_add` in argument 1 | no prediction written | v20 Y/X late, v21/v22 identical | – |

Base b7033a699 (74.07%, refs 859/0/0, 4151 instructions):

| Variant | Raw | Refs | Labels masked vs base (`label_drift.py`) |
|---|---|---|---|
| v25 `float &shot_heading = scratch_pos.x` (best.diff) | 73.97% | 856/0/0 | +11 / -3 (net +8) |
| v03 plain `scratch_pos.x` | 74.08% | 857/0/0 | +11 / -7 (the 4 extra are move-speed flips) |
| v07 named then copied | 73.97% | 856/0/0 | same as v25 |
| v01 second use | 73.97% | 857/0/0 | – |

The three lines lost with labels masked are native's `fld [eax+4]`, `fxch` and `fsub [ADDR]`
(label_drift's 0-based lines 321, 322 and 328). They come from the load order and the window cut in
§4. v25's raw loss is label drift. It loses four branch-label lines that matched by coincidence
(734, 760, 784, 868), plus ten raw-aligned lines at 2142-2152. None of these is lost with labels
masked. No variant adds a reference mismatch or unresolved reference.

## 6. Predicting from source

1. A single-use float local is propagated unless one of R1-R8, K1-K6 or a range check fails.
   Multi-def, inline-in-argument and argument-order spellings do not change that.
2. Storing into a field of an address-taken function-scope aggregate is not forwarded, so it gives
   an early store and a memory push.
3. Once the heading stays, the atan2f parameters propagate into it. Expect Y, X loads.
4. Where `fsub` lands relative to the argument pushes follows the 81-node window cut
   ([x87-held-lanes.md](x87-held-lanes.md) §5). Count nodes (machine plus FROUND) from the last label.

## Open questions

- A source that kills only the X parameter. Native's X, Y, `fxch` needs it.
- The exact kill for the aggregate store: the last-use mark versus K1. A kill-site observer
  (0x10711e0b, 0x10711d9a, 0x10712094, 0x10712136, 0x1071213c, 0x10712166, 0x1071234b) would settle
  it.
- Native's window-44 node count. The `add ebp, ADDR` / `[ebp+ADDR]` difference and native's FROUND
  count before the call are unknown.

## Corrections to other notes

- [optimizer.md](optimizer.md), "Forward substitution": `propagation_def_use_eligible` 0x10711786
  also returns 0 in the same block when a block boundary (kind 0x19) comes before the use. Add a
  registration rule: registering the same def a second time sets 0xb (0x10711f31). The call kill
  (0x10712164) spares registered defs unless their first source is a temp or symbol with a
  defining tuple.
- `player_update/NOTES.md` "Fire Cough propagation": the eligibility helper is not where storage
  spellings act. Early heading computation is reachable from stock source (§3). The remaining
  constraints are the X-only kill and the window cut.
