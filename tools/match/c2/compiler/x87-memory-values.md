# x87 values that native keeps in memory: an earlier stack value forces the split (C2.DLL 8966)

This note explains a native x87 shape where a float that scores like a normal stack candidate is
stored to its frame home and multiplied from memory. It uses the four accelerate arms of
`player_update` (native 0x4140bb, 0x414323, 0x414b61, 0x414e2f) as the worked case. Addresses are
virtual addresses in the pinned C2.DLL (image base 0x10700000), and all rules are for `/O2 /GB`
without `/Op`.

"Verified" means confirmed on real compiles with the preserving observers
([`scripts/c2/x87_alloc_trace.py`](../../../../scripts/c2/x87_alloc_trace.py),
[`scripts/c2/fwdprop_trace.py`](../../../../scripts/c2/fwdprop_trace.py),
[`scripts/c2/il_stage_trace.py`](../../../../scripts/c2/il_stage_trace.py),
[`scripts/c2/frame_predict.py`](../../../../scripts/c2/frame_predict.py)). "Read" means static reading
only. "Inferred" means the rule fits every compile below but was not traced.

Short version:

1. A float with one def and a last use that is not an `fld` into a store or compare scores +2
   ([x87-spills.md](x87-spills.md) §3). It stays on the x87 stack unless it fails the LIFO test.
   Native's memory copy of `3.1415927f - angle_step` is a **nesting failure**, not a score of 0 or
   less. The other value in the conflict is `heading - 1.5707964f`, which was computed **before** it
   and is used later by `fcos`.
2. That earlier value exists only when forward propagation did not move the cos argument down to
   its use. Every plain spelling (named local, inline parameter, `double` local, reused
   function-scope variable, embedded assignment) is propagated, and then the argument is computed
   after the scale. [Verified]
3. A spelling that blocks the propagation without an address escape puts the angle and the scale
   in **two fields of one local aggregate** (a `vec2` struct or `float[2]`), with the angle field
   stored first. The store to the second field kills the pending forward propagation of the first
   field (`forward_propagate_definitions`, 0x107120a7..0x10712136). [Verified: all four arms then
   reproduce native's x87 sequence exactly, including the product order]
4. An address-taken scale variable gives the same x87 shape, because its store then aliases the
   `player->heading` read. Native takes no address of that slot, so this is not the native
   mechanism. [Verified shape; native lea scan]

## 1. The native shape

Native, mode-2 arm (0x414b61), after the cap compare's join label:

```
fld  [edi+0x2c]        ; A = heading
fsub [1.5707964]       ; A = heading - pi/2         (angle_step is st(1))
fld  [3.1415927]
fsub st(2)             ; M = pi - angle_step
lea/push ...           ; scheduler fill
fstp [esp+0x28]        ; M -> frame 0x20 (two pushes pending)
fcos                   ; cos(A)
fstp st(1)             ; pop angle_step under the cosine
fmul [edi+0x68]        ; * move_speed
fmul [esp+0x28]        ; * M          (memory)
fmul [esp+0x24]        ; * scalar     (frame 0x1c)
fmul [7.957747]
fstp [edi+0x1c]
fld  [edi+0x2c]; fsub [1.5707964]; fsin; fmul [edi+0x68]; fmul [esp+0x28]; ...
```

The four accelerate arms (modes 4 and 3, mode 2, the demo arm) are identical in shape. In all of
them M lives at frame 0x20. The same slot holds the mode 4/3 target heading and mode 1's ±1.0
move flag. No `lea` of frame 0x20 exists anywhere in the function (scan of every `lea [esp+X]` with
pending pushes subtracted: only 0x28, 0x38, 0x40, 0x48 ... 0x64 are address-taken).

The pre-fix candidate (`pu_inv0.cpp`, 67.45%) computes `fsubr [pi]` right after the cap, keeps M in
st(1), and pops it after the dy store:

```
fsubr [3.1415927]      ; M replaces angle_step in st(0)
fld [edi+0x2c]; fsub [1.5707964]; fcos; fmul [edi+0x68]; fmul st(1); fmul [scalar]; fmul [7.95]; fstp dx
... fsin ...; fmul st(1); ...; fstp dy
fstp st(0)
```

## 2. Allocator view [verified]

`x87_alloc_trace.py` on the candidate (mode-2 arm):

| Range | What | Score | Verdict |
|---|---|---|---|
| lr199 | `angle_step`, def = call result | 2 (def) | fits |
| lr192 | `movement_heading` web in this arm (M) | 2 (def; last use `fmul`) | fits |

The same variable's other webs (the mode-2 target heading, lr191, 6 constant defs, −7) are
separate ranges. The function-scope variable having many defs across the arms does not change
M's web.

`x87_alloc_trace.py` on the struct-field variant (§4, `turn.x = heading - pi/2; turn.y = pi -
angle_step`):

| Range | What | Score | tie | Verdict |
|---|---|---|---|---|
| lr213 | `turn.x` (A), def L590, end at the cos statement L593 | 2 | 0x70b | fits (placed first) |
| lr214 | `turn.y` (M), def L591, end at the dy store L595 | 2 | 0x708 | **fails** `below-dies-inside` and `below-ends-inside` at L593 |
| lr195 | `angle_step`, last use in M's def L591 | 2 | 0x6c3 | `extend-end` (REGUSE to A's end L593), fits |

- A and M tie on priority. The tie goes to the earlier def in the same block (higher tie key), so A
  is placed first ([x87-spills.md](x87-spills.md) §3).
- M is born while A is live, and A dies at the cos statement while M is still live. After the
  split M's def piece scores 2 − 2 = 0 and its reload pieces −1. Both go to memory, which gives
  `fstp [M]` and `fmul [M]` twice.
- `angle_step` dies in M's def while A, placed above it, is still live. The allocator extends its
  end to A's end, so its pop is emitted after `fcos` as `fstp st(1)`.

So native's M is memory because of a **nesting failure against A**. It is not a score of 0 or less,
not a call between def and uses, and not the many defs of the function-scope variable.

## 3. Why A is computed before M: forward propagation

C1 already emits the argument before M in some spellings. `il_stage_trace.py` (stage `glob`) for
`dx = pu_cos(player->heading - 1.5707964f) * speed * (movement_heading = pi - angle_step) * ...`:

```
#3595 (inline param 'angle') = heading - 1.5707964f     ; A, hoisted inline parameter setup
movement_heading = 3.1415927f - angle_step               ; M
cvt  #3711 <= #3595 ; 15a arg ; intrin (cos) ; cvt      ; the intrinsic
```

That is native's order. `forward_propagate_definitions` 0x10711afa then moves A's tree down to its
single use, with a FROUND. `fwdprop_trace.py` shows `ln 587 range_between: free` for `#3595`, so
the compile emits M first again (67.03%). An embedded assignment on its own is emitted first by C1
(`M = ...` before the cos argument), with a C1 `round` of M at its use.

Every def-before-use pair is propagated unless one of the kill or refusal conditions of
[optimizer.md](optimizer.md) ("Forward substitution") fires. The ones that can leave A in place
while A still dies at `fcos` are:

| Condition | Where | Usable here? |
|---|---|---|
| A store between def and use may alias the tree's reads (`range_free_of_conflicts`) | 0x107125d8 | Only if M is address-taken (in the alias class of `[player+0x2c]`). Native has no address of frame 0x20 |
| A direct store to **another location of the same parent aggregate** | 0x107120a7..0x10712136 | Yes: A and M as fields of one local struct or array |
| A call between def and use | 0x10712164 | No: the x87 stack cannot hold A across a call |
| A live out of the block, A address-taken, a second use | | No: A would have to survive `fcos` or live in memory |

The sibling-field kill, from the disassembly [read, and verified by the compiles in §4]:

```
107120a7  ebx = dst->sym->parent                   ; direct store (operand kind 2)
107120aa  if !(parent[+0x32] & 8) skip             ; parent is a forward-propagation candidate
107120c6  for each pending def d in parent[+0x4c]:
10712125      if !operands_same_location(dst, d->dst)   ; 0x1071d500
10712136          d[+0x13] = 0xb                         ; killed: never propagated
107120d2  list_node_release_all(&parent[+0x4c]); list_node_release_all(&parent[+0x50])   ; 0x1071175c
107120e3  if store is 0x15b: push it as the parent's new pending def
1071213c  else: the store itself is marked 0xb
```

Defs and uses are tracked per **parent symbol**. A scalar local is its own parent, so a store to a
different scalar never kills anything. A field of a local aggregate shares its parent with the
sibling fields, so storing `turn.y` kills the pending propagation of `turn.x`. `fwdprop_trace.py`
on that variant logs no range check at all for either field. `turn.x` never reaches the commit
step, and `turn.y` has two uses.

## 4. How to predict from source

For a value M used twice and a single-use value A used after M's def:

1. If A's def ends up before M's def in the IL **and** is not propagated, A is placed first (tie on
   priority 2, earlier def). M fails the LIFO test and becomes memory: `fstp [M]`, `fmul [M]`. The
   dying value under A (here `angle_step`) is popped after A's consumer with `fstp st(1)`.
2. A stays before M only if a kill fires. From source, that means one of these:
   - A and M are fields of the same non-address-taken local aggregate, with A stored first;
   - M is address-taken and A reads through a computed pointer (the held-lanes alias rule,
     [x87-held-lanes.md](x87-held-lanes.md) §3).
3. Otherwise A is propagated (FROUND at the use) or is just part of the cos expression, M is
   computed first and stays on the stack, and the product reads it as `fmul st(1)`.

Things that do **not** change the outcome [all verified, see §5]: moving M's statement before or
after the aim, accelerate and cap code; a named A local; a `double` A; a function-scope A
assigned in all four arms; an inline `pu_cos(float)` wrapper; an embedded `(M = ...)`; a CSE'd
`(pi - angle_step)` with no variable; a per-arm block-scoped scalar M; and binding M to an inline
pointer or reference parameter, a local `float &`, or a local `float *`. None of these last
spellings makes M address-taken.

## 5. Acceptance tests

All variants are copies of `pu_inv0.cpp` with the canonical `player_update` scratch.conf. The
template replaced the M assignment and the two move lines in all four accelerate arms unless noted.
Predictions were written before each compile. Score is the whole function. Refs are ok / missing /
problems.

| Variant | Prediction | Observed arm x87 | Score, refs, frame |
|---|---|---|---|
| inv0 (baseline) | – | `fsubr [pi]`; M in st(1) | 67.45%, 785/0/3, 0x50 |
| **v25**: block-scoped `player_update_vec2_t turn; turn.x = heading - pi/2; turn.y = pi - angle_step; dx = cos(turn.x) * speed * turn.y * scalar * C; dy = sin(heading - pi/2) * speed * turn.y * ...` | native shape: A first, M split, `fstp st(1)` after `fcos` | **native x87 sequence in all four arms**: same instructions, stack operands and order, including `fmul speed; fmul [M]; fmul [scalar]`. The `esp` offsets and the interleaved pushes differ with the frame | 59.69%, 781/0/2, 0x54 |
| v34: same, fields swapped (`turn.y` = A stored first, `turn.x` = M) | native shape (kill is symmetric) | native | 59.61%, 781/0/2, 0x54 |
| v25, mode-2 arm only | native shape in that arm only | native in arm 2 | 59.75%, 780/0/3, 0x54 |
| v26 / v27: function-scope `turn` struct / `float turn[2]` | native shape | native | 56.55%, 723/0/13, 0x58 |
| **nc1** (negative): v25 but `turn.y = M` stored **before** `turn.x = A` | A propagated to its use, candidate shape | candidate shape | 67.06%, 783/0/2 |
| v3 (negative): `float move_angle = heading - pi/2;` before the scalar M | propagated | candidate shape | 67.06%, 783/0/2 |
| v7 (negative): function-scope `move_angle` assigned in all four arms | propagated (multi-def alone is no kill) | candidate shape | 67.06% |
| v16 (negative): `double move_angle` | propagated | candidate shape | 67.06% |
| v18, v20 (negative): inline `pu_cos(float)`, with and without embedded `(M = ...)` | propagated. v20's C1 IL has native order, then `range_between: free` | candidate shape, v20 `fld st(1); fmulp` | 67.06%, 67.03% |
| v1 (negative): embedded `(movement_heading = pi - angle_step)` in dx | C1 emits the assignment first | M first | 67.42% |
| v2 (negative): `(pi - angle_step)` in both lanes, no variable | CSE temp defined before the cos statement | candidate shape | 67.06% |
| v36 (negative): per-arm `float move_scale = pi - angle_step;` | no A def, M fits | candidate shape | 67.45%, 785/0/3 |
| early: M assigned right after the call | M held across accel/cap | M on stack from the call on | 67.45% |
| bptr / bref: mode 4/3 wrap loop as inline `pu_wrap_heading(float *)` / `(float &)` | inline address does not set the address-taken flag | object identical to inv0 | 67.45% |
| v21 / v22: `float *p = &movement_heading` / `float &r = movement_heading` in the body | no alias effect | candidate shape | 67.00% / 67.45% |
| v4 (mechanism): named A local + `pu_sink(&movement_heading)` at entry | range_between conflict, native shape | native order, but `fmul [scalar]` before `fmul [M]` | 54.40% (extra call) |
| v6: `pu_sink(&movement_heading)` only | M memory, still first | `fld pi; fsub st(1); fstp [M]; fstp st(0); fld heading...` | 53.96% |

**Result.** The x87 question is answered: v25 and v34 reproduce native's sequence in all four arms.
The whole-function score falls because the 8-byte aggregate widens frame slot 6 from 4 to 8 bytes
(`frame_predict.py`: `sub esp,0x54` against the candidate's 0x50 and native's 0x48), and that
shifts every `esp` offset. The candidate frame is already 8 bytes larger than native's, so the
aggregate has to replace existing frame bytes before the gain shows in the score.

A second side effect comes from dropping the trailing `fstp st(0)`. In v25 the accelerate arm's dy
store `fstp [edi+0x20]` becomes identical to the decelerate arm's, and C2 sinks it into the
shared tail (`jmp` right after the last `fmul`). Native keeps the store in the arm, followed by
the per-arm vector build. Moving `pu_move_scaled` into both branches of the mode-2 and demo arms
does not recover this: v25p 59.50% and baseline inv0p 61.75%, both with refs x/0/8. That is block
structure, not x87 ([x87-held-lanes.md](x87-held-lanes.md) §5, §6).

**Layout hint** [inferred]. Native frame 0x1c is `scalar`, live across the arms, and M is at 0x20.
If native uses an aggregate, it is `{M at +0, A at +4}` at frame 0x20, and A's field never reaches
memory. That is v34's field order. Frame 0x20 also holds the mode 4/3 target heading and mode 1's
±1.0 flag. That is consistent with the pair's first field being the function's
`movement_heading`, but making `movement_heading` a struct field everywhere (v33) costs a new 8-byte
slot (53.18%, frame 0x58).

## Open questions

- The natural original source. The traces fix the mechanism (a sibling-field kill, or an aliased
  M, which native's lack of any address of frame 0x20 excludes). They do not fix the aggregate's
  type or its role elsewhere in the function.
- How to place the aggregate so that the frame does not grow. That depends on the rest of the
  candidate's frame surplus (0x50 against 0x48).
- Why the address-taken variant (v4) sorts `scalar` before M while the field variants keep source
  order. This is presumably the commutative operand sort keys of a local against a field
  ([x87-scheduling.md](x87-scheduling.md) §5). Not traced.

## Corrections to other notes

- [optimizer.md](optimizer.md), "Forward substitution", kill list: add "a direct store to another
  location of the same parent aggregate kills the pending defs of that parent's other fields
  (0x107120a7..0x10712136). A direct def that is not a 0x15b assign is itself marked 0xb
  (0x1071213c)." Defs and uses are tracked per parent symbol (+0x4c, +0x50).
- [x87-scheduling.md](x87-scheduling.md) §3 table, row "Variable with more than one def ... no":
  multiple defs of a scalar are not a kill. A function-scope float assigned in four arms was
  propagated (v7). The `position.x` example is a field of an aggregate, so the sibling-field kill,
  a read of the variable inside its own redefinition, or a live-out may be the real cause there.
  Not re-traced.
- [x87-held-lanes.md](x87-held-lanes.md) §3: binding a local to an inline pointer or reference
  parameter, a body `float *p = &x`, or a `float &r = x` does not make it alias-class visible. The
  object is identical, or the value still propagates. Only a real escape (address passed to a
  call) does.
