# Field operands in commutative float products: owner-id keys and parenthesis rounds

This note answers one question from player_update. The move lanes compute
`(float)cos(h) * player->move_speed * turn * scalar * K`. Why does `fmul [edi+0x68]` (move_speed) move
between first and last when an unrelated edit is made? It also records two general rules the answer
depends on. The sort itself is described in [optimizer.md](optimizer.md) (Part B, cost and ordering) and
[x87-scheduling.md](x87-scheduling.md) §5.

## 1. A field leaf's key after globopt is its address owner's id mod 4

`compute_tree_cost_and_sort` 0x1070d90c runs twice: before globopt and after it. The second run decides
the order.

- **First run.** `player->move_speed` is `[player + 104]`, a memory operand whose address is still the
  subtree `player + 104`. Its key is `0x01020158` (need 1, size 2), so it sorts ahead of every leaf.
- **globopt.** `assign_expression_owners` 0x10711209 gives the pure address `player + 104` an expression-owner
  temp (class 3). The operand becomes `[owner + 0]`, a size-1 leaf.
- **Second run.** The key is

  ```
  key = 0x10000 | (fold(0) + (IL_AM_BASE_DISP - 0x145) + (owner << 6) << 8) & 0xffff
      = 0x10007 | (owner & 3) << 14            -> 0x10007, 0x14007, 0x18007 or 0x1c007
  ```

  The field displacement lives in the owner's definition, not in the leaf. A float local's key is
  `0x10000 | ((id & 0x7ff) << 5)`, which is 0x10160 to 0x12a80 for the locals of a large function.

So a field leaf beats the locals of the same product when `owner & 3 != 0`, and loses to all of them when
`owner ≡ 0 (mod 4)`. The owner ids are drawn one per new pure expression in IL order (a lea of a memory
operand takes two). Any edit upstream that adds or removes 1 to 3 expressions can flip the order. Block-sized
shifts (+32) cannot.

## 2. Explicit parentheses around a float subexpression are a C1 `round`

C1 emits a `round` tuple (IL 0x162) for a parenthesized float subexpression. This happens even when the
parentheses restate left associativity: `((float)cos(h) * m) * s * K` parses the same as
`(float)cos(h) * m * s * K`, and the round is still emitted. Without /Op the round generates no code, but it is
not a multiply. It therefore ends the flattened mul/add chain, and the two chains are sorted separately:

- inner `{cos subtree, m}`: the cos subtree (need 5, size 5) always sorts first, so m is second at any owner id;
- outer `{round temp, s, K}`: the round temp sorts first.

A `(float)` cast of a float product is a no-op, but it needs parentheses, so it has the same effect. Operand
order in the source (`m * (float)cos(h)`) has no effect. Seen outside the lanes: ln260
`(0.6f / time_scale_factor) * frame_dt`.

## 3. What moved the player_update lanes (919d90105)

| build | owner of `player+0x68` | move_speed key | lanes |
|---|---|---|---|
| 919d90105, `player->movement = scratch_pos` | #4552 (0x11c8) | 0x10007 | move_speed last |
| two field stores instead of the vector copy | #4554 | 0x18007 | native |
| `player_update_vec2_set` for fire-bullets blocks {0}, {1}, {2} or {1,2} | #4553 | 0x14007 | native |
| setter for all three blocks | #4554 | 0x18007 | native |
| parenthesized `(cos * move_speed)` | #4584 (+32) | 0x10007 | native (round barrier) |

- **The vector copy is −2.** It is one blkcopy with one address owner (player+0x1c). The two field stores
  need two address owners (0x1c and 0x20) plus their memory ids.
- **Each setter call whose X argument is a new expression is +1.** C1 forward-propagates X with a `round`
  ([x87-memory-values.md](x87-memory-values.md)), and that round is a new VN expression. Calls 2 and 3 share
  X, so they CSE.
- **The competing locals** are scalar (#300 → 0x12580; #329 → 0x12920 in the setter build),
  movement_input.x (#21 → 0x102a0), scratch_pos.x (#11 → 0x10160), movement_heading (#310 → 0x126c0) and
  frame_dt (g0x26 → 0x104c0).

## 4. Predicting from source

1. Find the product's leaves. Pointer fields become `[owner+0]` after globopt. Locals and globals hash
   by id.
2. Count the owner id of the field's address from an existing trace:
   - `sched_trace.py` prints `[t0x…+0x0]:key` at lowering entry;
   - `sort_trace.py` prints the keys at the sort itself.

   For an edit, add or subtract the new pure expressions drawn before the first use of that address.
3. `owner & 3 == 0` means the field sorts after every local. Otherwise it sorts before locals with id
   below 0x200 (key < 0x14000).
4. To make the order independent of ids, parenthesize the pair so the round barrier separates it.

## 5. Acceptance tests (prediction first, then compile)

| test | prediction | observed |
|---|---|---|
| owner model on 919d90105 / two-stores build | last / first | yes / yes (22 lanes, plus L516) |
| swap `player->move_speed * (float)cos(h)` | no change | no change (identical object) |
| paren `((float)cos(h) * player->move_speed) * …` | first | first; the owner is 0x11e8, still ≡ 0 |
| `(float)(cos(h) * player->move_speed)` | first | first, same code as paren |
| `(float)((float)cos(h) * player->move_speed)` | predicted a no-op cast (last) | **wrong**: first, because the parentheses round |
| setter subsets {0}, {1}, {2}, {1,2}, {0,1,2} | +1, +1, +1, +1, +2; all first | all measured as predicted |
| paren on top of the full setter | identical object | identical |
| nested `((cos*m)*turn)*scalar*K` | source order | cos, m, turn, scalar, K |

The whole-function % falls in every build that fixes the lanes (74.66 → 73.02). `label_drift.py` shows why:

- 47 branch labels are lost to the +1 instruction of the changed cross-jump;
- 27 lines are lost to a SequenceMatcher cross-arm alignment of lane 1, the source of the 849/0/1 reference pair;
- with labels masked, 4 lines are gained and none lost.

## Tool

`scripts/c2/sort_trace.py <scratch> --out <dir> [--lines A-B]` hooks the call at 0x1070da8d
(`compute_tree_cost_and_sort` → `merge_sort_operand_list` 0x1070f584, comparator 0x1070f6ae). For every
commutative node it prints the operand list before (PRE) and after (POST) the sort, with
`need/size/hash` decoded. The last POST for a line is the final order.

## Open questions

- In all 8 four-factor lanes native puts the turn factor before scalar, and one slot ([esp+0x20]) serves
  all four arms. With our ids scalar outranks movement_input.x/scratch_pos.x. Native's turn variable
  probably has a larger pool-B id than scalar, meaning it is first referenced after scalar. Reusing
  angle_step makes C2 hold the value on the x87 stack (`fmul st(1)`), which is not native.
- The +32 owner shift in the parenthesis build is attributed to one more frontend temp block; not traced.
