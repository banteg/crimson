# Splitting `move_delta` into block-scoped vectors (C2.DLL 8966)

This note records what happens when `player_update`'s function-scope `move_delta` is split into
block-scoped vectors across the whole function. The goal was for the arms that native keeps apart to
build into different objects that share one frame slot, as proposed in
[slot-sharing-symbols.md](slot-sharing-symbols.md) §1.5.

The split does keep the arm pairs apart. It fails on two other counts:

- It breaks the x87 shape of every movement build.
- It cannot place the new vectors in native's slot without reworking `random_offset`.

The note also collects three native facts about the frame slot at bottom 0x38 (below, b0x38). No
source model tested so far satisfies all three.

Addresses are C2.DLL virtual addresses (image base 0x10700000), `/O2 /GB`. Evidence labels:

- **Verified**: observed in a compile or a preserving trace.
- **Read**: taken from the cited notes.
- **Inferred**: fits every compile, but not traced.

The base is origin/master 830389960, at 73.64% and refs 855/0/0, frame 0x48. Predictions were written
before each compile.

See also:

- [x87-held-lanes.md](x87-held-lanes.md) §3: the scope rule for held lanes.
- [per-arm-frame-weights.md](per-arm-frame-weights.md): weights and the 8-byte order.
- [native-slot-partition.md](native-slot-partition.md): the partition method.
- [aim-chain-mover.md](aim-chain-mover.md): cross-jump pairs.

## 1. Short answer

1. **Symbols do keep the pairs apart** [verified]. With a block-scoped vector in each movement mode,
   `xjump_trace.py` no longer reports these merges:
   - the demo-accel / mode-3-decel pair (ln664/ln430);
   - the demo / mode-3 accel pairs that the setter-shaped `> 300` arm creates (ln652/ln399 and
     ln666/ln413);
   - the mode-4-decel / mode-3-accel pair, once mode 4 gets its own vector.
2. **Block scope loses native's held y lane at every movement build** [verified].
   - A block-scoped vector is not in the alias class of `[player+0x20]`, because `player` is defined at
     function entry. Both setter lanes then forward-propagate, which gives two FROUNDs in the
     pre-schedule IL.
   - The code becomes `fmul [x]; push; fstp x; fmul [y]; fstp y`. Native has
     `fmul [y]; fxch; fmul [x]; …; fstp x; fstp y` at all 11 builds.
   - Every spelling that re-points the lane inside the block was tried. Only a fresh
     `&player_state_table[idx]` gives a held lane, and it reads through a new ebp pointer (§4).
3. **Block scope also breaks the aim arms** [verified]. The aim-arm uses (`move_delta.x = scalar * mi.x`
   and the `.y` sin temps) become vectors whose address is never taken. They are promoted, so they
   leave the frame, and aim arm 4 loses native's `fstp [b0x38]; fld [b0x38]`.
4. **The split vectors land one slot too high unless `random_offset` loses weight** [verified].
   - The 8-byte slots take list order from the lowest address. Every split vector weighs 3 to 9, far
     below `random_offset`'s 130.
   - So the split slot opens after `random_offset` (b0x40), and `random_offset` moves to b0x38.
   - A single fire-block vector reaches 115. It passes `random_offset` only when the weapon arms'
     projectile positions also move from `&random_offset` into it (160 against 85).
5. **An escaped function-scope vector is live at every later call** [verified, micro F1/F2]. It
   therefore conflicts with every object defined before a later call, even far past its last direct
   reference. Keeping `move_delta` function-scope for the cough, movement and aim sections, and
   splitting only the fire section, grows the frame to 0x54.

The best split scores **70.29%, refs 859/0/0**, against the base's 73.64% and 855/0/0. No split beats
the base.

## 2. Use map of `move_delta` (830389960 line numbers)

| Section | Lines | Kind |
|---|---|---|
| fire cough | 295–298, 315–319, 324–331 | two field stores each; `vec2_length(&)`, `projectile_spawn(&)`, `fx_spawn_sprite(&mi, &)` |
| mode 3 | 549/553, 562/566 | `pu_move_scaled(&)` + `player_apply_move_with_spawn_avoidance(…, &)` |
| mode 1 | 618/622, 636/640, 653–658 | same; the last arm uses direct field stores |
| mode 2 | 738/742, 751/755 | same |
| demo | 800/804, 813/817 | same |
| aim 4 / 3 / 1 / POV / auto | 947, 973/987, 1012, 1031, 1053 | field temps only; the address is never taken in these arms |
| smoke | 1176–1183 | field stores and reads |
| spread | 1207–1211 | setter + `vec2_length(&)` |
| fire_bullets | 1265–1271 | sprite velocity |
| weapon arms | 1304–1990 | sprite velocities (×25, ×15) in 13 arms; projectile positions in 11 arms |

Mode 4 builds into `movement_input`. The weight of `move_delta` is 163: 57 source references and 106
destination references.

## 3. The frame, predicted and observed

| Variant | Change | Prediction | Observed |
|---|---|---|---|
| v1 | a block vector in each of 30 blocks (cough, modes 3/1/2/demo, 5 aim arms, fire block for the spread, smoke, fire_bullets, 17 weapon arms) | B slot opens after `random_offset`; the spread vector conflicts with the smoke objects | as predicted: mi 0x20, sp 0x28, ro 0x30, B slot 0x38 (16 bytes, `smoke_color` joins), spread vector alone at 0x48, frame 0x50; 67.18%, 858/0/0 |
| v2 | block vectors for cough, modes and aim, plus **one** fire-block vector | fb about 110 < ro 130: ro b0x38, fb b0x40 | fb 115: ro b0x38, fb b0x40 with `previous_pos`, movement vectors in the temp slot b0x18; **70.29%, 859/0/0** |
| v3 | v2 + weapon projectile positions `&random_offset` → fire-block vector | fb about 165 > ro about 75: fb b0x38; `previous_pos` (13) joins fb's slot, so the movement vectors fall to b0x18 | fb 160 b0x38 with `previous_pos`, ro 85 b0x40, movement vectors b0x18; extra weapon-arm cross-jumps; 70.21%, 842/0/0 |
| v3m4 | v3 + mode 4 builds into its own block vector | `movement_input` 188 − 6 = 182 < `scratch_pos` 184, so the slots swap | swap; 66.53%, 848/0/0 |
| v4a | function-scope `move_delta` kept for cough, movement and aim; a shadowing fire-block vector + positions | frame identical to base | **wrong**: the function-scope vector (w48) conflicts with fb and `smoke_color`; frame 0x54, 60.79%, 809/0/7 |
| v5 | v3 with `previous_pos` as two floats (diagnostic) | movement vectors join fb | fb joins the 4-byte slot 7 instead; frame 0x4c, 64.34% |

The v4a failure is rule 5 of §1. Micro F1 has a function-scope `vec2f_t d` escaped in an `if`,
followed by a block `C4 c` with a call after its stores. There `c` conflicts with `d`. Micro F2 is the
same without the later call, and there `c` joins `d`'s slot.

## 4. Held-lane controls in player_update

Every variant below puts a block-scoped `move_step` in the mode-3 block (m3only) and changes only how
the lanes are read.

| Variant | Lane source | Result |
|---|---|---|
| m3only | `player->movement` | x first, two FROUNDs (`alias_trace.py`); frame 0x4c; 65.49% |
| L6a | block `const vec2f_t &movement = player->movement` | identical object to m3only |
| L6d | block `const vec2f_t *movement = &player->movement` | identical object to m3only |
| L6c | block `player_state_t *mover = player` | identical object to m3only (copy propagated) |
| L6b | block `mover = &player_state_table[render_overlay_player_index]` | held (y first), but a new `ebp` pointer is computed; 64.53% |

Micro re-runs of [x87-held-lanes.md](x87-held-lanes.md) gave the same results. L4 (function-scope
`d`) is held. L5 (block `vec2f_t d`) and L5a (block `float d[2]`) are not.

## 5. Native facts about b0x38 that the model cannot yet combine

Follow-up ([pu-residual-map.md](pu-residual-map.md)): native's 0x38 slot also holds every spawn position and the smoke colour, and native splits `random_offset`'s roles over four slots.

These come from `native_slots.py` with the corrected candidate tracker (§7). With that fix the
partition maps `movement_input` → 0x28, `scratch_pos` → 0x30, `previous_pos` → 0x20, and
`move_delta` + `smoke_color` → the 16-byte native object at 0x38. It shows one bracketed conflict,
`_move_delta x _smoke_color`.

1. **Held y lane at all 11 movement builds.** Native reads through `edi`, which is computed once at
   entry. So the vector is exposed at entry: function scope, by the L4/L5 rule (§4).
2. **Aim arm 4 stores and reloads the vector through b0x38** (`fstp [esp+0x48]; fld [esp+0x48]`,
   0x415396). The object must be escaped, and its scope must reach the aim arms. A block-local vector
   there is promoted (§1, point 3).
3. **`smoke_color` occupies b0x38..0x47** (constants 1, 1, 1, 0.6 at 0x415a8e..0x415ac0). The vector
   is therefore dead at the smoke stores, which calls follow. By rule 5 of §1 it cannot be an escaped
   function-scope local.

Facts 1 and 2 point to a single escaped vector exposed at entry. Fact 3 excludes one. The movement
non-merges are the other constraint. They need different symbols ([slot-sharing-symbols.md](slot-sharing-symbols.md) §3),
or some IL difference that nobody has found.

One untested source shape satisfies facts 1–3 and native's frame order: a single function-scope
16-byte object, used as the movement/aim/weapon vector and as the smoke colour. It would sort after
the 8-byte group and land at b0x38. It would not explain the movement non-merges. [inferred]

## 6. How to predict from source

- A block-scoped vector built by a setter from `player->…` lanes is **x-first**. It is y-first
  (native) only when the pointer the lanes read through is defined in the vector's own block by a real
  computation. A copy or a reference is not enough.
- A block-scoped vector whose address is never taken is promoted and leaves the frame.
- An escaped function-scope aggregate conflicts with every object whose definitions precede a later
  call. Its last direct reference does not matter.
- Block-scoped aggregates in disjoint scopes share a slot. The slot sits in the 8-byte list at the
  position of its heaviest member. Compare that weight against the function-scope vectors
  (`frame_predict.py`).

## 7. Tools

```sh
uv run python scripts/c2/frame_predict.py <scratch> --out <new dir> --json w.json   # weights, slots, offsets
uv run python scripts/c2/slot_scan.py <scratch> --out <new dir> --match '_move_delta|_smoke_color'
uv run python scripts/c2/xjump_trace.py <scratch> --out <new dir>                   # cross_jump_pair verdicts
```

`frame_predict.py --native` and `native_slots.py` track the candidate's esp wrongly. For a relocated
call not followed by `add esp`, `candidate_pop` returns `None` whenever the name is not in the image
manifest (for example `_crt_rand`). The caller then pops the argument window, although C2 defers
cdecl cleanup to a later `add esp`.

The result is depth conflicts at the first join, and every candidate bottom offset shifts. On
830389960 `native_slots.py` mapped `movement_input` to native 0x18 (2/22 objects at their native
offset). With relocated non-`@N` calls popping 0 it maps 0x28 (13/37).

The work directory's `nref.py` and `ns_fixed.py` carry the fix. The one-line change belongs in
`binary_frames` (`candidate_pop`: `return 0` for a relocated name without `@N`, except `@@QAE`
members).

## 8. Open questions

- Which C2 structure gives a nested-scope escaped local membership in an entry-defined pointer's
  alias class, or keeps a function-scope escaped local out of later calls' alias sets. The candidates
  are `build_block_alias_sets` 0x1071954a, `compute_alias_points_to` 0x10719707 and the call
  alias-set expansion that `frame_predict.py` hooks at 0x93CC0/0x93D2A. Tracing either one on micro
  F1/L5 would settle which of the facts in §5 the model misreads.
- Whether the 16-byte single-object shape in §5 reproduces native's frame. It would still need a cause
  for the movement non-merges.
