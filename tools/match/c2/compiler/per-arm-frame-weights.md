# Per-arm builds, frame weights and slot room (C2.DLL 8966)

This note covers what happens to the stack frame when a call's argument build is repeated in each arm
of an if/else ([arm-local-builds.md](arm-local-builds.md)), and why a new 8-byte aggregate cannot be
added to a packed frame without growing it. The worked case is the movement section of
`player_update` (native 0x413f19..0x414f44). All rules are for `/O2 /GB`; addresses are virtual
addresses in the pinned C2.DLL (image base 0x10700000).

Evidence labels: **Verified** means observed in a compile or a preserving trace. **Read** means taken
from the notes cited. **Inferred** means consistent with every compile below but not traced.

See also [frame-model.md](frame-model.md) (reference counts, list order, packing),
[frame.md](frame.md) §1.3, [arm-local-builds.md](arm-local-builds.md) (the mod-3 rotation rule),
[x87-memory-values.md](x87-memory-values.md) (the turn pair) and
[aggregate-temporaries.md](aggregate-temporaries.md) §6 (`cross_jump_pair` profitability).

## 1. Summary

1. **Every per-arm copy is weighted before it is merged.** `count_stack_object_references`
   0x10733e75 runs in the stack-layout pass, before both jump-optimizer runs ([frame-model.md](frame-model.md) §2).
   A build that jump optimization later merges down to one call still counts once per arm.
   Moving `pu_move_scaled(&v, ...); call(..., &v)` from after an if/else into both arms adds the
   second copy's `lea` and two field stores: **+3** on `v`. Splitting a shared `call(..., &v)` whose
   stores were already per arm adds only the second `lea`: **+1**. [Verified]
2. **Equal weights keep the object that reached the count first.** In a tie the object whose last
   reference comes earlier in block-list order stays ahead ([frame-model.md](frame-model.md) §2 list
   rule). In `player_update` `scratch_pos` (last reference line 1776) beats `move_delta` (1842). [Verified]
3. **Rotation registers of later arms depend on every integer temp in between.** When a per-arm
   build is added below a block whose integer temps differ from native, the new copies take the
   wrong rotation registers ([arm-local-builds.md](arm-local-builds.md) §1, mod-3 rule), and an arm
   whose registers equal an earlier arm's is cross-jumped whole into it. The fix is in the block
   above the arms, not in the arms. [Verified]
4. **A new 8-byte local defined in the arms always grows a 4-byte slot.** Every function-scope
   aggregate whose later accesses are field stores is live through the arms, and so is any aggregate
   saved before and read after them. The new object conflicts with all of them. When no slot of 8
   bytes or more is free of conflicts, it joins a 4-byte slot, which grows by 4
   (`join_or_create_stack_slot` 0x1074bae6, size rule `size <= 2 * slot size`). [Verified by
   replay; the partial-definition liveness rule is **inferred**, see frame.md's open question on
   0x1074b45e]
5. **An address-taken existing vector is a free weight lever.** Storing a temporary pair in an
   aggregate that is already address-taken and dead at that point costs no slot and adds its
   stores and reloads to that aggregate's weight (+5 per arm for the turn pair). [Verified]

## 2. Weight arithmetic for `player_update`

Correction ([pu-residual-map.md](pu-residual-map.md)): native has no separate 8-byte slot at 0x40; 0x38 is one 16-byte slot.

Baseline 5436cf105: 8-byte list `movement_input` 185, `scratch_pos` 161, `move_delta` 159,
`random_offset` 139. In an FPO frame without a density sort the 8-byte slots take list order from the
lowest address: b0x28, b0x30, b0x38, b0x40 (native uses the same four addresses).

| Change | Weight effect | Result |
|---|---|---|
| demo build + call in both arms | `move_delta` +3 → 162 | 162 > 161: slots 9 and 10 swap, every later `[esp+x]` of both vectors moves |
| mode 3 call in both arms | `move_delta` +1 → 160 | order kept |
| both | `move_delta` 163 | swap |
| demo head: `movement_input = scratch_pos;` in each inner arm | `scratch_pos` +2 → 163, `movement_input` +2 | with both builds: 163 = 163, tie kept by rule 2 |
| turn pair stored in `scratch_pos` in the four accel arms | `scratch_pos` +20 → 183 | order kept with margin 20 over `move_delta`, 4 under `movement_input` |
| mode 4 builds in `move_delta` (native b0x38) | `move_delta` +6, `movement_input` −6 | needs `scratch_pos` ≥ 169 and `movement_input` ≥ `scratch_pos` |

To predict, count the references of each copy in source, add them per copy, and compare against the
neighbour in the same size group. `scripts/c2/frame_predict.py` prints the compiler's weights.

## 3. Why the 8-byte turn pair does not fit (rule 4)

`scripts/c2/slot_scan.py` on the block-scoped turn in the mode-2 arm (`t_m2`):

```
_turn size=8 weight=3: slot 11 conflicts=['_random_offset']
_turn size=8 weight=3: slot 10 conflicts=['_move_delta']
_turn size=8 weight=3: slot 9  conflicts=['_scratch_pos']
_turn size=8 weight=3: slot 8  conflicts=['_movement_input']
_turn size=8 weight=3: slot 7  conflicts=['_previous_pos']      (4-byte temps slot grown to 8 by previous_pos)
_turn size=8 weight=3: slot 6  size=4 no conflict -> joins, grows by 4   (local bytes 0x46 -> 0x4a, frame 0x4c)
```

A function-scope turn aggregate (`t_fs`, weight 12, so it is placed before `previous_pos`) joins
slot 7 instead (+4), and `previous_pos` then conflicts with it and opens a new 8-byte slot (+8):
local bytes 0x4e, frame 0x50, 59.72%. [Verified] Only one slot of 8 bytes or more is free of the
vectors, and two mutually conflicting 8-byte objects need it. So the pair fits only if 4 bytes are
freed elsewhere in the frame or `previous_pos` stops being live across the arms.

Native pays the same +4 in a different place: its M lives at b0x10, in the 4-byte slot that holds
the modes' `movement_heading`, and b0x14 (the second field) has no reference in the movement
section. Native has three plain 4-byte slots below it (b0x04, b0x08, b0x0c) where the candidate
has five (b0x04..b0x14), which is where native's 4 bytes come from. [Inferred from esp-tracked
native references]

## 4. Acceptance tests

Copies of 5436cf105's scratch. Score is whole-function, refs are ok/unresolved/mismatch. Predictions
were written before each compile (`predictions.md` in the work dir).

| Variant | Prediction | Observed |
|---|---|---|
| base | – | 70.35%, 799/0/2 |
| d1: demo build + call per arm | 162 > 161, slots swap | swap; 63.83%, 778/0/11 |
| m3: mode-3 call per arm | 160, no swap | no swap; 70.33%, 795/0/5 |
| dm3: both | 163 > 161, swap | swap; 64.13%, 777/0/13 |
| m4a: mode-4 key block via `player_update_vec2_set` | `scratch_pos` +1 | **wrong**: weight unchanged (the extra native load is not a separate tuple here); 70.38%, 795/0/6 |
| C2 (test-only weight compensation outside the movement section) | no movement change | 70.30%, 799/0/2 |
| C2 + dm3 | order kept; demo registers still off | order kept; demo accel arm cross-jumped whole into mode 3's accel copy; 70.12%, 791/0/5 |
| C2 + dm3 + 1 / 2 dummy int temps at the head of the demo accel arm (control) | 2 temps shift the demo copies to native's (edx,eax)/(ecx,edx) | 1 temp: 70.22%, 801/0/3. 2 temps: native demo registers, mode-4 accel merges into the demo decel tail as in native; 71.08%, 814/0/4 |
| dm3 + h6 (per-inner-arm struct copy in the demo head) | +2 `scratch_pos`, tie keeps order; rotation as the 2-temp control | 163 = 163, order kept; demo decel `lea ecx`/`mov edx`, heading push `eax`, perk load `ecx`, as native; 71.15%, 814/0/4 |
| dm3 + h6 + decel arms of modes 4 and 3 as `pu_move_scaled` | native decel x87 | 70.72%, 812/0/2 |
| same + turn pair in `scratch_pos` (4 accel arms) | +20 `scratch_pos`, no slot | 183/163, frame 0x48; **71.95%, 816/0/1** |
| same with `movement_input` or `random_offset` as the pair | same code, different weights | identical object score 71.95%, 816/0/1 |
| block-scoped turn (native x87) | +4 frame | frame 0x4c, 62.07%, 798/0/2 |
| function-scope turn (native x87) | joins slot 7, `previous_pos` needs a new slot | frame 0x50, 59.72%, 738/0/15 |
| negative: `(vec2 *)&move_delta.x` at the call, or an inline returning `v` | a distinct IL operand | byte-identical object |

On origin/master e3194a49e (fire section retuned) the same movement diff gives 70.49% → 72.09%,
818/0/1, with the same four weights.

## 5. How to predict from source

1. For each per-arm copy you add, add its frame references (lea, stores, reloads) to the vector's
   weight. Compare with the neighbours of the same size; a tie goes to the one whose last reference
   is earlier in the function.
2. If the order would change, move weight with native-shaped per-arm code above the arms (each
   per-arm copy counts), or store a dead temporary pair in an already address-taken vector.
3. Check the rotation registers of the new copies against native. If an arm has the same registers
   as an earlier arm with the same tail, the whole arm is cross-jumped; fix the integer temps of the
   block above.
4. A new aggregate in the arms needs a slot of at least its size with no conflicting member. Use
   `slot_scan.py --match <name>` to list the conflicts before compiling.

## 6. Tools

```sh
uv run python scripts/c2/slot_scan.py <scratch> --out <new dir> --match '_turn|_previous_pos' [--source v.cpp]
uv run python scripts/c2/frame_predict.py <scratch> --out <new dir>     # weights, slots, offsets
```

## 7. Open questions

- Native keeps the mode-3 decel arm and the demo accel arm apart although both end in
  `mov eax,[idx]; push eax; fstp; fstp; jmp call` with (edx, eax), and likewise mode-4 decel and
  mode-3 accel with (eax, ecx). The candidate merges the first pair (`cross_jump_pair: MERGED`,
  `il_stage_trace.py --preset jumpopt`). By [aggregate-temporaries.md](aggregate-temporaries.md) §6
  the native IL must differ at jump-optimizer time, or the running byte sum of the tail must land
  on exactly 20. The pre-schedule tail `push; mov r,[idx]; push esi; push; lea; fstp; fstp` sums to
  20 only if `mov eax,[abs]` is sized 5; the candidate merged, so C2's size estimate or the tuple
  order differs. Not traced.
- The partial-definition liveness rule (a field store never kills its aggregate, 0x1074b45e) is
  inferred from the conflicts, not traced.
