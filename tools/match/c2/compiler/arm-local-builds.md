# Per-arm argument builds that share only the call (C2.DLL 8966)

This note explains a native shape in which both arms of an if/else build the same call's arguments,
and only the call itself is shared:

```
accel:  ... lea edx,[esp+0x48]; push edx; push esi; ... mov eax,[idx]; push eax; fstp; fstp
        jmp L_call
decel:  ... lea ecx,[esp+0x48]; push ecx; push esi; ... mov edx,[idx]; push edx; fstp; fstp
L_call: call player_apply_move_with_spawn_avoidance
        ...shared code after the if/else...
```

It also explains how to predict from source when two copies of a call sequence stay apart. Addresses
are virtual addresses in the pinned C2.DLL (image base 0x10700000). All rules are for `/O2 /GB`.

Evidence labels:

- **Verified** means observed in a compile, or in a preserving `il_stage_trace.py --preset jumpopt` trace.
- **Read** means taken from the static notes cited.
- **Inferred** means the rule fits every compile below, but the C2 code for it was not traced.

See also [layout.md](layout.md) §1 (the cross-jump functions), [regalloc.md](regalloc.md) §4 (local
rotation), [value-threading.md](value-threading.md) (the arm order that `player_update` needs), and
[x87-held-lanes.md](x87-held-lanes.md) §5 (where the push instructions land).

## 1. Summary

1. Write the build and the call in **each arm**. Do not write one shared call after the if/else. Each arm then
   ends in `...; push; call; add esp,N`.
2. **The call is always merged.** The first arm ends with `jmp JOIN`, and the last arm falls into JOIN.
   `cross_jump_into_fallthrough` 0x1073d701 (jump_optimize #2, 0x107584a9) matches backward from the
   jmp against the fall-in path. It has **no size threshold**, so it deletes the first arm's copy of the
   common tail and retargets its jmp into the second arm's copy. [Verified]
3. **How far the merge reaches depends on the registers, not on byte counts.** Jump optimization runs after
   register allocation and before scheduling. `tuples_equal` 0x1073d365 compares register operands, so the
   match stops at the first tuple whose temp got a different register.
   - Under /Ot, local temps take eax, ecx, edx from a **rotating cursor** that is reset once per function
     (0x1073375e, selector 0x1073c97c; [regalloc.md](regalloc.md) §4).
   - The two copies of `lea r1,[vec]; push r1; push esi; mov r2,[idx]; push r2` therefore get
     different registers unless the cursor has advanced by a multiple of 3 between them. [Verified by the
     controls in §3]
4. **Rule.** Let k be the number of rotation picks from the first copy's first temp to the second
   copy's first temp, in layout order. That is 2 for the copy's own two temps, plus every
   rotation-allocated integer temp placed between the two copies.
   - If **k mod 3 ≠ 0**, the copies differ at their last `push`. Only `call; add esp,N` merges, which is
     native's shape.
   - If **k mod 3 = 0**, the copies are identical and the whole common tail merges: pushes, the vector
     build, and the dy store when nothing follows it. That is the old shared shape again, with the build
     now physically in the last arm.
5. **Byte thresholds do not decide this case.**
   - The only threshold is the >20-byte rule of `cross_jump_pair` 0x1071dfc6 ([layout.md](layout.md)
     §1). It applies only when two jumps reach a label with no fall-in.
   - Even then, `sink_common_tail_pair` 0x1074d84f runs next and has no threshold. So the call would
     still be merged by some path.
   - What keeps native's builds apart is the rotation.

## 2. Mechanism details

- **Which merge runs.** In `if (c) {A; build; call} else {B; build; call} rest`, the first arm ends in
  `call; add esp; jmp JOIN`, and the second falls into `JOIN: rest`. The label pass cannot sink the tails,
  because JOIN has a fall-in (`sink_common_tails_of_label` needs a jmp or ret before L). The unconditional jump pass
  runs `cross_jump_into_fallthrough` on `jmp JOIN`. Trace of the mode-2 accel `jmp` (tuple 6c25d418, line 610):
  `cross_jump_into_fallthrough: MERGED`. Before the merge its preceding tuples are `lea t(edx); push;
  push esi; mov t(eax),[render_overlay_player_index]; push; call; add esp,12`. The retry after the merge
  shows the call and the add gone. [Verified, `jo_p_ne.txt`]
- **Why the registers differ.** The two copies have the same shape, so the rotation gives the
  first copy (lea, idx) = (edx, eax) and leaves the cursor at ecx. The second copy then gets (ecx, edx). These are
  exactly native's registers at 0x414b72/0x414bc8 and 0x414c05/0x414c48. [Verified]
- **Where the pushes land.** After the merge, each arm's pushes are in the same scheduling window as its
  own trigonometry. So the scheduler places `lea/push; push esi` inside the `fcos` code and `mov r,[idx];
  push r` just before the `fstp` pair, as in native ([x87-held-lanes.md](x87-held-lanes.md) §5).
  [Verified: the mode-2 region is instruction-identical to native apart from frame displacements and the
  turn-scale x87 shape]

## 3. Acceptance tests (player_update, base 8439eb73c, canonical 69.54%, refs 790/0/2)

All variants are copies of the canonical scratch. Only the mode-2 `if (movement_heading ... -1.0f)` block
was changed, unless noted. Predictions were written in `predictions.md` before each compile. Refs are
ok / unresolved / mismatch.

| Variant | Prediction | Observed | Score, refs |
|---|---|---|---|
| b_eq: canonical (`==`, shared build + call) | – | – | 69.54%, 790/0/2 |
| b_ne: `!=`, accel first, shared build + call | – | test kept, native store/jmp shape; 3rd mismatch pairs native `fmul [7.957747]` with our `fmul [25.0]` | 69.61%, 790/0/3 |
| **p_ne**: `!=`, build + call in each arm | I predicted identical registers and a full merge back to b_ne. **Wrong**: I had not accounted for the rotation | only `call; add esp` merged. Accel: `lea edx`/`mov eax`, then `jmp` to decel's call. Decel: `lea ecx`/`mov edx`. Same as native | **70.35%, 799/0/2** |
| p_eq: `==`, build + call in each arm | mover pulls accel up ([value-threading.md](value-threading.md)) | mover shape, registers shifted | 69.42%, 785/0/4 |
| c1: p_ne + 1 int temp at the head of decel (k=3) | same registers, full merge | decel `lea edx`/`mov eax`. Accel ends `fstp [edi+0x20]; fstp st(0); jmp` into decel's `fld dt` | 69.59%, 790/0/3 |
| c2: + 2 temps (k=4) | differ, call-only merge | decel `lea eax`/`mov ecx`, call-only merge | 69.58%, 792/0/6 |
| c3: + 3 temps (k=5) | differ, call-only merge | decel `lea ecx`/`mov edx`, call-only merge | 70.30%, 799/0/2 |
| c4: + 4 temps (k=6) | same registers, full merge | full merge (accel `jmp` before its build) | 69.54%, 790/0/3 |
| c1s: c1's temp with the shared build (control) | no structural change | shared build | 69.62%, 792/0/6 |

The controls' temps are global-to-global `int` copies. They change the program, so they only test the
rule. All four controls matched their predictions, which supports the mod-3 rule.

### Turn pair on top of per-arm builds

The turn pair is [x87-memory-values.md](x87-memory-values.md) §4: `V.x = heading - pi/2; V.y = pi -
angle_step`, used as `cos(V.x) * speed * V.y * scalar * C`.

| Variant | Observed x87 in the accel arm | Score, refs |
|---|---|---|
| t_ne_*: `!=`, shared build, V is an existing function-scope vector (random_offset, previous_pos, scratch_pos, movement_input, xy or yx) | A and M both stored and reloaded (V is address-taken), `fmul [scalar]` before `fmul [M]` | 69.50%, 791/0/3 (previous_pos yx 69.57%) |
| **pt_***: the same V, build + call in each arm | same x87; block structure native | **70.34%, 800/0/2** for all four vectors in either field order |
| pt_move_delta: V = move_delta, the call's own argument | clobbers the argument | 64.37%, 785/0/10 |
| k_ne: block-scoped `player_update_vec2_t turn`, shared build | native x87 sequence; frame 0x4c | 61.38%, 781/0/6 |
| pk_ne: block-scoped turn, build + call in each arm | the whole mode-2 region is instruction-identical to native apart from esp displacements; frame 0x4c | 62.11%, 791/0/5 |

The per-arm builds remove the `fmul [7.957747]` mismatch in every variant. The turn pair in an existing
address-taken vector adds one resolved reference, but costs 0.01% against p_ne, because its x87 sequence
is not native's. Native's x87 needs a non-address-taken aggregate, and that aggregate costs a frame slot.

## 4. How to predict from source

1. Find the calls whose argument pushes native repeats per arm, followed by a shared `call` reached by `jmp`.
   Write the argument setup and the call in each arm.
2. Order the arms so that the jumping arm comes first and the arm that falls into the join comes last.
   If value threading is involved, also follow [value-threading.md](value-threading.md) (the arm the
   constants select goes first).
3. Count the rotation picks between the two copies' first register temps. Count each copy's own
   `lea`/`mov` temps (not esi/edi/ebx globals) and every other integer local temp in between, in layout
   order. x87 values, `fnstsw ax` and immediates take no picks. If the count is not a multiple of 3,
   only the call merges.
4. The registers themselves then follow from the cursor. In native, the cursor position also
   determines the registers of every later local temp.

## 5. Other arms of player_update (leads, not verified as fixes)

- Native builds the vector in 11 places. Modes 4 and 3 and the demo accel arm `jmp L186c`, the demo
  decel arm's call. Mode 1 uses L1188, and mode 2 has its own L15a7.
- Moving the call into both **demo** arms on top of p_ne gives 63.83% (778/0/11). frame_predict shows
  the frame slot order changes, and every later esp displacement shifts. Moving it into both **mode 3**
  arms gives 70.33% (795/0/5). Native's mode 3 arms jump into the demo's call, which needs the
  cross-arm fall-in path, not a mode-local join.

## 6. Tools

```sh
uv run python scripts/c2/il_stage_trace.py <scratch copy> --out <new dir> --preset jumpopt [--context 40]
```

This lists every `cross_jump_into_fallthrough`, `cross_jump_pair` and `sink_common_tail_pair` attempt
with its verdict and the tuples before the jump. Operands print as `#tmp @#r` with the assigned
register, so a mismatched push register is visible directly. C2 line labels are offset from
scratch.cpp lines (+140 here). Find a region by one of its constants, e.g. `=1078530011` for 3.1415927f.

## 7. Open questions

- Whether a `lea t,[esp+N]` def ever takes a preference instead of a rotation pick. The regalloc note
  lists `lea t,[base+disp]` as a preference source. Here the lea temps took rotation registers, which
  suggests an esp base is excluded. Not traced.
- The exact tuple where `cross_jump_into_fallthrough` stopped in the full-merge controls. The report
  shows the jump's context but not the match length. The final listing puts the retargeted jump just
  before `fld dt`.
