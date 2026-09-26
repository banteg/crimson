# player_update: an id-delta profile of every id-ordered decision (C2.DLL 8966)

[tu-prelude.md](tu-prelude.md) showed that `player_update`'s residual orderings are keyed by C2's per-function
counters, not by frontend ids. This note lists every decision in the function that a counter id decides. For each
one it gives the counter, our id, and the id condition that native's listing needs. It then reads the profile for
steps (places where native must have had extra constructs), and links the steps to the missing alias classes.

All numbers are for `player_update` at cf7f728f3, compiled with the scratch's `/O2 /GB /W3 /GR-`. Base scores:
74.401% raw, 83.764% labels masked, 84.555% structural, 94.109% stack masked, refs 863/0/0. Source lines are
`scratch.cpp` lines; C2 line labels are those minus 141. Evidence labels:

- **verified**: seen in a preserving trace, or by an intervention whose object was matched;
- **inferred**: key arithmetic only (the key model is checked on every operand, see §1);
- **read**: the target listing, read by hand.

## Short answer

1. **The sort ties.** After globopt, C2 sorts 929 commutative nodes. Their operands form 353 adjacent pairs that
   tie on need and size, so an id decides their order. Of these:
   - 120 pairs put an address constant next to a register. The order cannot change code.
   - 233 pairs have 57 deciding ids or nodes (`sites.csv`). Each one was probed by intervention.
   - 21 sites change code when reversed. 11 of them want the reversed order, 9 keep ours and 1 is undecided (verified).
2. **Pool E (value-numbering owners and CSE temporaries) is flat.** Only three pool-E sites change code, and our order
   is native at all three [verified]:
   - the `move_speed` owner: the owner id `n` must satisfy n ≢ 2 (mod 4);
   - a `frame_dt` product temp: C0 + n must avoid a window of width 19 (mod 1024);
   - a pair of CSE-temp squares.

   A shift of 0 satisfies every site, so no pool-E step can be located. The 12 other owner and temp sites have
   no code effect.
3. **Pool B (locals, parts, inline copies) has the steps.** The 11 sites that need the reversed order are
   creation-order sites or squares, not residues:
   - **Four movement arms** (lines 463, 521, 713, 777; 8 lanes): native multiplies the turn factor before `scalar`.
     So native's turn value is a record created after `scalar` (first referenced at line 384). Ours are the early
     parts `movement_input.x` (#28) and `scratch_pos.x` (#18).
   - **Auto-aim** (1030/1036): native's aim-delta `x` is created after `angle_step` (first referenced at line 455).
     Its square sorts above the held `y` copy.
   - **The mode-3 pad square** (505): x² before the held y copy.
   - **Two sites that must keep our order**, which constrain any rewrite: line 929 (`scalar` must stay above
     `movement_input.x`) and line 1865 (`rocket_heading` above `movement_heading`).

   Applying all 11 reversals together by intervention gives 74.536 / 83.922 / 84.712 / 94.218, refs 863/0/0. That
   is the most these sites are worth.
4. **Nothing else in the function is id-ordered in a way that shows:**
   - Sethi-Ullman: no ties (tu-prelude.md).
   - The colouring queue: 159 picks, whose only two full ties are split pieces of one range in disjoint blocks.
     Both get `eax`.
   - SIB base/index: no two-register sum ties.
   - Mod-8 local-base memory leaves (69 pairs) and inline-copy leaves (12 pairs): no code effect.
5. **Construct guesses.**
   - For the movement arms: a turn value first referenced in each arm, and memory resident. In native it lives in
     a 4-byte slot (frame −56), which it shares with the auto-aim distance.
   - For auto-aim: a vector local to that block.

   Both steps add at most about 10 alias classes. They explain the order sites, not the ~200 missing classes.
6. **Constraints on the missing classes, from the flat pool-E profile:**
   - Constructs that add classes without pool-E slots are free at the owner. Examples: dead locals, float
     overloads, formals bound to locals.
   - The same constructs are not free when they open symbol chunks. C0 moves by 32 per chunk. 100 dead locals
     moved C0 by +0x60 and flipped the `frame_dt` window, which changes code (verified, below).
7. **No spelling lands.** Block-scoped turn vectors, `movement_heading` or an arm-local float as the turn, a block
   aim vector, and first-reference reorders each fix their order sites but change other code. Every one loses on
   at least one of the four ratios or on refs. So there is no `best.diff`. Under the diagnostic collapse the block
   aim vector gains +0.048 stack-masked with the other ratios and refs unchanged. That is a lead, not a landing.

## 1. Method

### 1.1 Counters

All pools take 32-id chunks from one shared counter (`symbol_alloc` 0x107017eb, class in `ecx`).

| Counter | What takes ids | Leaf key that decides a sort | Period |
|---|---|---|---|
| pool E (class 15) | VN owners and CSE temps, `C0 + n`, never recycled ([cse-slot-count.md](cse-slot-count.md)) | field leaf `[owner+0]`: `0x10007 \| (owner & 3) << 14`; temp symbol leaf: `(id << 6) & 0xffff` | 4; 1024 (C0 moves in 32s) |
| pool B (classes 4/5) | named locals and aggregate parts at first IL reference (reader); inline formal copies (LIFO free list) | local leaf `id << 5` (id < 0x800; above that, `((id & 0x7ff) << 5) ^ 1`); memory leaf through a local base `(id & 7) << 13` | creation order; 8; 2048 |
| squares `t*t` | the squared symbol | `3·H(t) + 0x2a` | as for H |

Two corrections to the pool-B picture came out of this work [verified]:

- **A pool-B record's id is not "previous + 1".** When pool B's chunk is full, the next pool-B record starts a new
  chunk at the shared counter's current value. So 100 dead locals right before `float rocket_heading` moved it
  from #1883 to #3199, not to #1983. They also moved C0 by 3 chunks (+0x60).
- **C0 counts every chunk opened before value numbering, including pool B's.** Pool-B growth anywhere in the
  reader therefore moves every mod-1024 temp window ([cse-id-push.md](cse-id-push.md) §1).

### 1.2 Sites

`scripts/c2/id_delta_profile.py` hooks the call at 0x1070da8d (`compute_tree_cost_and_sort` →
`merge_sort_operand_list`). After `purge_unreferenced_temps` every commutative node is sorted exactly once
(929 nodes, verified). For every adjacent pair whose `key >> 16` (need, size) is equal, the tool:

1. names the deciding id of each leaf;
2. re-derives both keys (it stops if the model disagrees, which it never did on 353 pairs);
3. lists the residues or id windows at which the pair would reverse.

For a pair of squares it finds the child `t*t` node by its key and uses the squared symbol. Pairs where one side is
an address constant or an integer constant are dropped, because such an operand folds into the displacement.

### 1.3 Interventions

The observer changes one decision and the object is matched. This is never match credit.

| Site kind | Intervention |
|---|---|
| pool E | burn M ids right before slot n and the complement to 4 (or 1024) right after it (`n:M,n+1:4−M`), as `cse_slot_trace.py --phantom` does, so only that id's residue moves |
| pool B residue | re-key that symbol's leaves in the post-globopt sort as if it had another id. Burning class-4 records crashes C2 in globopt: all 15 burn probes gave an empty object |
| creation order, squares | swap that one node's pair by key |

The verdict comes first from a data-flow window. Each stack read is renamed by the mnemonic that produced the value
its reaching store wrote, for example `fmul [V=fsub]` against `fmul [V=int]`. An operand swap of two `[esp+x]`
slots is invisible to every masked ratio, but after renaming it is a difference. Without a data-flow difference,
the verdict comes from stack masked, then labels, then raw, then fewer mismatches.

## 2. Site table (code-relevant sites)

The full table is `scratchpad/pu-id-delta-profile/sites.csv` (57 sites). "Probe" is the reversed order.

| Site | Source line | Counter | Our id | Reversed when | Probe: raw / labels / structural / stack, refs, data flow | Native |
|---|---|---|---|---|---|---|
| `move_speed` owner, 33 pairs (22 lanes, move_phase) | VN 457; lanes 463–802 | E owner, mod 4 | 0x1316 = n342, ≡2 | ≡0 | 74.291 / 83.679 / 84.469 / 93.498, 862/0/0, −202 | ours (verified) |
| `frame_dt` product temp #5039 | 566, 577 | E temp, mod 1024 | 0x13af = n495, ≡943 | ≡0..18 (shift +81..+99) | 65.342 / 83.676 / 84.466 / 94.016, 743/0/1, −18 | ours (verified) |
| CSE-temp squares #5129/#5126 | 752 | E temps (192·id+0x2a) | n585/n582 | uniform shift ∈ {1015–1017, 333–335, 674–676} mod 1024 | data flow −15 | ours (verified) |
| dy/dx squares ×3 | 409, 420, 449 | B locals #304/305, #308/309, #313/314 | | dx id < dy id | data flow −15, −15, −4 | ours (verified) |
| `scalar` · turn, lanes ×2 | 463 (mode 4) | B order | #301 vs `movement_input.x` #28 | #301 < #28 | 74.401 / … unchanged, +1 each | **swap** (verified) |
| `scalar` · turn, lanes ×2 each | 521 (mode 3), 713 (mode 2), 777 (demo) | B order | #301 vs `scratch_pos.x` #18 | #301 < #18 | unchanged, +1 each | **swap** (verified) |
| x² vs held y² | 505 (mode 3 pad move) | B square | x #28, y copy #3254 | y copy mod 2048 ∈ {0–27, 683–710, 1365–1393}, or x ∈ {524–682, …} | 74.449 / 83.812 / 84.602 / 94.109, 863/0/0 (registers only) | **swap** (verified) |
| `scalar` vs `movement_input.x` | 929 (aim scheme 4) | B order | #301 vs #28 | #301 < #28 | data flow −2 | ours (verified) |
| x² vs y² | 965 | B square | #28, #30 | | 74.353 (registers only) | ours (verified) |
| aim x² vs held y² | 1030 (auto-aim) | B square | x #28, y copy #3828 | y copy mod 2048 ∈ {0–27, …} (+268 / −387), or x ∈ {415–682, 1098–1364, …} | data flow +5; the probe gives native's `fld [x]; fmul [x]; fld st(1); fmul st(2)` exactly | **swap** (verified) |
| aim x · `angle_step` | 1036 | B order | #316 vs #28 | #316 < #28 | 74.449 / 83.812 / 84.602 / 94.157, 863/0/0, +2 | **swap** (verified) |
| `rocket_heading` + `movement_heading` | 1865 | B order | #1883 vs #315 | key(#1883) < key(#315), that is id ≥ 0x800 with (id & 0x7ff) < 315 | data flow −2 | ours (verified) |
| scalar² vs x² | 921 | B square | #301, #28 | | registers change, no ratio moves | undecided |

No code effect (verified), grouped by counter:

- **pool E owners/temps**: n9 (66 pairs, `player_position + 4`), n36, n71, n99, n105, n201, n222, n382, n473, n628,
  n647, n795.
- **pool B residues**:
  - `player_position` #14 (mod 8, 67 pairs). Also a source-level check: 2 + 6 dead locals around its declaration
    move it to #16 ≡0 and flip all 67 pairs, and the object is byte-identical.
  - `auto_aim` #1387 (mod 8).
  - 20 inline-copy leaves of `pu_move_scaled` and the setters (mod 2048).
- **pool B order**: the `movement_input.y` partners at 933 and 1037.

## 3. The profile

### 3.1 Pool E: flat

In slot order, with native's shift Δ = native id − ours at each site:

| Slot | Line | Allowed Δ |
|---|---|---|
| n342 | 457 | Δn ≢ 2 (mod 4) |
| n495 | 575 | ΔC0 + Δn ∉ [81, 99] (mod 1024) |
| n582/n585 | 752 | ΔC0 + Δn ∉ {1015–1017, 333–335, 674–676} (mod 1024) |

- **The minimal consistent sequence is Δ = 0 everywhere.** No step is forced, so the pool-E profile says nothing
  about where native's extra constructs sit. It says only that they total Δn ≢ 2 (mod 4) of pool-E slots before
  line 457, and avoid the two windows.
- **Verification by source** [verified]:
  - Two parenthesized float stores before line 457 (`k7x2`, +2 FROUND slots) give a candidate listing identical to
    the `E:342:2` phantom.
  - Three (`k7x3`) give an object identical to base.
  - A struct copy for two stores (`k8`, +2) gives the same object as `k7x2`.
  - 100 dead locals before `rocket_heading` (`rk100`) move C0 by +0x60. That puts #5039 at ≡15, and the listing is
    identical to the n495 +81 phantom.

### 3.2 Pool B: steps

Correction ([pu-residual-map.md](pu-residual-map.md)): the −56 slot belongs to the later `scalar`; the −60 "scalar" is the movement speed factor, a separate variable.

| Step | Where native had something we lack | Evidence | What it must be |
|---|---|---|---|
| B1 | each of the four movement arms, between `scalar`'s first reference (384) and the lanes (463, 521, 713, 777) | 8 lane nodes, data flow +1 each | the turn factor (π − `angle_step`) in a record created after `scalar`. The target stores it (`fstp [esp+0x20]`, frame −56) and reloads it twice as a memory operand. `scalar` is at frame −60 |
| B2 | the auto-aim block, after `angle_step`'s first reference (455) | lines 1030 and 1036 | the aim-delta vector's `x` created after `angle_step`, with a key above the held `y` copy's square. The target's vector is at frame −32, the slot of our `movement_input` |
| B3 | between the mode-3 expansion (505) and the auto-aim expansion (1030) | two square sites | no single shift of the inline-copy ids satisfies both windows: #3254 needs {+159…+187, …}, #3828 needs {+268…+296, …}. A step of ≥ 81 inline ids between them would, or an `x` record in 524–682 (mod 2048) for both. The latter conflicts with line 929 unless the vectors differ [inferred] |
| keep | 929 | data flow −2 | the pad-aim vector's `x` stays older than `scalar` |
| keep | 1865 | data flow −2 | `rocket_heading`'s id must stay out of [0x800, 0x93a] (mod 0x1000), where its key drops below `movement_heading`'s (#315). The diagnostic inflater (207 `pu_diag_id` calls) puts it at #2075 and reverses this fadd; the collapsed profile flags it (+480 restores it) [verified] |

A **shift model** does not fit B1 and B2. The required moves are +274..+284 ids for a record that exists in the
reader's first chunk, so the native record is a different, later record. The target's slot map agrees:

- the turn has its own 4-byte slot, frame −56, which the auto-aim distance also uses (`fst [esp+0x20]` after the
  auto-aim `fsqrt`);
- `scalar` is at −60, a slot shared with `rocket_heading`;
- the blood splatter and the zeroed movement vector use frame −24;
- the Fire Cough `vec2_sub` destination is at −48, a different object from ours (`scratch_pos`, −24).

### 3.3 Construct costs

Measured by the tool's census. ΔE counts pool-E slots before the `move_speed` owner. The code column compares with
the base object.

| Construct | ΔE before n342 | ΔB (stage) | Δ alias classes | ΔC0 | Code |
|---|---|---|---|---|---|
| dead `int` local, function scope (`k1`) | 0 | +1 reader | +1 | 0 | identical |
| `{ float t = expr; use(t); }`, first local in a block (`k3`) | +1 (its FROUND) | +1 reader | +2 | 0 | identical |
| parenthesized float store (`k7`) | +1 | 0 | 0 | 0 | identical; ×2 flips the lanes, ×3 identical |
| `(float)sin(e)` for `sinf(e)` (`k10`, the float overload reversed) | 0 | −1 inline | −2 | 0 | identical |
| `player_update_vec2_set` for two stores (`k5`) | +2 | +3 inline | +3 | 0 | owner ≡0: lanes flip |
| struct copy for two stores (`k8`) | +2 | 0 | 0 | 0 | same object as `k7x2` |
| `v = vec2_t(x, y)` (`k6`) | +3 | +1 reader, +6 inline | +5 | +0x20 | changes |
| 100 / 200 dead locals at line 1855 (`rk100`, `rk200`) | 0 | +100 / +200 reader | +100 / +200 | +0x60 / +0xe0 | `rk100` flips n495; `rk200` identical |
| block `vec2` turn in one arm (`s1_a`) | 0 | +5 reader, +1 inline | +2 | +0x20 | changes |
| block aim vector (`s2a`) | 0 | +5 reader, +1 inline | +1 | +0x20 | changes |
| `movement_heading` as the turn, one arm (`s3_a`) | 0 | −3 inline | −2 | 0 | changes |
| diagnostic `pu_diag_id` ×207 | −1 | +414 inline | +414 | +0x60 | collapse |

A construct explains a step only if it moves every counter as required:

- **B1 needs one later pool-B record per arm and no pool-E change before line 457.** An arm-local float or vector
  qualifies for the counters: ΔE 0 before the owner, ΔB ≥ 1, Δalias +1 or +2. But C2 keeps a fresh arm-local
  float on the x87 stack (`fmul st(1)`), while native stores and reloads it. The order is then native, and the x87
  shape is not.
- **B2 needs a later aim vector.** `s2a` gets line 1036 exactly (`fld [x]; fmul st(1)`). It does not get the 1030
  square, and its slot comes out at −48 instead of −32. This is the function-scope-against-block conflict of
  [slot-sharing-symbols.md](slot-sharing-symbols.md) §4.
- **The alias link.** B1 and B2 add at most about 10 classes (4 arms + 1 block, at 1 or 2 each). The rest of the
  missing classes must come from constructs that keep:
  - the pool-E count before line 457 in {0, 1, 3} (mod 4);
  - the n495 and n582/585 windows clear;
  - `rocket_heading`'s id out of [0x800, 0x93a] (mod 0x1000).

  Dead or bound-to-local locals and float overloads add classes with ΔE 0. But each 32 pool-B records opens a chunk
  and moves C0 by 32, and exactly +3 chunks with Δn = 0 hits the n495 window.

## 4. Spellings tried

Every variant was scored against cf7f728f3. The arm letters are a = mode 4 (463), b = mode 3 (521),
c = mode 2 (713) and d = demo (777).

| Variant | Raw | Labels | Structural | Stack | Refs |
|---|---|---|---|---|---|
| base | 74.401 | 83.764 | 84.555 | 94.109 | 863/0/0 |
| `s1` block `vec2 turn`, arms a / b / c / d / all | 74.332 / 65.533 / 74.284 / 74.347 / 65.332 | 83.723 / 75.257 / 83.675 / 83.737 / 75.090 | 81.159 / 76.240 / 84.465 / 84.527 / 72.836 | 93.975 / 94.132 / 93.951 / 94.012 / 93.743 | 862 / 841/0/2 / 861 / 862 / 837/0/2 |
| `s3` `movement_heading = π − angle_step` as the turn, arms a / b / c / d / all | 74.332 / **74.413** / 74.308 / 74.347 / 74.245 | 83.723 / **83.781** / 83.699 / 83.737 / 83.645 | 81.159 / **84.571** / 84.489 / 84.527 / 84.436 | 93.999 / 94.058 / 93.975 / 94.012 / 93.717 | 862 / 862 / 861 / 862 / 858 |
| `s4` arm-local `float turn`, arm d / all | 74.347 / 74.245 | 83.737 / 83.645 | 84.527 / 84.436 | 94.012 / 93.717 | 862 / 858 |
| `s2a` block aim vector | 73.997 | 83.387 | 84.298 | 94.047 | 858/0/0 |
| `v1r` blood splatter into `random_offset` | 74.306 | 83.669 | 84.459 | 94.109 | 863/0/0 |
| `v2r` = `v1r` + arm a turn in `scratch_pos` | 74.177 | 83.563 | 84.353 | 94.002 | 863/0/0 |
| `v3r` = `v2r` + `s2a` | 73.901 | 83.291 | 84.202 | 94.047 | 858/0/0 |
| `v1`/`v2`/`v3` block-scoped blood vector | 65.668 / 65.668 / 65.54 | 75.395 / 75.395 / 75.27 | 76.378 / 76.378 / 76.372 | 93.939 / 93.939 / 93.937 | 837/0/2, 837/0/2, 832/0/2 |
| upper bound: the 11 reversals by intervention | 74.536 | 83.922 | 84.712 | 94.218 | 863/0/0 |

In the zero-mismatch rows, "862" means 862/0/0 and "861" means 861/0/0.

- `s3_b` gains on raw, labels and structural (+0.012, +0.017, +0.016) but loses 0.051 stack masked and one ok
  reference. It is not an improvement.
- **Collapsed regime** (+207 `pu_diag_id`, first pointer class 1023):

  | Build | Raw | Labels | Structural | Stack | Refs |
  |---|---|---|---|---|---|
  | base | 66.045 | 75.699 | 76.703 | 94.456 | 837/0/2 |
  | `s2a` | 66.045 | 75.699 | 76.703 | **94.504** | 837/0/2 |
  | `s3_b` | 66.077 | 75.711 | 76.715 | 94.406 | 836/0/2 |
  | `s4` | 65.901 | 75.568 | 76.573 | 94.066 | 831/0/4 |

  The collapsed profile (`sites_inf207.csv`) has the same B1/B2 sites. It adds the `rocket_heading` wrap caused
  by the inflater. Its owner is n341 ≡1, still native.

## 5. Acceptance tests

Predictions are in `scratchpad/pu-id-delta-profile/predictions.md`, written before each compile.

| Test | Prediction | Observed |
|---|---|---|
| T1 `k7x2`: two parenthesized float stores before 457 | owner n344 ≡0; the listing equals the `E:342:2` phantom; 74.291 / 83.679 / 84.469 / 93.498, 862/0/0 | identical listing (hash 95a726ca25f0), same scores ✔ |
| T2 `k7x3` (negative control) | owner ≡1, object identical to base | identical ✔ |
| T3 `rk100`: 100 dead locals before `rocket_heading` | `rocket_heading` about #1983 < 0x800, object identical | **✗**: `rocket_heading` #3199 (new pool-B chunk at the shared counter). C0 +0x60 put the n495 temp at ≡15 and flipped that window; the listing is identical to the n495 +81 phantom. Explained by the corrected chunk rule (§1.1) |
| T4 `rk200` | `rocket_heading` ≥ 0x800 with (id & 0x7ff) < 315: rocket fadd flips | **✗**: #3299, (id & 0x7ff) = 1251 ≥ 315, and C0 +0xe0 misses the window: object identical to base. Explained by the same rule |
| T5 re-key `rocket_heading` to 2403 / 2075 | 2403: identical to base; 2075: the same object as the node-861 swap | ✔ / ✔ |
| B14 pads (2 + 6 dead locals around `player_position`), predicted from its override probe | 67 pairs flip, no code change | trace shows #16 ≡0 and the flips; object identical ✔ |
| negative control: every pool-E owner/temp site except n342, n495 | no code effect | 12 of 12 unchanged objects ✔ |

## 6. Tool

```sh
uv run python scripts/c2/id_delta_profile.py <scratch-dir> --out <new-dir> --ties
uv run python scripts/c2/id_delta_profile.py <scratch-dir> --out <dir> --probe --csv sites.csv [--jobs 8] [--pools E,B,O]
uv run python scripts/c2/id_delta_profile.py <scratch-dir> --out <dir> \
    --phantom E:342:2,E:343:2        # pool-E burns: 2 before fresh slot 342, 2 before 343
    --phantom O:1883:2075            # re-key symbol #1883 as #2075 (optionally :NODE)
    --phantom K:460:0x12780:0x1037f  # at sorted node 460, give the operand keyed 0x12780 the key 0x1037f
```

A trace takes about 6 s. `--probe` on `player_update` runs 59 interventions in about 2 minutes with 8 jobs. The
report and CSV list per site:

- the counter, id and residue;
- the first source line and the value-numbering line;
- the pairs, the reversing residues or windows, and the nearest shifts;
- each probe's four ratios, refs and data-flow delta;
- the verdict.

## 7. Open questions

- Why native stores the turn (frame −56) while C2 keeps every arm-local spelling on the x87 stack.
  [x87-spills.md](x87-spills.md)'s scores and nesting test decide it; `x87_alloc_trace.py` on `s4_d` would show
  which one.
- The inline-copy ids of the held `y` lanes (#3254, #3828) come from pool B's LIFO free list. A shift model for
  them is approximate; the free-list history that native's extra expansions would produce was not replayed.
- Line 921 (scalar² vs x²) changes only registers; no ratio or data-flow window decides it.
- Whether the missing classes open whole symbol chunks in the reader. This decides C0, and so the n495 and
  n582/585 windows.
