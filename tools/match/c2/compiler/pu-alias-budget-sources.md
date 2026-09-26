# Where `player_update`'s missing alias classes come from (C2.DLL 8966)

[unfolded-field-pointers.md](unfolded-field-pointers.md) showed that native `player_update` is over the
0x400 alias-class budget and that our source is about 510 symbol-level classes short. This note answers
three questions:

1. Which C2 counters make up those classes.
2. What each plausible source construct costs.
3. Which constructs a 2003 Crimsonland programmer would plausibly have written, and how far they get.

Addresses are C2.DLL virtual addresses (image base 0x10700000). Evidence labels:

- **verified**: seen in a compile or a preserving trace;
- **measured**: a class count from a compile;
- **read**: static reading only;
- **inferred**: consistent with every compile, but not traced.

All scores are for `player_update` at 52ef72f3d with `/O2 /GB`. The collapsed-regime scores use a
code-free inflater (`pu_diag_id`, 2 classes per call), which is a diagnostic only.

## Short answer

1. **The class count has three parts** [verified]:
   - one class per lexical scope that still holds a symbol;
   - one class per root symbol: a named local, an inline parameter or local that survives, or a global;
   - one class per pointer root, numbered after all symbols.

   Our base has 150 scope markers, 361 symbol classes and a first pointer class of 515. Every pointer
   root collapses only when that first pointer class reaches 0x400, so the budget is short by 509
   classes.
2. **The source family is the 2003 SDK's `vec2_t` value style.** The authenticated MOD SDK header
   `cl_mod_sdk_v1/cl_crimsonroks/src/cltypes.h` defines it: vector temporaries returned by value, float
   math overloads and small reference helpers. Under full collapse these spellings reproduce native
   shapes that no pointer spelling reaches:
   - the y-first muzzle build written straight into the pushed temporary;
   - separate objects for each movement arm;
   - the Alternate Weapon swap with native's weapon-id `lea eax,[edi+0x2c0]` and its `mov ecx,<shot
     cooldown ptr>` copy.
3. **How far natural constructs get: +307 of the 509 classes (first pointer class 822).** Nothing
   collapses at that count, so no budget feature appears from source alone. The best natural set with a
   102-call inflater scores 67.02% raw, 96.33% stack-masked and 859/0/4 refs. The pure-inflater
   control scores 66.28%, 93.96% and 839/0/2. The last 202 classes are not identified.
4. **One small change can land today** ([§6](#6-landable-change)):
   - the SDK `vec2_t` shell;
   - the C++ float math overloads (`cosf`, `sinf`, `sqrtf`, `atan2f`);
   - the muzzle pointer declared at first use.

   It raises the score from 74.36% to 74.40%, with 863/0/0 refs, and adds 94 classes (first pointer
   class 609).

## 1. The counters

### 1.1 Scope markers

`compute_alias_classes` 0x10718eaf sets `g_alias_class_count = count_tuples_and_scan_calls(first) + 3`
(0x10718ef9). `count_tuples_and_scan_calls` 0x107190b8 returns 1 plus the number of tuples that have all
of the following [read]:

- type 0x16;
- opcode 0x1b4;
- a non-null payload at +0x14 (`inc [esp+0x10]` at 0x107191a1).

The same function counts real tuples, and above 0x2710 it forces the coarse alias fallback. Our
`player_update` has 4,769 real tuples, so that fallback is not in play [verified].

The census below walks the tuple list at the hook [verified]:

| Variant (10 copies each) | Markers | First symbol class |
|---|---|---|
| base | 150 | 154 = 150 + 1 + 3 |
| `{ int a = crt_rand(); ... }` block with one local | 160 | 164 |
| same block with two locals | 160 | 164 (+2 symbols) |
| the same local at function scope (no braces) | 150 | 154 |
| `idf(i)`: an inline body with a local `t` | 160 | 164 |
| `vinl()`: an inline body with no surviving symbol | 150 | 154 |
| `cv2 t(frame_dt, 2.0f)` in a block (block + ctor body) | 170 | 174 |

So each lexical scope, whether a block or an inlined body, costs one class **if a symbol survives in
it**. The function scope is free. The marker is presumably C1's block-begin record, which carries the
scope's symbol list [inferred].

### 1.2 Symbol classes

`assign_symbol_alias_classes` 0x1071921c numbers every root symbol after the markers [read, already in
[unfolded-field-pointers.md](unfolded-field-pointers.md)].

In the base, the 361 symbol classes split as follows [verified]:

- 101 named locals;
- 199 unnamed temporaries, which are inline formals that survived (164 of them come from the 82
  `player_update_vec2_set` calls);
- 61 referenced globals.

### 1.3 Pointer roots

Pointer roots follow in IL order. `player` is the third root, so it collapses only when
`markers + symbols + 3 + 2 >= 0x400`. The late roots are:

- `mouse_screen` and `stick_screen`;
- `auto_aim`;
- `shot_cooldown`;
- `weapon_id` and `reload_timer`.

They also count the roots and fresh "unknown source" classes before them. That includes inline pointer
formals, such as `pu_move_scaled`'s `m`, which is one root per call.

## 2. What constructs cost (measured, class deltas)

| Construct | Classes | Code |
|---|---|---|
| named local at function scope | 1 | – |
| first named local in a block | 2 (marker + symbol) | – |
| inline call, no surviving symbol (`vinl()`, a constant argument, or a formal bound to a local or an address constant) | 0 | – |
| formal bound to a global, a field or an expression that survives (`cosf(frame_dt)`, `cosf(x - 1)`, `cosf(p->heading)`) | 2 (marker + formal) | identical |
| `cosf(local)` | 0 | identical |
| `finl(a) { return a + 1; }` with a single-use formal in arithmetic | 0 | – |
| `player_update_vec2_set(&v, x, y)` (free) or `v.set(x, y)` (member) | 3 each | identical to each other |
| `&(a + *p)`: member `operator+` temporary passed by address | 5 (+2 over `vec2_set`) | x87 order changes unless collapsed (§3) |
| `v = vec2_t(x, y)` or `v = a + b`: temporary plus copy into a local | 5 (+2) | adds `mov r,[tmp]; mov [dst],r` |
| `&(random_offset - fire_player->position)` (`vec2_length` argument) | +3 over `vec2_set` | – |
| `VEC2_Angle(*p - q)` (inline `atan2f` inside) | about 9.5 per site | nearly neutral when collapsed |
| `template swap(T &a, T &b)` for the 7 Alternate Weapon fields (replaces 9 named locals and pointers) | +25 net | native shape when collapsed (§4) |
| `&(frame_dt * player->movement)` replacing `pu_move_scaled` (10 sites) | +20 net (2 per site) | better when collapsed |
| `x = color_t(r, g, b, a)`, or `effect_color_set(c, r, g, b, a)` with `effect_color_t &` | +2 each | hostile: the constants are no longer stored directly |
| `pu_diag_id(i)` (the diagnostic) | 2 | none |

For the four float wrappers over the whole function (C++ `math.h` inline overloads):

| Wrapper | Calls | Classes | Score (from 74.36%) |
|---|---|---|---|
| `cosf` | 35 | +30 | unchanged |
| `sinf` | 35 | +30 | unchanged |
| `atan2f` | 9 | +24 | unchanged |
| `sqrtf` | 8 | +10 | 74.34% alone, 74.40% with the others |

Per site, the three auto-target `sqrtf(dy*dy + dx*dx)` calls add 0 classes and lose 0.09%. The other
five add 2 each.

## 3. Evidence for the SDK value style

- **The SDK itself.** `cltypes.h` (2003, 10tons) gives `vec2_t` the following members and helpers:
  - constructors;
  - member `operator-` and `operator+` returning by value;
  - `+=`, `-=` and `*=`;
  - free `operator*(v, s)` and `operator*(s, v)`;
  - `VEC2_Dot`, `VEC2_Angle` (`atan2f`) and `VEC2_Normalize` (`sqrtf`);
  - `color_t` with a 4-float constructor.

  Its math uses the `f` overloads throughout.
- **Native Fire Cough.** Native calls the out-of-line subtraction 0x417640 and consumes the result
  through `eax` (`fld [eax]; fld [eax+4]; fxch; fpatan`). That is `VEC2_Angle(a - b)`
  ([vector-return-contract evidence](../../evidence/vector-return-contract-2026-09-08/README.md)).
- **Native aim updates.** The native aim updates build a temporary and copy it with integer moves at
  nine sites (`fstp [tmp]; mov r,[tmp]; mov [edi+0x50],r`). That is `player->aim = vec2_t(...)`.
- **The inline budget does not explain the out-of-line helpers.** `inline_budget_trace.py` shows that
  our function has own size 14,228, a budget of 28,456 and 117 expansions, with none refused. When
  given bodies, `vec2_sub` (size 73) and `vec2_length` (size 43) are inlined at their first sites.
  Callees are visited in IL order, and Fire Cough is the first callee over 0x28. So native's calls are
  not a budget refusal: native defined `vec2_sub` and `vec2_length` out of line [inferred].
- **Collapsed-regime comparison (§4).** Under full collapse, the SDK spellings match native better than
  our hand-tuned pointer and setter spellings. Before the budget is reached they score worse, which is
  why earlier probes rejected them. See `player_update/NOTES.md`, "inlined vector-operator probe ...
  every used form regressed".

## 4. The natural set and what each part does under collapse

Each variant below is built with just enough `pu_diag_id` calls to collapse every root, so the only
difference is the source construct. The reference point is the pure inflater: base + SDK shell + muzzle
move + 256 calls. It scores 66.28% raw, 75.99% label-masked, 76.97% structural, 93.96% stack-masked,
839/0/2 refs, with a 0x4c frame.

| Natural set n7 | Classes added |
|---|---|
| SDK `vec2_t : vec2f_t` shell with operators; muzzle pointer at first use | 0 alone (its default constructor adds 12 once the float wrappers are in; counted in their row) |
| `tmpplus2`: 65 muzzle builds as `&(movement_input + *player_position)` | +130 |
| `aim`: 7 aim/delta assignments as `x = vec2_t(a, b)` | +14 |
| `lensub`: 2 `vec2_length(&(a - b))` | +6 |
| `angle`: 4 `VEC2_Angle(*player_position - q)` | +38 |
| `cosf`, `sinf`, `sqrtf` (with the shell's 12) | +70 |
| `aimop`: `*auto_aim += movement_input * angle_step` | +3 |
| `aimsub_init`: `player_update_vec2_t aim_delta = *target_position - *auto_aim` | +1 |
| `swapT3`: `pu_swap(player->alt_X, player->X)` × 7 | +25 |
| `mvtemp`: `&(frame_dt * player->movement)` × 10 | +20 |
| **n7 total: first pointer class 822** | **+307** |

For the collapsed-regime scores below, n7 needs `pu_diag_id` × 102.

| Build | Raw | Label-masked | Structural | Stack-masked | Refs | Frame |
|---|---|---|---|---|---|---|
| pure inflater (256) | 66.28 | 75.99 | 76.97 | 93.96 | 839/0/2 | 0x4c |
| `tmpplus2` alone (+191) | 64.78 | 74.80 | 75.63 | 95.37 | 844/0/3 | 0x54 |
| n7 (+102) | **67.02** | 75.72 | 76.05 | **96.33** | **859/0/4** | 0x54 |
| n7 without the budget | 59.13 | 68.25 | 69.28 | 87.57 | 823/0/4 | – |

Ablation from n6, which is n7 plus `atan2f` (96.27 stack-masked, 856/0/4). Each row drops one part,
with the inflater re-sized:

| Dropped | Stack-masked | Refs | Verdict |
|---|---|---|---|
| `tmpplus2` | 94.90 | 845/0/5 | strongest native signal |
| `sqrtf` | 95.59 | 855 | keep |
| `lensub` | 95.64 | 855 | keep |
| `cosf` / `sinf` | 95.66 | 855 | keep |
| `mvtemp` | 95.85 | 845/0/5 | keep |
| `muzzle` | 96.00 | 856 | keep |
| `aim` | 96.03 | 862/0/0 (raw 67.73) | mixed: better structure, 4 ref mismatches |
| `swapT3` | 96.14 | 852 | keep |
| `aimsub_init` | 96.22 | 856 | marginal |
| `aimop` | 96.27 | 856 | neutral |
| `atan2f` | 96.33 | 859 | dropping it helps: `atan2f` is left out of n7 |

The velocity temporaries (`&(dir * 25.0f)`, +88), the per-field world clamp helper (+6), `color_t` or
the color setter (+50), and the remaining `vec2_set` sites as constructors (+10) all regress under
collapse. They are rejected. An `owner_id` helper is neutral and adds 0 classes.

### 4.1 The sibling agent's open items

- **The weapon id is folded late: resolved by the swap helper.** With
  `template <class T> inline void pu_swap(T &a, T &b) { T t = a; a = b; b = t; }` called as
  `pu_swap(player->alt_X, player->X)` for the seven fields, the collapsed build emits native's block
  exactly:
  - `mov edx,[edi+0x2c0]; mov ecx,[edi+0x2dc]; lea eax,[edi+0x2c0]; mov [edi+0x2dc],edx; ... mov [eax],ecx`;
  - the reload-timer `lea ecx,[edi+0x2d0]`;
  - the late `mov eax,[eax]` for the reload sound.

  The shot-cooldown field must be passed as `player->shot_cooldown`, not `*shot_cooldown`. Value
  numbering then turns the `b` formal into a register copy of the `shot_cooldown` pointer, as native's
  `mov ecx,ebp; mov edx,[ecx]; ...; fstp [ecx]` does. Ours allocates it as `mov ecx,ebx`, but the
  shape is the same. Before the budget is reached, the same helper costs 0.6% (73.72%, 852 refs),
  which is why the earlier `alternate-weapon-swap-helper` probe rejected it.
- **`aim` against `aim+4`: unresolved.** Native keeps `lea ebp,[edi+0x50]` and addresses y as
  `[ebp+4]`. Every variant keeps a value-numbered `player+0x54` range instead:
  - `vec2_set`;
  - `movement_input = *target_position - *auto_aim`;
  - a block-scoped `aim_delta` initialised from the difference;
  - `*auto_aim += movement_input * angle_step`.

  So native's y accesses go through an object whose address is not forward-propagated into `player`.
  One candidate is an inlined function that receives the aim by reference and holds the whole
  auto-aim block. It is not tested.
- **The muzzle stack slot and the frame: open, narrowed.** With the temporaries, the collapsed frame
  is 0x54, not native's 0x48. [slot-sharing-symbols.md](slot-sharing-symbols.md) §4 explains the
  likely cause. A function-scope, address-taken aggregate (`scratch_pos`, `move_delta`,
  `movement_input`, `random_offset`) conflicts with every block-scoped aggregate, and the temporaries
  are block-scoped. Native's 0x48 therefore suggests that fewer of these vectors were function-scope
  objects [inferred]. Converting the movement arms to temporaries (`mvtemp`) did improve structure,
  which fits that note's "each arm builds into a different object".

## 5. How to predict from source

1. Count the scope markers: one per block or inlined body that keeps at least one symbol.
2. Count the symbols:
   - named locals, globals and class-typed temporaries;
   - inline formals, except those bound to constants, to local variables, to address constants, or
     single-use arithmetic formals.
3. The first pointer class is `markers + symbols + 4`. `scripts/c2/alias_class_census.py` prints the
   parts.
4. Roots collapse when their id reaches 0x400. `player` needs the first pointer class to be at least
   0x3fe; the late roots also count the roots before them.
5. A construct that adds classes without changing code today is a free step towards the budget. A
   construct that changes code must be judged in the collapsed regime, because that is the regime
   native was compiled in.

## 6. Landable change

The change against 52ef72f3d is in `scratchpad/pu-alias-budget-sources/best.diff`:

- `struct vec2_t : vec2f_t { vec2_t() {} vec2_t(float, float); float *vec2_sub(...); }` with
  `typedef vec2_t player_update_vec2_t`;
- `(float)cos/sin/sqrt/atan2(` replaced by `cosf/sinf/sqrtf/atan2f(` throughout;
- `muzzle_flash_alpha` declared at its first use.

| Build | Raw | Label-masked | Structural | Stack-masked | Refs | First pointer class |
|---|---|---|---|---|---|---|
| base 52ef72f3d | 74.36 | 83.74 | 84.53 | 94.04 | 863/0/0 | 515 (0x22d classes) |
| best.diff | **74.40** | 83.76 | 84.55 | **94.11** | 863/0/0 | 609 (0x28b) |

The code changes in three places, and all three move towards native:

- the auto-aim `sqrtf` result is kept with `fst` instead of `fstp`/`fstp`/`fld`;
- one x87 operand order;
- one `fst` and one byte store are reordered.

The same number of lines match (2,526), with two fewer candidate lines. Nothing else moves.

## 7. Acceptance tests

| Test | Prediction | Observed |
|---|---|---|
| markers = first symbol class − 4 | base 150 → 154 | ✔ (seven calibration variants) |
| block local / function local / `vinl` / `idf` / ctor | +1 marker / 0 / 0 / +1 / +2 per copy | ✔ |
| `cosf(local)` against `cosf(global)` | 0 against 2 | ✔ (+0, +20 over 10 copies) |
| `tmpplus2` class delta | 65 × (5 − 3) = +130 | ✔ first pointer class 645 |
| `aim` delta on top of it | 7 × 2 = +14 | ✔ 659 |
| `lensub` delta | 2 × 3 = +6 | ✔ 651 |
| pure inflater N = 256 on the SDK shell | collapses all 25 roots, reproduces the sibling's 66.28 / 93.96 | ✔ |
| `pu_swap(alt, cur)` under collapse emits native's weapon-id `lea` | found by experiment, not predicted | ✔ |
| negative control: `pu_swap(cur, alt)` | worse (95.40 against 95.97) | ✔ |
| negative control: velocity temporaries | worse under collapse | ✔ |

## 8. Tools

```sh
uv run python scripts/c2/alias_class_census.py <scratch> --out <new-dir> [--function NAME] [--list]
uv run python scripts/c2/inline_budget_trace.py <scratch> --out <new-dir> [--function NAME] [--all]
```

- `alias_class_census.py` prints:
  - the real tuples;
  - the scope markers;
  - the symbol classes by category (named local, unnamed temporary, global);
  - the first pointer class and the margin to 0x400.
- `inline_budget_trace.py` prints the caller's own size and budget. It then lists every expansion that
  spends budget and every refused `__inline` callee (C4710), in the inliner's visiting order, with the
  remaining budget and the running total.

## 9. Open questions

- Where the last 202 classes come from. Candidates not yet tested:
  - block-scoped direction and velocity vectors per weapon arm (this would also affect the frame);
  - an inlined auto-aim or aim-scheme function (this would also affect `aim+4`);
  - an SDK helper form for the 16 remaining `vec2_set` calls in the movement and aim code.
- Why a single-use formal survives for `cosf(global)` but not for `finl(global)` (`return a + 1`).
  C1's formal substitution was not traced.
- The frame: which native vectors were function-scope objects.
