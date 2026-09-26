# Unfolded field pointers: forward substitution and the alias-class budget (C2.DLL 8966)

This note explains when C2 keeps a field pointer such as `&player->aim` in a register (`lea ebp,[edi+0x50]`
followed by `[ebp]`, `[ebp+4]`) and when it folds the `lea` into `[edi+0x50]`. It uses the
`player_update` sites that native keeps: auto-aim, the Alternate Weapon swap, the muzzle-flash pointer
and the final world-bound clamp. Addresses are C2.DLL virtual addresses (image base 0x10700000).
"Verified" means observed in a preserving trace or confirmed by compiles. "Read" means static reading
only.

Short version:

1. The fold happens in one place. `forward_substitute_single_def_ranges` 0x107306c1 runs at the start of
   global register allocation, after `coalesce_copy_live_ranges` 0x10730308. The global optimizer
   (forward propagation, value numbering, CSE) and `pass_select_address_modes` 0x1072930f both leave
   `auto_aim = lea [player+0x50]` and `[auto_aim]` in the IL. [verified: IL at `addr`, `lower`,
   `fsub` and `blockregs`]
2. A pointer range is kept only if the pass excludes it. Phase 1 excludes value uses, uses before the
   definition, a second definition with another tree, and definitions that are not foldable. Phase 2
   excludes a range when `has_intervening_base_definition` 0x10731a50 returns 1: the base register is
   redefined while the range is live, or a store or call in that stretch has an alias class that
   contains the base's root symbol.
3. `symbol_in_alias_class` 0x10702e19 returns 1 for class 1, whatever the symbol. Class 1 is what
   `alias_class_for_symbol_set` 0x1075d456 hands out once `g_alias_class_count` reaches 0x400
   ([alias-field-records.md](alias-field-records.md)). Any store or call through a collapsed root
   therefore blocks the substitution of every `lea` pointer whose stretch contains it.
4. Native `player_update` is over that budget. A code-free way to push our build over it reproduces the
   native pointer registers, the sequential swap, the entry order and the late `add edi,0x18`. No local
   spelling of the pointers does (§4). Our build has 0x22a classes. Native needs about 510 more
   symbol-level classes, from locals, inline-expansion locals and temporaries.
5. Native's "no reload of `auto_target` between the x and y stores" is not an alias effect. It is one
   8-byte aggregate copy, `*auto_aim = creature_pool[player->auto_target].position`, with one index
   computation. With two scalar statements C2 reloads the index even when the pointer sits in a
   register. [verified]
6. Native's dead `lea eax,[eax*8+creature_pool.pos]` comes from a named pointer to the target position.
   Its `sym+index` definition is not foldable, so phase 1 keeps it. A later pass folds both uses and
   leaves the definition dead. [verified: the lines are identical to native]

## 1. The pass (read; phases verified by trace)

`forward_substitute_single_def_ranges` 0x107306c1 is called at 0x1072fbbd, after
`coalesce_copy_live_ranges` 0x10730308 and before the per-block register sets 0x10730a40.

**Phase 1** walks the tuples in IL order (0x107306d1..0x107307ec). The live range is `op+0x18` and must
have kind 2.

| Operand | Rule | Effect |
|---|---|---|
| source, not an address part (`op+0x10 & 0x20` clear) | allowed only for a `/Ot` register `mov` whose destination appears as a source register in the range's definition (`find_src_reg_operand`) | otherwise the range is excluded (`lr+5 |= 4`): a **value use** |
| source, address part | the definition must already have been seen (`lr+0x38`) and `is_substitutable_address_use` 0x10731bbf must accept it | otherwise excluded: a **use before the definition**, or an unfoldable use |
| destination, first definition | a `mov` from a register whose definition is the previous tuple and is foldable is merged into that `lea` (`tuple_replace_dst`) | then `is_foldable_address_definition` 0x107309bb must accept the definition, or the range is excluded |
| destination, later definition | same opcode and `compare_trees` equal | otherwise excluded: **two different definitions** |

`is_foldable_address_definition` 0x107309bb (read): a `lea` (opcode 0x12) with one destination and a
kind-5 source.

| Address form | Foldable when |
|---|---|
| 0x14c `base+disp` | the base's live range has kind 2 |
| 0x14f `index*s+disp` | `/Ot`, and the index range has kind 2 |
| 0x14d `base+index*s+disp` | `/Ot`, and both ranges have kind 2 |
| 0x14e `sym+index*s+disp`, 0x14a `&sym+disp` | never |

`is_substitutable_address_use` 0x10731bbf accepts every use of a 0x14c definition.

**Phase 2** runs for every range not excluded (0x107308db..0x10730993):

1. If the range is live out of its last block, its end becomes that block's end (`bitset_test` of the
   block set at +0x44).
2. `has_intervening_base_definition(base, def, end, lr)` runs. If the definition has an index,
   `has_intervening_base_definition(index, …)` runs too. A 0x14f definition with one register source is
   not substituted.
3. Without `/Ot`, `sub_1078f095` adds a size check.
4. `substitute_definition_into_uses` 0x1071f578 then rewrites the uses, and the range is freed.

`has_intervening_base_definition` 0x10731a50 (read):
- It walks backward from `end->prev` to the definition. The end tuple itself is not tested.
- A live flag starts at 1. It is reloaded at every block marker (0x19) and cleared at the range's own
  definition.
- While the flag is set, each destination operand is tested:
  - kind 1 or 2 with the same root as the base (`sym+8`), and the same symbol or an overlapping range,
    returns 1;
  - kind 6 (a store) returns 1 if `symbol_in_alias_class(root, op+0x1c)`;
  - kind 0xb (a call's side-effect operand) returns 1 if `symbol_in_alias_class(root, op+0x14)`.

`symbol_in_alias_class` 0x10702e19 (read):
- It starts with `cmp edx,1; je 0x10704042`, which returns 1.
- Otherwise a local (kind 4 or 5) is a member only if `flags5 & 2` (memory resident) is set.

A register pointer local like `player` is in no class except class 1.

## 2. How to predict from source

1. Take a pointer that is used only as an address, whose single definition is `base+disp`, and whose
   base is a register candidate. Unless something in §1 excludes it, it is folded into `[base+disp]`.
2. Things that exclude it (each verified on `mini/` controls, see §5):
   - passing it to a call (value use);
   - two reaching definitions at a merge (`p = c ? &a : &b`);
   - an address-taken base (`&player` escapes; `player` then lives in memory, unlike native);
   - **class 1 on a store or call inside its stretch**.
3. Things that do not exclude it:
   - `register`, `*const`, split declaration and initialisation;
   - `(char *)` arithmetic;
   - inline-function pointer or reference parameters (C1 or globopt substitutes them);
   - a pointer reassigned later with disjoint uses (live ranges split into webs);
   - a pointer copy (copy-propagated);
   - a function-scope versus block-scope declaration.
4. Named pointers to `global[index].field` (`sym+index` form) are never foldable. They stay ranges and
   are often folded late with a dead `lea` left behind.
5. Budget arithmetic:
   - Symbol classes come first: every local root, parameter and inline-expansion local, some compiler
     temporaries, and referenced globals.
   - Pointer roots follow in IL order (source order in `player_update`).
   - A root collapses to class 1 when its class id would be at least 0x400.
   - `scripts/c2/alias_budget_probe.py` prints the count and the collapsed roots.
   - The last roots collapse first. So a function slightly over budget keeps the pointers declared
     late, and one far over budget keeps all of them.

## 3. Question (b): the `auto_target` reload

Native close-target arm: `mov eax,[edi+0x320]; lea ecx,[eax+eax*8]; lea edx,[eax+ecx*2]; mov eax,[edx*8+pos.x];
mov [ebp],eax; mov ecx,[edx*8+pos.y]; mov [ebp+4],ecx`. That is one 8-byte float-pair copy: one index, then
`ld lo; st lo; ld hi; st hi` from lowering ([small-aggregate-copies.md](small-aggregate-copies.md)).

Stores through a pointer do kill `player->auto_target`. Evidence:
- `w2` (a two-definition pointer, kept in `edi`) with two scalar stores reloads `[esi+0x320]` between
  them.
- Under class 1 every pointer store conflicts with everything anyway.

Only the single statement avoids the reload. Verified in `mini/v1` and in the full function:
`*auto_aim = creature_pool[player->auto_target].position;` gives the native lines apart from the base
register.

## 4. The `player_update` evidence

Native keeps six field pointers:

| Address | Pointer |
|---|---|
| 0x413842 | `lea ecx,[edi+0x2fc]` plus a home at `[esp+0x24]` (muzzle) |
| 0x41564a | `lea ebp,[edi+0x50]` (aim) |
| 0x41573b | `lea ebp,[edi+0x2d4]` (shot cooldown) |
| 0x41581f | `lea eax,[edi+0x2c0]` (weapon id) |
| 0x415875 | `lea ecx,[edi+0x2d0]` (reload timer) |
| 0x4175f0 | `add edi,0x18` (world-bound Y) |

It also runs the seven Alternate Weapon swaps strictly in sequence, and it stores `previous_pos` before
the entry health compare.

A crude scan found no other matched Crimson function with this pattern: a kept `base+disp` pointer used
across blocks, with no value use, no loop increment and no block copy. The only hit was
`survival_spawn_creature`, whose pointer is explained by its 16-byte colour copies.

**Our build** (b7033a699, `fsub_trace.py`): `_auto_aim`, `_weapon_id` and `_muzzle_flash_alpha` are
phase-2 candidates and are substituted. Every `player+K` value-numbered temporary is substituted too,
including `shot_cooldown`'s and `reload_timer`'s after the coalescer merges the named copies. The
function has 0x22a classes: 513 symbol classes, then 24 pointer roots, and none collapses.

**Code-free budget push.** N calls of `static __inline int f(int v) { int t = v; return t; }` add
exactly 2N classes and no instructions (N = 100: 74.07%, byte-identical, 0x2f2 classes).
Predictions were made from the b7033a699 class ids and then compiled. The pointer root ids were:
- aim_screen 513, player_position 514, player 515, muzzle 516, then fire_player, shot_delta,
  effect_color, position and inline parameters;
- mouse_screen 532, stick_screen 533, auto_aim 534, shot_cooldown 535, weapon_id 536, reload_timer 537.

A root collapses when `id + 2N >= 0x400`.

| N | Predicted newly collapsed | Observed |
|---|---|---|
| 243 | none | none (74.0% band) |
| 244 | weapon_id, reload_timer | weapon_id, reload_timer ✔ |
| 245 | auto_aim, shot_cooldown | + auto_aim, shot_cooldown ✔ |
| 246 | mouse_screen, stick_screen | + mouse_screen, stick_screen ✔ |
| 254 → 255 | player (515) | the code changes between 254 and 255 only ✔ (65.81% → 65.97%) |
| ≥ 256 | every root | all 24 ✔ |

Native signatures predicted for full collapse (N ≥ 255) and checked:

| Native signature | Full collapse (s255/s256, and 8175f599c `diag256`) |
|---|---|
| entry: `previous_pos` stored before `fld [edi+0x24]` | ✔ (every collapse variant; our base hoists the compare) |
| `xor ebx,ebx` kept | ✔ once the muzzle pointer is declared at its first use |
| muzzle: `lea ecx,[edi+0x2fc]` at the muzzle block, home, final `mov ecx,[esp+..]; fld [ecx]; … mov [ecx],0x3f4ccccd` | ✔ (home at a new slot: frame 0x4c, not 0x48) |
| `lea ebp,[edi+0x2d4]` shot cooldown through readiness, swap and penalty | ✔ |
| reload timer via `lea r,[edi+0x2d0]` | ✔ (eax, native ecx) |
| seven swaps in strict sequence | ✔ (N = 245 still interleaves: player's own stores must be class 1) |
| `fcom [edi+0x18]; add edi,0x18; … [edi]` world-bound Y | ✔, only for N ≥ 255 as predicted |
| aim `lea ebp,[edi+0x50]` with `[ebp+4]` | partly: we keep `auto_aim+4` (`lea ebp,[edi+0x54]`), because our source value-numbers `auto_aim->y` separately |
| weapon id `lea eax,[edi+0x2c0]` | ✗: kept at 0x306c1 (`base check returned 1`) but folded later |

`fsub_trace.py` on `diag256` has 53 ranges kept by the base check and 33 substituted. The base
has 88 substituted.

Scores (8175f599c):
- `diag256` scores raw 66.28%, label-masked 75.99% and stack-masked 93.96%.
- best.diff scores 74.36%, 83.74% and 94.04%.
- On b7033a699 the full collapse with the muzzle move was 94.55% stack-masked against 93.90%.

The raw loss is mostly the extra 4-byte frame slot, which moves every `esp` displacement, plus
allocation drift. So the budget is a precondition for native's shape, and the inflater is diagnostic
only. It is a fakematch.

## 5. Controls (`scratchpad/unfolded-field-pointers/mini`, all predicted before compiling)

| Control | Prediction | Observed |
|---|---|---|
| m0: `vec2f_t *auto_aim = &player->aim;` address uses only | substituted | ✔ (trace: `forward-substituted`) |
| t1: + `sink_ptr(auto_aim)` | kept | ✔ `lea edi,[esi+0x50]` |
| w2: `if (g) auto_aim = &player->move_target;` (merge) | kept | ✔ |
| w1, sw6: reassigned later, disjoint uses | substituted (webs split) | ✔ |
| v11, sw1, sw5: inline helper with pointer parameters | substituted | ✔ |
| r1/r2/r3: `register`, `*const`, split init; v4 `(char *)player + 0x50` | substituted | ✔ |
| t4: `sink_pp(&player)` | kept, `player` in memory | ✔ |
| c900 / c1100: 900 or 1100 fresh-class stores before the block | folded / kept | ✔ |
| v1: `*auto_aim = pos` | one index computation | ✔ |
| v10: pointer to `creature_pool[t].position` | lea kept (0x14e not foldable) | ✔ (one use folded later) |

## 6. Tools

```sh
uv run python scripts/c2/fsub_trace.py <scratch> --out <new-dir> --lines A-B [--symbols auto_aim,weapon_id]
uv run python scripts/c2/alias_budget_probe.py <scratch> --out <new-dir> --expansions 0 244 245 256
```

`fsub_trace.py` builds on `il_stage_trace.py`. It prints IL at the regalloc pass boundaries and one
verdict per live range: substituted, kept by the base or index check, or kept in phase 1.
`alias_budget_probe.py` builds on `field_records.py`. It writes code-free inflation variants and prints
the class count and the collapsed roots. Both are diagnostics.

## 7. Open questions

- Which source constructs gave native about 510 more symbol classes? Candidates: inline helpers or
  C++ vector operators, whose parameters, locals and temporaries each add a class; or more named
  temporaries. Any recovery that adds real symbols moves `player_update` towards the tipping point.
- Why native keeps `aim` rather than `aim+4`. Native addresses y as `[ebp+4]`, so native probably had
  no separate value-numbered `auto_aim->y` address. One possibility is an aggregate or inline-reference
  spelling of the far-arm update.
- Which late pass folds a phase-1-kept `sym+index` pointer into its uses and leaves the dead `lea`
  (`target_position`). The candidates are the three other `substitute_definition_into_uses` callers.
- The muzzle home takes a fresh slot (frame 0x4c). Native shares it (0x48).
- N = 252 on b7033a699 drops to 53.7%. There the field-record budget (`0x400 − count`) is nearly spent,
  but the count has not wrapped. Not analysed.
- [frame-model.md](frame-model.md)'s open question about `creature_update_all`'s retained temporary
  is not class 1 (0x196 classes, nothing collapsed). The kind-6 alias branch of
  `has_intervening_base_definition` is the next thing to check there.
