---
tags:
  - reverse-engineering
  - matching
---

# MSVC 6 code generation

How the VC6 backend (C2) turns ordinary source into the shapes seen in
`crimsonland.exe` and `grim.dll`, and which source choices move those shapes.
Each entry is distilled from the per-function scratch notes and evidence
reports. The links go to the function where the behavior was demonstrated.

When a function will not match, find the section for the kind of difference
you see (loop shape, register choice, frame offsets, x87 order, block layout)
and check the entries there before searching blindly. A rule here explains a
mechanism; it does not promise the same spelling works at another site.
Retest every rule against native evidence.

The pinned compiler is VC6 SP6 under `/O2 /GB`. C2's internals are described
in [How C2 compiles a function][c2-compiler].

## Loops and induction variables

C2's strength reduction, linear test replacement, loop reversal and loop
inversion rewrite plain loops heavily. Most odd-looking native loop shapes come
from ordinary indexed source.

### Indexed loops become pointer walks

**C2 turns a plain signed-index `for` loop over a static array or record pool
into a pointer induction variable that advances by the stride.** Linear test
replacement then compares that pointer against the one-past-end address while
keeping the index's signed condition. Hand-written int-cast pointer walks,
container-of casts and negative-offset cursors are therefore C2 output, not
source. Writing them by hand is at best byte-identical, and can hoist slot
zero out of the loop or emit an unsigned `jb`.

```c
for (i = 0; i < 16; i++) {   /* not: while ((int)p < (int)&pool[16]) */
    if (pool[i].active) ...
}
```

Native advances a pointer register by `sizeof(T)` and ends with
`cmp reg, offset pool_end; jl`. Fields are addressed as `[reg+disp]`, and no
index register remains unless the body uses the index. The anchor is often an
interior field, so decompilers show negative offsets; that is an IV artifact,
not a missing owner type.

Seen in:

- [bonus_alloc_slot, creature_alloc_slot, projectile_spawn][audit-exe]: int-cast
  pointer walks rewritten as plain `for` loops stay byte-exact.
- [grim_find_free_texture_slot][audit-grim]: a `while ((int)slot < ...)` loop
  with a `goto` became a plain indexed loop, byte-exact.
- [tutorial_timeline_update][]: the indexed 16-slot bonus scan reduces to the
  native record pointer; the hand-written pointer loop hoisted slot zero and
  added instructions.
- [highscore_screen_update][]: replacing the pool-reset pointer walks with a
  signed index changes exactly the five `jb` latches to `jl`.
- [unlocked_weapons_database_update][]: indexed source already produces the
  native `0x7c`-step walks; explicit count or hovered-row cursors regress.

### Unused counted indexes become countdowns

**When a counted loop's index is not used in the body, C2 reverses it into a
`dec reg; jne` countdown**, and the entry guard folds away for constant trip
counts. IV elimination also computes trip counts and final values in closed
form. Native countdowns and closed-form arithmetic come from plain counted
loops; writing the countdown by hand can produce the wrong block order.

Source: `for (i = 0; i < n; i++) body_not_using_i;` rather than
`do { ... } while (--n);`, and `while (x < 0) { ...; x += 2; }` rather than a
hand-computed `(1 - x) >> 1`. Native: `mov ebx,N ... call; dec ebx; jne`, with
the trip-count arithmetic in the preheader.

Seen in:

- [creature_handle_death][], effect_spawn_explosion_burst and
  effect_spawn_freeze_shatter: countdown `do`/`while` loops replaced by counted
  `for` loops.
- [perks_update_effects][]: the ordinary local-index loop gives the native
  `dec ecx` and cold false-path block; encoding the countdown directly gives
  the wrong block order.
- [survival_update][]: the `(1 - interval) >> 1` closed-form trip count comes
  from `while (interval < 0) { ...; interval += 2; }`.
- [grim_get_key_char][]: an indexed shift loop reverses into the same countdown.

Conversion is not automatically neutral: in
[projectile_update][audit-exe], auto-converting its countdowns loses
references.

### Loop-test signedness follows the compared source value

**A loop whose source compares a signed `int` index or count keeps a signed
latch branch (`jl`/`jle`) even after strength reduction to a pointer walk; a
plain pointer-cursor compare gives the unsigned `jb`.** The opcode reveals the
signedness of the compared source value, not strictly index versus pointer: an
unsigned index would also give `jb`, and int-cast address compares lower to the
same signed compare as indexed loops.

Native: `7c` (`jl`) versus `72` (`jb`) at the latch, everything else identical.

Seen in:

- [highscore_screen_update][]: explicit signed pointer bounds are canonicalized
  away; only switching to a signed index flips the five `jb` latches to `jl`.
- [bonus_render][]: an `int` index for the nearby-bonus search exposes the
  native signed `jl`; a pointer search reintroduces the unsigned branch.
- [audio_update][]: both table walks are strength-reduced to pointers but keep
  the signed `jl` termination.
- [grim_keyboard_poll][]: the local count is signed because the native loop
  uses `jle`.
- [bonus_try_spawn_on_kill][]: int-cast address compares and indexed loops lower
  to the same signed pointer compare.

### Field access decides the induction anchor

**C2 creates one derived IV per accessed field address and merges compatible
ones; the surviving anchor is chosen by IV-merge order and per-field use
counts, not register priority.** All other fields are addressed by compensating
displacements, so moving the anchor changes every displacement and the
end-compare constant. Introducing a named record or field pointer changes IV
rounds and creation order, so the surviving anchor can move to the base, to the
named field or to a field next to it. Extra tests on a field raise its use
count, and a named record local changes creation order because derived IVs are
created in reverse order of last use.

Source: direct `pool[i].f` keeps the native base or field anchors;
`(flags & 1) || (flags & 4)` instead of `(flags & 5)` raises a field's use
count and can move the anchor there. Native: `mov esi, offset pool+K` with
fields at `[esi-K+off]`, and `lea esi,[edi-0x44]` rebuilding the record from a
field cursor only where needed.

Seen in:

- [highscore_screen_update][highscore-row-induction-2026-09-22]: splitting mask
  5 into two bit tests raises the `flags` use count by one and anchors the IV
  on `flags`; forcing that count in the compiler reproduces the same COFF.
- [typo_word_pick_highscore_name][]: a record local for the current row swaps
  two entry stores because the cache IV is created before the table IV; the
  fully indexed form is exact.
- [projectile_render][]: `const vec2f_t *position = &pool[i].position` (+8)
  anchors the plasma cursor at `position.y` (+0xc), the native anchor, through
  the parallel-IV merge.
- [bonus_spawn_at_pos, creature_find_nearest][audit-exe]: taking a field address
  gives a base-anchored IV, while a pure index loop anchors at the most-used
  field.
- [creature_render_type][creature-render-exact-2026-09-12]: four per-pass
  indexed-versus-pointer choices recover the native lifecycle, max-health and
  anim-phase cursors; only that combination is exact.
- [highscore_sync_worker][]: native walks `&highscore_table[0].flags` in EDI
  and rebuilds the record with `lea esi,[edi-0x44]`; a reference-bound `flags`
  local plus an arm-local record pointer gets closest, while a plain
  branch-local pointer falls back to base-record iteration.

Not every alias spelling moves the anchor; several pointer, reference and
flat-field variants are byte-identical.

### Values derived from one index get their own induction registers

**When counts, trigger times, spreads or positions are written as expressions
of one zero-based index, C2 strength-reduces each into its own IV register**
with native init and step placement, and keeps the original index for the
bound. Separately maintained accumulators (`+= 15`) allocate and schedule
differently. Naming loop-invariant terms also changes IV register roles.

```c
count   = wave_index + 2;           /* not count++ */
trigger = wave_index * 5500 + 4000; /* not trigger += 5500 */
```

Native: registers seeded with 2 and 4000 stepping by 1 and 5500, with
`lea eax,[edi-2]` recomputing the index for the compare.

Seen in:

- [quest_build_gauntlet][]: deriving both count and trigger from a zero-based
  `wave_index` is exact; deriving only one of them is not.
- [quest_build_major_alien_breach][]: `wave * 15` is exact with ESI zeroed
  after the hoisted constants; an explicit acceleration counter swaps them.
- [quest_build_the_beating][]: deriving positions and first-phase time from the
  wave index is exact, where the parenthesized forms are not.
- [quest_build_syntax_terror][]: naming the two outer polynomial terms puts the
  count in EBP and the inner seed in EBX.

### An early constant trip count specializes later loops

**If source exposes a constant trip count or index early, VC6 propagates it and
specializes later general loops into much smaller code.** Native registers that
hold constants such as 12 come instead from fixed-trip inductions that C2
eliminates late: an ordinary path index for coordinates and time plus a
separate scalar entry count for publication.

Seen in:

- [quest_build_survival_of_the_fastest][]: fixed, builder-backed, shared-index
  and six-plus-six reservations of 12 entries all collapse the third loop to a
  much shorter body; an ordinary path index plus a separate count leaves two
  registers holding 12 before the third loop, as native does.
- [quest_build_nagolipoli][]: carrying `entry_count` as the loop-carried
  publication cursor makes VC6 hoist the known +12/+6/+6 advances into
  pre-loop setup blocks, which is the native shape. Saved-start reservations
  before the loops add instructions, and collapsing the corner records into one
  pre-loop add is the non-native outcome.

### Loop statement form: inversion, peeling and spellings

**C2 inverts pre-tested loops (entry test plus bottom test) and supplies the
guard itself, so a native guarded bottom-test loop comes from a plain `for` or
`while`.** A tail-tested `do` loop can instead get its first iteration peeled.
The equivalent spellings `for (;;)`, `while (1)`, `for (; cond;)` and guarded
`do`/`while` are not always canonicalized and can change operand registers and
latch placement.

Seen in:

- [creatures_none_active][]: stock VC6 peels the first iteration of the
  tail-tested spelling; the pre-tested bounded loop is exact.
- [grim_run_loop][]: a guarded `do`/`while` became
  `if (hwnd) while (msg != WM_QUIT)`; loop inversion supplies the guard,
  byte-exact.
- [statistics_update_check_worker][] and highscore_sync_worker: `for (;;)` plus
  `if (!read_ok) break` is exact, `for (; read_ok;)` is neutral, and
  `while (1)` with a break regresses.
- [quest_build_arachnoid_farm][]: equivalent `while` loops choose different
  operand bytes (EAX/EDX exchanged, `lea eax` versus `add edx`); a guarded
  `do`/`while` recovers them.
- [plaguebearer_spread_infection][]: a pre-tested `while` with an explicit
  `found` exit lets VC6 drop the initially true bound check; `do` with `break`
  needs extra instructions.

Loop forms are often canonicalized: every `do`/`while`/`for` form tried in
[quest_build_the_gang_wars][] and every pool-reset spelling in
[highscore_screen_update][] was byte-identical.

## Statement order, ownership and spelling

The source choices that most often move native code: who owns a value
(indexed expression, cached pointer, named local or repeated expression),
where it is first assigned, and the order of independent statements.

### Indexed publication versus a cached record pointer

**Writing each field through a fresh `base[count]` expression and incrementing
the count after the record keeps base-plus-scaled-index addressing and keeps
metadata stores after the x87 coordinate work.** A record pointer computed once
lets C2 hoist the record's integer stores into `fild`/`fstp` latency windows
and moves the `lea`. Native evidence picks the owner per site; some sites need
the cached pointer.

```c
spawns[count].pos.x = ...;           /* versus entry = &spawns[count++]; */
spawns[count].pos.y = ...;           /*        entry->pos.x = ...;       */
spawns[count].template_id = ...;
count++;
```

Native: `mov [reg+0xc], imm` interleaved between `fild` and `fstp` (captured
pointer) or after both `fstp` (indexed); `[reg*stride+base]` versus an absolute
`lea` pointer.

Seen in:

- [quest_build_gauntlet][]: a retained record pointer hoists metadata stores
  into x87 conversion windows; separate `spawns[entry_count]` expressions delay
  them.
- [quest_build_nagolipoli][]: publishing the final four entries through
  `spawns[entry_count]` removes the scheduled-position differences and folds
  +4/+8 offsets into a scaled `lea`.
- [creature_spawn][]: a local `creature_t *` instead of direct
  `creature_pool[slot_id]` turns global-base-plus-index addressing into an
  absolute pointer.
- [creature_spawn_template][]: the opposite case. One
  `creature_spawn_slot_t *` materialized after allocation gives native's single
  scaled `lea` plus member stores for the spawn-controller templates.
  Separately, direct `creature_pool[child_slot_idx]` initialization of the child
  creature regresses against a block-local child pointer.

### One append count from zero

**In several quest builders, publishing every entry through one append count
that starts at zero lets C2 constant-fold the fixed-prefix indices and derive
loop seeds and the live count itself.** Preseeded counts, fixed indices and
manually reserved batches give different schedules: an extra add per batch, or
metadata hoisted before positions. The append count is a tendency, not
sufficient on its own.

Source: `count = 0; spawns[count]...; count++;` throughout. Avoid
`spawns[0]`, `spawns[1]` then `count = 2`, and `base = &spawns[count]; count += 7;
base[i]`. Native: fixed offsets for the first entries, the live count
initialized to the folded constant at the first branch, and `lea` displacement
folding instead of `lea base; add 0xc` pairs.

Seen in:

- [quest_build_minor_alien_breach][]: replacing `entry_count = 2` and fixed
  indices with a zero-based append count is exact, and VC6 derives the native
  wave seed of two.
- [quest_build_the_unblitzkrieg][]: a reserved batch plus `base[index]`
  produced `lea base; add 0xc` pairs; indexing `entry_count` directly and
  advancing per record lets VC6 fold the advances.
- [quest_build_spideroids][]: the append count alone is byte-identical to the
  fixed-index form; it matches only together with direct first-position
  stores.
- [quest_build_8_legged_terror][]: the exact form keeps cursor and count
  together in a builder initialized at `(entries, 0)`, which stops VC6 folding
  the final count to a literal.

### Repeat a pure expression instead of naming it

**When native computes a value once and reuses it, spelling the expression at
every use often matches better than a named local.** C2's CSE then picks the
native owner register, lifetime and IR shape, such as an additive immediate
folded into `lea` or `add reg,-N`. A named local imposes its own lifetime:
hoisting, spills, `sub` instead of `add -N`, rotated registers. Likewise,
recompute a value rather than reading it back from a field where it was
stored.

Source: repeat `height / 16 - 2` in each clamp's compare and assignment; write
`wave * 13000 + 1500` at each publication; use
`vec2(size * 0.5f, size * 0.5f)` rather than `half = size * 0.5f`. Native:
`add eax,-2` rather than `sub eax,2`; the value computed once and kept on x87;
the frame at its native size.

Seen in:

- [console_render][]: repeating `height / 16 - 2` emits `add eax,-2` at both
  sites; every decrement and unsigned-constant spelling of a named value
  compiled to `sub`.
- [quest_build_everred_pastures][]: removing only the named `trigger_time_ms`
  and repeating `wave * 13000 + 1500` is exact.
- [creature_render_type][]: repeating `size * 0.5` in both constructor
  arguments restores the native `0x3c` frame.
- [quest_build_spiders_inc][]: recomputing `step_count / 2 + 3` gives
  `sar eax,1; lea ebp,[eax+3]`, while reading the stored `wave.count` field
  regresses; a shared half-step local was equally exact.

Not universal: in [quest_select_menu_update][] duplicating the unlock-index
expression regresses, and some sites need a named local.

### Re-read fields and globals at each use

**C2 does not cache memory across stores or calls unless the source does, so
native reloads after calls are source re-reads.** A local snapshot imposes a
lifetime that changes register ownership across the function, moves loads ahead
of compares, or coalesces later loads. In the other direction, a global used
directly several times may be hoisted into a callee-saved register by C2
itself, and a call-free loop that updates globals directly gets them
register-promoted. Decide per site from native reload evidence.

Native: `mov reg,[rec+type]` after a call; a temporary `shl` and `lea` for the
slot address versus a coalesced `mov ebx,ebp; shl; add`; a global held in EBX.

Seen in:

- [projectile_update][]: reloading the secondary type before damage and after
  `creature_apply_damage` gains a lot, and either reload alone regresses;
  likewise `bonus_freeze_timer` per arm and `target_id` for
  `creature_handle_death`.
- [typo_target_name_assign_random][]: a named `char *name` makes VC6 coalesce
  the id into EBX; direct `typo_target_name_table[id]` at every site gives the
  native temporary `shl` plus `lea`.
- [perk_apply][]: Ammo/Bandage refresh a captured `player_count` after each
  callback while other loops read the global; fully cached forms rotate
  EBP/EDI across the whole function.
- [grim_lookup_blob_size_for_path][]: using the global directly lets VC6 hoist
  it into EBX; a local alias flips the commutative operand choice.
- [quest_start_selected][]: updating the globals directly inside a call-free
  loop lets VC6 register-promote them and publish them once, where local
  lifetime variants were all neutral.

### Value copy versus a C++ reference to the field

**Copying a field into a value local lets C2 keep it in a register for the
iteration; a reference bound to the real field or global makes C2 reload or
update the actual object at each use.** That restores late reads, in-place x87
updates with no stack copy, and stores through a shared register. A reference
used as a plain alias of a pointer is byte-identical to the pointer.

```cpp
float &angle = particle->angle;
angle -= turn;
dir = vec2(cos(angle), sin(angle));  // fcos on the live value, fsin reloads the field
```

Seen in:

- [projectile_render][]: a primary-type reference (mutable and `const`
  identical) reloads `type_id` at native decision points. `volatile` scored
  higher but is a fakematch.
- [projectile_update][projectile-particle-update-2026-09-11]: a reference to
  `particle->angle` removes a stack copy; cosine uses the updated live value
  and sine reloads the stored field.
- [highscore_screen_update][highscore-state-owners-2026-09-22]: making `stage`
  a reference to the saved stage index removes separate local and global
  constant stores; both stores then use ECX.
- [gameplay_update_and_render][]: an array-element reference preserves the
  in-place weapon-time update.

The effect is local: in `projectile_render`, aliases at other loops regressed.

### First assignment matters; declaration position does not

**The point of first assignment, relative to calls, other stores or an inline
`rep` string intrinsic, sets the schedule, which register owns the value and
whether it survives a call in a callee-saved register.** A definition live
across an inlined `memset`/`rep stos` cannot use ECX or EDI, even if the
scheduler later places the store after the clear. Moving only an uninitialized
declaration is byte-neutral, and initializing at function entry stretches the
lifetime and regresses.

Seen in:

- [typo_player_update][]: declaring the perk-assisted readiness flag after the
  aim computation reproduces the native zero-store schedule.
- [statistics_menu_update][]: capturing the renderer pointer after the F1 key
  test fixes the EDX/EAX rotation across later widget calls.
- [highscore_screen_update][highscore-prefix-lifetime-2026-09-22]: initializing
  `prefix_length` before `memset` makes its range cross the clear, which
  excludes ECX and EDI, so it lands in EBX. Moving the declaration alone is
  neutral.
- [ui_render_hud][]: initializing `hud_y` at entry regresses; moving
  declarations only is neutral.
- [grim_zlib_decompress_alloc][]: declaring the available-size local after the
  allocation keeps the original value in ESI across `operator new`.

### Declaration order is usually neutral

**In medium and large functions, stack homes and registers come from use
lifetimes and counts, so permuting declarations is byte-identical.** In small
builders, the order of loop-carried scalars and of their bottom-of-loop updates
can still decide initialization order, register roles or spill slots.

Seen in:

- [creature_spawn_template][]: a declaration-order sweep is byte-identical;
  slots come from the root-offset and zero-vector use lifetimes.
- [perk_apply][]: all declaration orders are byte-identical, which rules order
  out as the cause of its ESI/EBP split.
- [quest_build_monster_blues][]: declaring `index` before `trigger_time_ms`
  yields native `xor esi,esi` / `mov edi,27500` order.
- [quest_build_syntax_terror][]: advancing `outer_index` before `outer_seed`
  selects the native spill slots, while VC6 still emits the seed increment
  first.

Declaration order was also neutral in sfx_entry_start_playback,
projectile_update and player_render; in [quest_build_frontline_assault][]
declaring the trigger step before the builder regressed.

### Independent statements keep source order

**C2's list scheduler only fills latency locally, so independent field stores,
increments, initializations and per-component x87 arithmetic mostly keep their
source order.** Native store order reveals the original statement order. Order
matters most when it moves a lifetime, a constructor boundary or interleaving
with x87 work; many local permutations are canonicalized.

Seen in:

- [quest_build_army_of_three][]: finishing the first entry's count before
  constructing the next position lets VC6 interleave the constructor load as
  native does.
- [grim_set_rotation][]: writing the matrix as m00, m01, m10, m11 gives the
  native x87 schedule and EAX/EDX allocation.
- [config_init_defaults][]: initializing the byte cursor between the slot-index
  zeroing and the order-offset assignment publishes it before `mov ebp,0x88`.
- [player_update][player-fire-cough-2026-09-14] (Fire Cough): subtracting Y
  before X when building the spread vector matches native.

Exceptions exist: [tutorial_timeline_update][] emits independent compound
assignments in reverse source order, [quest_select_menu_update][] keeps one
reverse order for every placement, and [grim_flush_input][] moves a count store
ahead of `rep stosd`.

### Chained assignment stores the rightmost target first

**`a = b = v` stores `b` before `a`, and for floats keeps the value on the x87
stack (`fld st(0); fstp`) instead of store, pop and reload.** Reversing or
splitting the chain keeps the masked bytes but swaps the store order, which
shows up as reference mismatches. Historical constructor chains are recoverable
this way.

Seen in:

- [play_game_menu_update][]: native stores `checked` then `disabled`;
  `disabled = checked = false` is exact and the opposite chain mismatches
  references.
- [quest_results_screen_update][]: `force_small = force_wide = false`; reversed
  or separate forms create reference mismatches.
- [music_update_fades][]: a chained local-first float assignment becomes
  `fld st(0); fstp [table]`, where native uses `fstp [table]; fld [local]`.
- [creature_update_all][creature-state-publication-2026-09-11]: native clears Y
  and then X; `delta.x = delta.y = 0.0f` reproduces it.

### Work common to both arms is hoisted

**C2 hoists a load or partial product that is identical in every arm to one
common point**, which can land between other instructions without adding any.
A catch-all final `else` lets shared subexpressions move above the preceding
gate. Branch-local scalars, an explicit condition on the last arm, or the
computation inside each arm keep per-arm loads and a single store at the join.

Seen in:

- [player_render][overlay-render-owners-2026-09-12]: VC6 hoists the common size
  load between the weapon-index shift and the subtraction.
- [perk_selection_screen_update][]: direct compound assignments hoist the
  common load; two arm-scoped scalars recover native's load/store shape.
- [projectile_render][]: a catch-all final `else` lets VC6 hoist the shared
  coordinate differences across the Spider gate; an explicit `SHRINKIFIER`
  condition regresses.
- [ui_render_hud][]: the player-zero weapon-id expression inside both
  icon-layout branches lets VC6 hoist the common load in native order.

### Redundant stores in native code are real source stores

**VC6 keeps a default store that is overwritten only on some paths**, so the
native shape of a base store followed by a conditional overwrite must come
from source that stores on every path; a conditional expression drops the base
store. The shape does not by itself prove that the original wrote a default
and then adjusted it, because an explicit `if`/`else` can lower to the same
default-then-overwrite. A store to a global that is unconditionally
overwritten before any call or read is removed, while a store followed by an
external call survives.

Seen in:

- [ui_menu_layout_init][]: slots 8, 9 and 33 and the controls panel are
  initialized before the responsive branches (the panel at `(-165, 200)`, then
  X becomes -183); the port's ternary had dropped those base stores.
- [controls_menu_update][]: in the point-click gate, `if (v == 0) n = 3; else
  n = 4;` lowers to native's materialized 3 overwritten by 4. A conditional
  expression and a reversed default both regress.
- [terrain_generate_random][]: the third `rand()` result is never stored
  because no external call can observe it before the fixed zero overwrites it.

### Aggregate identity of globals changes alias ordering

**C2 treats separately declared contiguous globals as non-aliasing objects.**
Accessing the same storage through its owning aggregate (a struct global or a
borrowed sub-object) changes alias classes, so loads and stores keep or lose
source order, and addressing or encodings shift even at identical offsets.

Seen in:

- [game_frame_update][]: separate mouse components let VC6 load both before
  either aim store; one aggregate preserves native's store-X-before-load-Y
  order.
- [gameplay_reset_state][]: the `game_t` aggregate makes VC6 schedule two byte
  flags before the 256-byte `memset`; it was neutral in other consumers.
- [sfx_entry_load_ogg][]: a borrowed `sfx_pcm_storage_t *` sub-object gives
  native's `pcm_bytes`-then-`pcm_data` load order, where every arithmetic
  spelling was identical.
- [ui_menu_layout_init][]: the recovered 2003 `ui_t` owner fixes a long prefix
  and the reference mismatches.

Often neutral (the `textures_t` owner in [ui_cursor_render][]), and in
[creature_update_all][] aggregate spellings of navigation and velocity
regressed.

### Spellings that compile byte-identically

**Many surface spellings reach the same IR and are not matching levers.**
Pointer versus reference versus `const` declarations of an alias; `register`;
pointer-to-member access; swapping the operands of a single commutative op;
explicit versus implicit int-to-float casts; compound versus explicit
assignment; copy construction versus copy assignment; struct, union, int or
float destinations of the same bits; moving a declaration without its
initialization; and `extern "C"` versus C++ linkage of a callee, which changes
only the relocation name. C2 also already keeps repeated constants in
registers, lowers float copies to integer moves and if-converts a constant
ternary.

Seen in:

- [player_update][]: muzzle-flash pointer versus reference are identical, as
  are the Fire Cough pointer, `const` pointer, reference and `const` reference
  forms.
- [ui_scrollbar_update][]: every explicit and implicit cast spelling for
  `fild visible_rows; fidiv item_count` is byte-neutral.
- [quest_spawn_timeline_update][quest-history-controls-2026-09-28]: every
  pointer-to-member, accessor and `register` control reproduces the canonical
  body.
- [grim_d3d_init][]: `(D3DSWAPEFFECT)((is_voodoo3 != 0) + 1)` and a bool ternary
  are byte-identical.
- [gameplay_reset_state][]: moving the `player_reset_all` declaration out of
  `extern "C"` changes only the relocation name.

Neutrality is per expression. Association, grouping, comparison operand order
and multi-term sums do change code (see
[Floating point and x87](#floating-point-and-x87)), and id-keyed ordering can
flip commutative order indirectly.

## C++ value classes and aggregates

The game used the 2003 MOD SDK `vec2_t` and color value classes. Inlined
operators, constructors and implicit copies leave recognizable stack
temporaries and copy shapes, but only at the sites where the original used
them.

### Value-class temporaries set frame size and slot reuse

**A two- or four-float constructor expression, a value-returning `operator+`,
or `(a + b).v` passed to a call materializes a stack temporary that lives for
the whole expression; the result is then copied, often with integer moves.**
The temporaries' lifetimes decide which dead slots the colorer reuses and the
frame size. Chained `a + b + c` keeps a hidden first-sum temporary that `+=`
would remove. Constructors where native wrote component stores add a temporary
and instructions, so use them only where native shows them.

Source: `(position + vec2(7, 7) + render_offset).v` as a call argument;
`pos + vertex + vec2(180, 40)`. Native: 8- or 16-byte `[esp+N]` temporaries
with x87 spills and paired dword copies, and frame sizes that change with them.

Seen in:

- [ui_element_render][]: offset shadow and panel calls taking `(...).v` are
  exact; a staged owner or a named panel position regresses.
- [survival_update][]: temporary vectors are needed at every milestone spawn
  call; early-only or late-only conversion falls short because native reuses
  the dead centroid slot.
- [quest_failed_screen_update][]: `position + vertex + (180, 40)` reproduces
  VC6's hidden first-addition temporary; declaring `xy` just before the `do`
  body moves it to native `[esp+0x20]`.
- [quest_build_spider_spawns][]: negative case. A two-float constructor adds
  an eight-byte temporary native does not have and many instructions.

Single-site controls often look negative while only the combined forms match.
Materializing vectors where native has scalars loses heavily
([controls_menu_update][], orbit arms).

### Vector operator form decides x87 interleaving

**Inlined vector operators keep their temporary structure.**
`base + vec2(0, dy)` interleaves the Y conversion with the X load and store and
the argument pushes, while a direct constructor schedules X first.
`v += vec2(-84, 0)` emits a Y self-copy. Constructing an aggregate in one
expression publishes all its components at the construction point, whereas
separate field stores let C2 defer the first component past unrelated pushes.
A destination-writing helper differs from one returning a named `vec2`.

Seen in:

- [ui_list_widget_update][]: the row point as `base + (0, row_offset)` through
  `operator+` is exact; direct constructor variants are neutral or worse.
- [ui_menu_assets_init][]: inlined `vec2 += (-84, 0)` reproduces the native
  loop, including its Y self-copy.
- [quest_spawn_timeline_update][]: `pos = offset + quest_spawn_table[i].position`
  through `operator+` is one of the spellings needed for exactness; component
  math regresses.
- [ui_draw_progress_bar][]: the background color as one constructed value
  reproduces native stores; four array assignments change the order.
- [typo_player_update][]: a forced-inline destination-writing add reproduces
  the staging; any helper returning a named `vec2f_t` regresses.

### An inline two-argument setter keeps both lanes on x87

**With right-to-left argument evaluation, an inline `set(x, y)` computes both
lanes (Y first) on the x87 stack before two `fstp`.**

```text
fld a.y; fadd b.y; fld a.x; fadd b.x; fstp v.x; fstp v.y
```

Seen in:

- [ui_element_render][]: constructing the first vector and publishing later
  pairs through inline `set()` reproduces native's paired stores.

Not every native site takes it: in [player_update][], converting the two
aim-screen pairs reorders the camera loads and adds reference mismatches. Its
companion scaled-movement helper lets C2 cross-jump arms that native keeps
separate when it is used everywhere.

### Keep implicit copy constructors and assignment

**Small value classes must keep the implicit copy constructor and copy
assignment.** A user-written copy constructor or `operator=` replaces the block
or word copy (`rep movsd`, integer `mov` pairs) with member-wise code and
disturbs the function-wide temporary allocation. An empty user destructor also
changes code. Constructor-body spelling is neutral: a two-float constructor
that assigns in its body behaves like the SDK-era code.

```cpp
struct vec2 { float x, y; vec2() {} vec2(float a, float b) { x = a; y = b; } };
// no user operator= and no user copy constructor
```

Seen in:

- [ui_menu_assets_init][]: every user-defined assignment destroys the native
  `rep movsd` shape.
- [projectile_render][]: every user copy constructor loses weighted bytes, and
  so does an empty user destructor.
- [quest_build_knee_deep_in_the_dead][]: explicit assignment operators collapse
  the temporary schedule; constructor-body and `inline` annotations are
  neutral.

A related trap: in [creature_spawn_template][], declaring a value-returning
`operator+` is neutral, but using it regresses heavily. Counter-example: in
[quest_build_the_lizquidation][] an explicit member-wise `operator=` is exact,
where the implicit copy gives a biased copy pointer.

### Whole float aggregates are copied with integer moves

**Whole two-float or color copies select integer moves (or `rep movsd`), never
`fld`/`fstp`; the load and store interleaving varies by site.** A whole-vector
copy from an indexed global computes the index once. Component float
assignments select x87 instead. A relative vector op on constants folds the
changed component and copies the untouched one as an integer.

Seen in:

- [player_update][]: the mouse-to-aim copy is two integer moves; splitting it
  into float assignments selects x87. The whole-vector auto-aim copy computes a
  single index.
- [ui_element_set_rect][]: grouping Z/RHW as an aggregate recovers the loop's
  ESI/EDI constant copies.
- [ui_menu_layout_init][]: the controls panel `(-165, 200)` then `-= (18, 0)`
  folds X to -183 and keeps the integer Y copy; a scalar setter uses x87.
- [projectile_render][renderer-house-style-2026-09-13]: copying the
  fading-beam direction as a whole `vec2f_t` matches native's integer loads and
  stores before normalization.

After a block copy VC6 may reuse the source value where native reloads the
destination; [ui_menu_assets_init][] accepts this only through the
`vc6-proven-copy-load` canonicalization.

### Initialized POD locals are constant-folded away

**A plain initialized two-float local that is only read for stores is
constant-propagated, and its stack slot disappears.** Native frames that
materialize zeros need a source object the compiler cannot fold: a
constructor-expression temporary in the C++ builders, or a union overlay of the
written zero words where constructor forms delete the storage or regress.

Seen in:

- [creature_spawn_tinted][]: a plain initialized zero velocity folds the 8-byte
  frame and its instructions; native keeps two written zero words.
- [creature_spawn_template][]: zero velocity in `[esp+0x10..0x14]` uses the
  same constructor-expression shape as `survival_spawn_creature`.
- [creature_spawn][]: a C translation unit where real C++ vector constructors
  either delete the six native zero-storage instructions or regress; only the
  named union overlay keeps the frame.

### By-value aggregates and unsized externs change alias analysis

**Passing a small vector class by value instead of as `const T *` changes
VC6's alias analysis and body code regardless of special members; a reference
parameter is byte-identical to the pointer.** Declaring a global array without
a size keeps aliasing between records that a sized declaration would
disambiguate.

Seen in:

- [projectile_spawn][]: by-value 2003-header parameters change alias analysis
  for every special-member variant; both reference forms are byte-identical to
  the pointer.
- [fx_queue_add][]: position or color by value each regress, and both together
  more.
- [effect_spawn][]: a by-value vector loses an instruction; `const vec2f_t *`
  is exact.
- [bonus_hud_slot_activate][]: the unsized `extern T table[];` lets the
  optimizer keep the alias between the current and scanned records.

## Register allocation and C2 internals

VC6 allocation is whole-function and keyed by internal ids, use counts and
lifetimes, so a residual far from the edit is normal. C2 traces of these
mechanisms are in [`tools/match/c2`][c2-tools].

### One shared constant register, split by retention cost

**C2 makes one constant definition shared by every use (clears, index inits,
compares), splits it during allocation, and keeps groups in a callee-saved
register while others become immediates.** Store width matters: a byte store
does not share a dword constant. The placement and lifetime of a counter that
holds zero, and whether a loop exposes its induction variable, decide whether
the zero register exists. Routing each use of an immediate mask through a
short-lived inline helper keeps it as an immediate.

Native: `xor ebx,ebx` reused by `mov [..],ebx` / `cmp ..,ebx`, versus literal
immediates with EBX given to a loop variable.

Seen in:

- [config_init_defaults][]: writing `ui_info_texts` as the one-byte
  initialization it is stops sharing the integer one with a later dword store,
  freeing EBX for the saved-name index.
- [quest_spawn_timeline_update][vc6-timeline-zero-splitting-2026-09-12]: the
  zero splits into groups with different retention costs. Flipping one group's
  cost, together with an extent change, partially recovers native (the initial
  scan and the pointer-store triplet); priority changes do nothing. In source,
  [resetting the spawn counter at the group advance][quest_spawn_timeline_update]
  keeps zero in EBX.
- [bonus_render][]: a bounded player `for` loop recovers the native EBX zero
  shared with the preceding weapon pass.
- [input_detect_active_analog_axis][]: each inline expansion owns a short-lived
  bit view, so VC6 emits `and eax,0x7fffffff` at every test.

Cost-based retention is an observed mechanism, not a complete explanation.

### Ties and commutative order are keyed by internal ids

**C2 sorts commutative operands, SIB address components and scheduler ties by
keys built from internal symbol or IL node ids**: x87 memory operands by id mod
8, memory keys from generated base ids with an unsigned descending compare,
ties by IL id mod 2048. Globals are numbered by first reference in 32-id
chunks. Any source change that adds or removes named locals, references,
inline formals, operator records or earlier global references shifts ids and
can flip operand order in distant, unchanged code, which then changes lowering
and allocation. Commuting a single op's operands in source is normally
neutral.

Seen in:

- [ui_element_render][]: converting one or two of three alpha loops swaps one
  `fadd`; converting all three restores native order. Direct operand-order
  combinations are identical.
- [grim_submit_vertices_transform_color][audit-grim]: a natural
  `unsigned long *vertex` local shifts inline copy ids and gives native
  `y*m1 + x*m0`; no spelling inside the helpers can.
- [highscore_screen_update][highscore-quest-ordering-2026-09-22]: a
  quest-predicate spelling changes a generated base id, which flips row-addition
  order and the earlier loop's allocation; rewriting only the keys reproduces
  the control's COFF.
- [projectile_render][projectile-id-window-2026-09-28]: ion-arc ties need ids
  shifted within the mod-2048 window. The final source uses a richer vector API
  (union `operator[]`, by-value compound operators with NRV return, `const&`
  scalar arguments) that adds inline records without code.
- [grim_window_proc][]: placing `WM_MOUSEMOVE` before `WM_CHAR` moves the count
  global's id and fixes the last SIB bytes; the sparse-switch layout does not
  depend on case position.

Pads and dead stores are only measuring devices. `FROUND` parentheses pin a
pair's order independent of ids, but using them only for that is id-tuning.

### The 0x400 alias-class budget

**C2's alias collector stops at 0x400 classes.** Big functions with many value
temporaries, inline formals or vector operators exceed it, so pointer roots or
distinct fields collapse into one class. Long-lived field pointers then survive
(stores and calls always alias them), and stores serialize behind
write-after-write dependencies. Spellings that are native under collapse score
worse below the budget, so judge them in the right regime.

Seen in:

- [player_update][]: the 2003 SDK spellings (`&(a + b)`, `cosf`/`sinf`
  overloads) push the first pointer class past the budget and collapse every
  root; the swap helper then reproduces `lea eax,[edi+0x2c0]` /
  `lea ecx,[edi+0x2d0]`.
- [creature_spawn_template][spawn-exact-2026-09-13]: above the budget all the
  blue-creature stores collapse into one class and the `1.0f` load into EDI is
  delayed.

### May-alias stores block copy propagation

**C2 compares memory operands only by alias class.** A store between a
definition and its use that may alias an indirect input load blocks forward
propagation, so inputs are reloaded and load order changes. A variable-index
`pool[i].f` and a `*ptr` into the same pool get dependence edges, while fields
reached through one named element pointer are disjoint and can be grouped
freely.

Seen in:

- [creature_update_all][]: the hold-timer copy order closes with a named
  `creature_t *c = &creatures[i]`, explained with the alias tracer.
- [player_update][player-angle-propagation-2026-09-22] (Fire Cough): the
  `move_delta.x` store blocks propagation of the indirect input read; array,
  struct, union and double destinations are all neutral.

### Derived field pointers are rematerialized

**A source pointer `T *p = &rec->field` becomes LEA-plus-COPY IR that C2 tends
to substitute back into its consumers as `[base+off]`** at several points
(early substitution, allocation analysis, spill handling, the final allocation
loop, or per region after splitting). Declaration spelling, more uses and the
pointee type do not keep it. Only a pointer that is a COPY of another live
pointer, such as one saved before a cursor advances, survives. A named field
pointer that duplicates a CSE address temp can also change register
preferences elsewhere.

Seen in:

- [quest_spawn_timeline_update][vc6-timeline-consumers-2026-09-11]: the
  eligibility check accepts a LEA and rejects a COPY, so both loads end up on
  the entry symbol.
- [creature_update_all][creature-pointer-rematerialization-2026-09-22]: four
  removal routes; field-reference and pointer-bound-to-reference controls emit
  the canonical bytes.
- [creature_update_all][creature-pool-base-2026-09-22]: native stores four
  field pointers and keeps `&attack_cooldown` in EBP; the candidate
  rematerializes them from ESI whatever the declaration placement or scope.
- [player_update][]: removing the named cooldown pointer removes the extra
  address range and restores native BL/EAX choices.

### Pool index spelling: shared byte offset or scaled addressing

**For records whose size is not a power of two (152 = 8 × 19), repeated
`pool[i].f` makes C2 share one byte offset `152*i` and address fields as
`[reg+pool+f]`; indexing through a local base pointer, binding a member by
reference, or using a field once keeps `19*i` with SIB scale 8.** A named byte
offset shared by two expressions gives the shift form, and another genuine
indexed use keeps the element index live. The choice is made in lowering,
before allocation.

```text
lea eax,[esi+esi*8]; lea esi,[esi+eax*2]; shl esi,3   ; [esi+abs]   shared offset
lea eax,[esi+esi*8]; lea esi,[esi+eax*2]              ; [esi*8+abs] scaled
```

Seen in:

- [creature_update_all][creature-pool-base-2026-09-22]: a local pool base gives
  native scaled addressing for every access, while the follow-link arms keep
  `creature_pool` because native uses `shl` there.
- [projectile_render][render-owner-lifetimes-2026-09-11]: a named byte offset
  shared by both ion-chain coordinate expressions recovers native `shl esi,3`.
- [player_render][overlay-render-owners-2026-09-12]: binding the position
  member by reference restores `[ecx*8+field]` reads.
- [creature_handle_death][]: the indexed active guard plus the pointer opening
  keeps the element index live for scaled operands; neither alone matches.

### Allocation is whole-function

**C2 rotates scratch registers through EAX/ECX/EDX and advances a shared
preference cursor across temporaries, and register costs include preferences
inherited from related ranges such as an LEA base.** Inserting or removing a
temporary anywhere, including a wrapper helper or a boolean, shifts every later
pick. Two identical arms get different registers, which also blocks
cross-jumping. Locally plausible changes add up until one more site crosses an
allocation boundary and the whole function's coloring flips.

Seen in:

- [player_update][]: wrapper helpers for perk counts and key tests put every
  load on the wrong rotation slot; any three of five shotgun loops reusing
  `move_delta` tie, while four or more lose heavily.
- [player_update][player-update-residuals-2026-09-27]: one range inherits an
  ECX preference from an LEA base; clearing only that preference fixes exactly
  three instructions.
- [statistics_update_check_worker][]: an explicit receive-loop break reorders
  the traversal, so the shared cursor gives the scanner addresses ECX, EDX and
  EAX as native does.
- [grim_state_init][]: a native-looking 16×16 row cursor regresses in every
  combination until the shared-y, local-column lifetime fix.

### Long-lived values and named booleans

**Long-lived flags and named integers get low or negative priority.** In
practice a spill or displacement comes from interference with a coexisting
temporary (pressure split markers) or from an extended live range. A named
`bool` for a call result can materialize 0/1 where native tests AL directly,
although a named compound predicate can also set arm order.

Seen in:

- [player_update][player-update-residuals-2026-09-27]: the flag's negative
  priority does not explain its spill; raising it changes nothing. The cause is
  a pending-split marker that the coexisting `&player->shot_cooldown` address
  temporary places at calls and swap instructions.
- [projectile_update][projectile-primary-secondary-residuals-2026-09-13]: a
  named integer extends a live range and displaces the native creature-offset
  register.
- [highscore_screen_update][highscore-label-bitcopy-2026-09-22]: a named
  boolean version result adds boolean materialization.
- [controls_menu_update][]: toggling the capture slot directly instead of
  through a `was_idle` boolean restores the long-lived zero register.
- [play_game_menu_update][]: naming the roomy-layout predicate as a `bool`
  recovers native arm order.

### Callee-saved pushes are shrink-wrapped

**VC6 places `push esi`/`push edi` according to which paths need the
register.** An early return before the heavy section, or a post-guard body
moved into an inline helper, delays the push into that region. Duplicated early
returns force the push into the prologue, and funnelling paths into one shared
final call and return can also delay it. Lexical declaration scope does not
move the push. Native sometimes saves in the prologue and sometimes
shrink-wraps; reproduce whichever native shows.

Seen in:

- [bonus_spawn_at_pos][]: native saves only EDI before the guard and pushes ESI
  before `bonus_alloc_slot`. `if (invalid) return S; return
  inline_valid_body(...);` reproduces it; guard helpers, gotos and declaration
  splits do not.
- [console_update][]: a shared Enter poll and normal return delays
  `push esi; push edi` to before the Right-arrow poll; pointer declaration
  placement is neutral.
- [effect_spawn_ion_hit_sparks][]: an early return delays reserving ESI/EDI
  until at least one spark will run.
- [sfx_entry_start_playback][]: delaying `result = 0` shrink-wraps the ESI save,
  but native keeps the prologue save; it needs delayed init plus
  return-in-arm together.

### Reusing one variable for successive values

**When native overwrites one stack slot or register with a sequence of values,
the original usually reused one local for disjoint lifetimes.** Separate named
locals get separate homes or an `fld st(0)` duplicate. Because coloring follows
use counts, raising a scalar's uses by reuse can also move it into the native
group. A fresh named local for one value is often neutral because an unnamed
temporary already sits there. Native slot sharing does not prove a shared
source variable.

Source: `scale = fade; ...; scale = factor * scale;`,
`total_minutes -= total_hours * 60;`.

Seen in:

- [bonus_render][]: the weapon-icon fade is overwritten in place by the pulsed
  scale, and the phase variable is reused as scaled half-height.
- [ui_render_hud][hud-exact-2026-09-12]: four scalar reuses (`hud_y`, `fade`,
  `draw_factor`, `render_value`) are exact only all together.
- [player_update][player-update-arithmetic-2026-09-27]: reusing the heavily
  used `scalar` for the smoke angle gives the native home; a separate
  `smoke_angle` lands elsewhere.
- [player_render][overlay-dead-body-size-2026-09-11]: reloading dimensions into
  `sprite_size` moves the store and load off an unnamed argument temporary;
  only ESP displacements change.

### Dead stores survive late-removed reads and lowered intrinsics

**C2's last DCE is one backward pass over precomputed liveness.** A definition
whose reads disappear later (redundant loads deleted by CSE, or compares
removed in the flow-graph rebuild) survives and is demoted to a memory store
that is never read. `memset` or `ZeroMemory` followed by field stores, and
byte-copy loops turned into the copy intrinsic, expand after global
optimization into symbol-backed stores that skip copy cleanup, so overwritten
or unused stores remain. Such adjacent same-slot dead overwrites are rare: a
narrow pattern scan found four in the exe.

Seen in:

- [dx_get_version_from_dxdiag][vc6-redundant-stores-2026-09-11]: `ZeroMemory`
  or `memset` plus assignments is exact; an aggregate `{0}` or field-only
  initialization drops the zeroing stores, and `/Oi-` leaves a `memset` call.
- [quest_spawn_timeline_update][vc6-timeline-pointer-home-2026-09-12]
  (witness): a pointer pair copied byte by byte leaves the native dead triplet;
  `memcpy` and assignment variants do not.
- [quest_spawn_timeline_update][quest-plain-guard-2026-09-28] (witness): a
  redundant pointer-comparison guard (`template_id != 0 && count <= 0`) leaves a
  dead comparison temporary that the flow-graph rebuild orphans and
  live-range construction demotes; `count < 1` changes the IL and loses it.
- [quest_spawn_timeline_update][quest-history-sources-2026-09-28]: CSE makes
  two entry loads dead, and the surviving definition is emitted as
  `mov [esp+0x10],esi`.

The witnesses demonstrate the mechanism; the canonical exact source avoids the
triplet.

## Stack layout

Homes come from a conflict graph over lifetimes, ordered by size and use
counts, or by use density for large frames. Scope and reuse decide homes;
declaration order does not.

### Slots are colored by lifetime, then size and use count

**C2 groups locals that do not interfere, ordered by increasing size and then
decreasing use count (parameters are scanned separately), so homes depend on
lifetimes and uses, not declaration order.** Narrowing a one-shot object's
scope, giving each arm its own short-lived vector, or ending a lifetime before
a join lets later values reuse its slot and can shrink the frame. Extending a
lifetime or adding an owner shifts neighbours. Lifetime fixes often only work
in combination across homologous sites.

```cpp
{ vec2 back_pos(x, y); ui_button_update(&back_button, &back_pos); }
```

Seen in:

- [typo_player_update][]: separate lexical scopes plus a fresh pellet position
  per iteration are exact; one flat scope or a hoisted pellet vector is not.
- [quest_select_menu_update][]: a short block around the Back position ends
  its lifetime at `ui_button_update`, and the frame drops to native size.
- [ui_render_hud][hud-stack-coloring-2026-09-10]: a model reproduces every
  group and offset; a float with one more use than a parameter sorting ahead of
  it exposes the two-pass parameter scan.
- [grim_state_init][]: a shared function-scope `y` plus a block-local column in
  every atlas loop keeps the spills at `[esp+0xc]`/`[esp+0x10]`; a uniform row
  cursor shrinks the frame and coalesces both spills.
- [player_update][]: under 9044 (1.9.8), liveness stops before an object's
  first possible definition, and an integer-view store (`x = 1.0f`) ends a
  range only when it is the first definition on every path. A reused `scalar`
  stayed live into the smoke block; per-purpose locals give native's slots in
  both builds.

Braces alone are sometimes neutral ([mods_menu_update][]), and repeated
assignment of one named object can keep assignment temporaries
([ui_render_hud][]).

### Large frames are ordered by use density, unstably

**When the coloring groups exceed 0x80 bytes, C2 sorts them by
`floor(1000 * uses / size)` descending with a middle-pivot quicksort that has
no tie-break, then places them backwards.** Equal-density groups land in an
order that depends on the whole set, and one extra use can move a group past
its neighbour. A float local defined only by integer-typed stores is never
killed and stays live across its whole loop.

Seen in:

- [projectile_render][]: `half_size` and `base` have equal weight and sort
  opposite to native until shared `step_x`/`step_y` owners are added.
- [highscore_screen_update][highscore-filter-storage-2026-09-22]: the model
  predicts every offset; the hover flag and right panel tie at density 4000,
  and a stable sort predicts the wrong offsets.

### Dead incoming-argument slots hold locals

**Once an argument is dead, VC6 reuses its stack slot for a local, so the frame
holds only the remaining genuine locals.** Extending a buffer's lifetime past
that point forces a real slot.

Seen in:

- [resource_open_read][]: the dead `size_out` slot holds the packed-entry size
  after the output pointer moves to EBX.
- [fx_spawn_secondary_projectile][]: the dead `pos` slot holds the cosine; one
  real local for the sine gives native's leading `push ecx`.
- [grim_set_color_ptr][]: the input pointer stays in ESI and its dead parameter
  home holds the four-byte local.
- [wrap_text_to_width_alloc][]: initializing the terminator before `strlen`
  extends the buffer lifetime, so VC6 reserves a slot instead of reusing the
  dead first-parameter slot.

### Declared extent limits slot overlap

**The allocator charges a local its full declared extent**, and a buffer's
declared size decides whether it can overlay an ended larger record. In one
compiler witness, a copied local kept in the implicit alias sets of pointer
loads and a call conflicted with every local and could not share a slot.

Seen in:

- [quest_spawn_timeline_update][vc6-timeline-decomposition-2026-09-12]
  (witness): shrinking the copied pair from 8 to 4 bytes gives the 28-byte
  frame.
- [quest_spawn_timeline_update][timeline-copy-aliases-2026-09-22] (witness):
  pruning only the copied local's alias link restores sharing with the spread
  slot. This is a diagnostic, not a match; do not generalize it to every
  address-escaping local.
- [mods_menu_update][]: a 256-byte version buffer overlays the ended
  `_finddata_t` to give the native `0x144` frame; a small buffer keeps them
  separate, and 256 and 260 are indistinguishable.

### Small local arrays: scalar replacement or an aligned frame

**C2 scalar-replaces a small local array of scalars into registers and
spills.** A local array of small float structs, separate point structs, or a
function-wide vector array makes C2 align the frame with `and esp,-8`,
sometimes with an EBP frame. Per-field copies make a float array
register-promotable, which changes x87 allocation.

Seen in:

- [grim_draw_quad][]: a `GrimPoint` array or separate points align the frame;
  per-field copies change x87 allocation.
- [terrain_generate_random][]: the three-entry texture-handle array becomes two
  registers plus one spill, which accounts for the `0x24` frame.
- [tutorial_timeline_update][]: a function-wide three-vector array forces
  8-byte alignment and an EBP frame; branch-local vectors coalesce within the
  native frame.

## Block layout and control flow

VC6 lays the then-arm out as the fallthrough, cross-jumps identical tails and
runs a gated late block mover. Arm order and where returns sit matter more
than goto placement, which C2 rebuilds.

### Then-arm fallthrough and predicate structure

**VC6 usually makes the then-arm the fallthrough, and reversing predicate and
arms can recover native direction.** C2 often canonicalizes simple arm swaps,
gotos and structured ifs to the same layout, though. When it does, native
placement comes from predicate structure: a named predicate, a separately
guarded phase, or a shared tail on a live flag.

Seen in:

- [player_update][player-projectile-boundaries]: reversing predicate and arm
  order recovers the native autoplay branch with a tiny local change.
- [game_frame_update][]: testing the zero-timeline case first leaves the
  constant `1.0f` result on the native fallthrough.
- [play_game_menu_update][]: physically inverted arms, structured control flow
  and a full goto reconstruction all compile byte-identically; naming the
  compound predicate as a `bool` sets the native arm order.
- [creature_apply_damage][]: separating the bullet heading change into its own
  guarded phase places the Ion Gun Master arm after the shock loop; natural
  if/else, inverted nesting and switch spellings could not recover it without
  regressing.
- [demo_purchase_screen_update][]: moving only the selector compiles back to
  the baseline byte for byte; sharing the UI tail and guarding on the live
  global flag gives native placement.

### Identical tails are cross-jumped

**`jump_optimize` cross-jumps identical tails across arms when the matched byte
sum is above 20; exactly 20 is refused.** Stack operands compare by symbol, so
arms building into the same local merge, while scoped or branch-owned objects
and different rotation temporaries stay separate. Duplicated calls in each arm
keep per-arm argument pushes jumping into one shared call. Early returns are
rebuilt into a shared epilogue without gotos. The surviving copy of a shared
exit tail is the one in the arm whose return is the newest reference to the
exit label.

Seen in:

- [player_update][]: movement twins building into the same `move_delta` merge
  (byte sum 22), a weapon-arm merge is refused at exactly 20, and one
  function-wide spawn temporary merged one-shot tails until each arm got a
  scoped `spawn_pos`.
- [bonus_try_spawn_on_kill][]: a local rejection flag before one shared cleanup
  is exact; combining the conditions tail-merges all three cleanup paths.
- [highscore_rank_index][]: sharing only the `return highscore_table_count`
  fallback is exact; also sharing the success return is not.
- [grim_is_key_active][]: native keeps the shared `fmul`/`fabs`/`fcomp` tail in
  the `0x13f` arm. If-chains and helpers keep it in the last arm, a switch
  gives a jump table, and only a goto ladder is exact.

### The block mover clones short tails

**Mover loop 2 duplicates a jump-target tail into its predecessor when its
size estimate is about 20 bytes or less.** Observed estimates of 19 bytes are
cloned and 21 bytes shared. The estimate is taken before final encoding and
counts codeless rounding markers. Locals are sized from global frame flags
that the driver sets for the current function only after the mover, so they
come from the previous function in the translation unit: `[ebp+disp8]` (3
bytes) when first in the TU or after an EBP-frame function, `[esp+disp8]` plus
SIB (4 bytes) after an FPO function. A tail on the threshold is cloned or
shared depending on what precedes it, and no in-function spelling changes it.

Seen in:

- [player_update][]: the demo-angle `fld`/`fld`/`fpatan`/`fsub` tail estimates
  to 19 bytes when first in its TU and is cloned. Defining the FPO helper
  `player_heading_approach_target` first makes it 21 bytes and shared, which
  is exact.
- [player_update][player-update-residuals-2026-09-27]: raising the `fpatan`
  estimate above the threshold fixes exactly this region; vector-copy, helper
  and branch-local angle spellings do not.

This mechanism is traced at one site. [grim_draw_text_mono][] also depends on
its TU predecessor for tail sharing (it keeps its suffix copies only after
`grim_draw_quad_points`), but its notes attribute that to optimizer
tail-merging state, not to the mover.

### The late range mover needs an unconditional skip

**Early reverse postorder lays blocks out in dominance and source order, and
manual tail labels are undone by the rebuild.** A late pass moves a block range
only when an unconditional jump, not to the next instruction, skips it and the
destination's predecessor ends unconditionally. Jumps to the next node vanish
earlier. The skip jump often comes from CSE threading of known values, so
reordering independent flat compound rules (with an identical final CFG)
changes intermediate IL and layout. Predicate inversion, switch rewrites,
synthetic shared returns and goto tails do not reach it.

Seen in:

- [bonus_pick_random_type][]: six flat rules with the stage-4 Freeze rule after
  the stage-5 Nuke rule are exact; adjacent stage-4 rules or nested `else if`
  are not.
- [bonus_pick][bonus-pick-layout-trace-2026-09-13]: a conditional predecessor
  rejects the move, and an explicit tail label is undone by the RPO rebuild.
- [dsound_restore_buffer][bonus-pick-flow-graph-2026-09-11]: positive control.
  An ordinary `do` loop leaves its test after a backward jump following
  `Sleep(10)`.

### switch lowering and case order

**A switch with enough cases becomes an unsigned range check plus a jump table
(with a byte index map when there are few targets), emitted as compiler-local
data inside the function.** Small switches with separate case bodies lower to a
`sub`/`dec` compare chain, which cross-jumping then merges, so a compare chain
does not by itself prove an if-ladder; only a jump table rules one out. Case
source order sets block layout while the table stays numeric.

```text
cmp eax,0xec; ja default; xor ecx,ecx; mov cl,[idx+eax]; jmp [tbl+ecx*4]
```

Seen in:

- [grim_zlib_status_is_error][]: three dense cases with separate bodies lower
  to a `sub`/`dec` chain; fall-through cases would become a range check.
- [game_state_set][]: complete switch variants emit a jump table that the
  native compare chain contradicts, even though they scored higher.
- [input_configure_for_label][]: case order 0, 3, 1, 2, 4, 5 decides block
  layout; the table still maps ids numerically.
- [controls_menu_update][]: three byte lookup maps bounded by their guards;
  reading past the bound into padding and the next jump table was a tooling
  error, not code.

### Ternary, if/else or per-branch calls

**A conditional expression assigned once gives one shared result store and
different long-lived registers; if/else with an assignment or call in each arm
stores or calls per arm, and VC6 then merges the common call with conditional
argument pushes.** Native evidence picks the form, and some functions need
both.

```c
if (i & 1) spawn(9, ...); else spawn(11, ...);  /* push 9 / push 11, one call */
spawn((i & 1) ? 9 : 11, ...);                   /* arithmetic select */
```

Seen in:

- [player_update][player-hot-tempered-2026-09-14] (Hot Tempered): separate
  branches merge the argument construction and call, keeping native
  conditional `push 9` / `push 11`.
- [console_render][]: a ternary for the first selection and an `if` for the
  second keep native's long-lived EBP and EDI.
- [typo_target_name_draw_labels][]: a conditional expression before the clamp
  recovers the native float store and reload; nesting the clamp folds one
  instruction.
- [ui_render_hud][]: duplicating `grim_set_color` across the filled and
  unfilled branches instead of a named ternary recovers the load-then-branch
  shape.

### Forward exits and labels inside an arm

**A guarded block with several forward exits to one join can be written as
`do { if (a) break; ... } while (0)`.** Nested ifs or early returns often
compile identically, because cross-jumping rebuilds shared exits and returns.
A native edge into the middle of another arm can need a single label inside
that arm.

Seen in:

- [statistics_menu_update][]: the total readout as a `do`/`while (0)` block is
  the exact idiom, also used by the Quest Failed callback.
- [grim_set_config_var][audit-grim]: `goto copy_config_tail` was replaced by
  full assignments, and cross-jumping rebuilt the four-word tail
  byte-identically. The Grim audit replaced other `do`/`while (0)` exits with
  early returns or nested ifs the same way.
- [sfx_entry_start_playback][]: a `stream_playback:` label for the
  restore-to-stream edge improves the match but is not exact.

## Floating point and x87

Gameplay runs at x87 PC24, but matching depends on where values are stored as
float32 (visible at PC64), on operand order, and on what C2 folds. Verify with
PC24 and PC64 execution fixtures, not only instruction diffs.

### Float32 store points follow expression and object boundaries

**x87 intermediates stay wide inside one expression; float32 stores appear at
expression and object boundaries, but not uniformly per construct.** Sharing a
named vector across uses or copying an aggregate adds early float32 stores. A
complete vector expression can still keep X wide while Y is stored and
reloaded, and a named float local may stay on x87. Recomputing a product at
each use keeps it wide. Treat each site's store pattern as evidence to
reproduce, not as something predictable from the spelling class.

Seen in:

- [projectile_render][ion-chain-product-2026-09-10] (ion chain): a shared named
  side vector adds a float32 store for X; repeating the product at the four
  corners keeps it on x87.
- [projectile_render][fire-overlay-lifetimes-2026-09-13] (Fire overlay): PC64
  witnesses show scalar arguments fail on Y and an aggregate copy fails on X;
  only the complete vector expression `camera + pos - 32` matches native.
- [plaguebearer_spread_infection][]: `d = dx*dx; d += dy*dy;` keeps both deltas
  on the FPU around `fsqrt` exactly.
- [creature_update_all][creature-corpse-vectors-2026-09-13]: the half-size
  stays on x87 even when named as a float; a vector constructor followed by
  vector subtraction recovers the native `fst`.

### fst-and-keep versus fstp-and-reload

**If the source consumes a just-assigned float through its memory destination,
VC6 emits `fstp` and then `fld` from that location; if it consumes a local, C2
keeps the value on x87 with a non-popping `fst`.** Routing only the first
consumer through a local gives `fst` for that use and a later field reload for
the others.

```cpp
float cur = (p->turn_speed = ...);  // fst [turn_speed], keep st(0)
body_heading(cur);
aim_heading(p->turn_speed);         // fld [turn_speed]
```

Seen in:

- [player_update][player-update-arithmetic-2026-09-27]: native stores
  `turn_speed` with `fst`, keeps it for the body heading and reloads the field
  for the aim heading; a named `current_turn_speed` used only first reproduces
  it.
- [music_update_fades][]: using the stored `music_track_volume[i]` for both the
  clamp compare and the argument recovers native store, pop and reload.
- [creature_spawn_template][]: templates keep randomized size on x87 with
  non-popping stores, and one random tint scalar across the channel stores.
- [creature_update_all][creature-retarget-distance-2026-09-13]: native keeps
  the alternate distance on x87 while storing its float copy and compares the
  wide value.

### Parentheses emit FROUND nodes

**C1 emits a codeless `FROUND` tuple for each parenthesis level around a
non-leaf float expression.** It occupies a scheduler cycle, splits association
chains and counts toward C2's 81-node scheduling window. Since the scheduler
reorders only within a window, redundant parentheses move later boundaries and
change instruction interleaving. Forward propagation of a single-use float
local adds the same marker. Casts add none: `(float)(expr)` gets exactly one,
from its parentheses. The original source contained such no-op parentheses.

Source: `move_delta.y = (random_offset.y * 15.0f);`,
`(elapsed * 0.001f) * 9.0f` (two `fmul` instead of a folded `0.009f`). Native:
a store or push on the other side of an `fstp`, `fsin` or interface load, or a
moved spill. Details are in [codeless tuples][c2-codeless] and
[plain float sources][c2-plain-float].

Seen in:

- [player_update][]: all the smoke-sprite arms need the parenthesized Y lane,
  so the previous sprite's color stores are no longer scheduled before the
  `fstp`.
- [projectile_render][projectile-plague-schedule-2026-09-28] (plague):
  parenthesizing the draw coordinates and both trig expressions changes only
  the mismatching window, which then matches; coordinates alone regress.
- [highscore_screen_update][highscore-state-owners-2026-09-22]: the first
  window has 81 nodes; a dependency chain inside one window cannot be reversed
  by reprioritizing.

### What C2 folds and reorders in float expressions

**C2 keeps source grouping for additive constant chains**: `x + 64 + 16` and
`(y + 114) - 14` stay separate `fadd`/`fsub`, and at PC24 they differ from
pre-folded constants. It does fold `a + -b` into `fsub`. Unparenthesized
product chains and products repeated per component can be reassociated or have
adjacent constants combined. Explicit parentheses, statement staging, or one
scale computed into a local pin the native factor order.

Seen in:

- [player_update][player-update-arithmetic-2026-09-27]: without parentheses C2
  interchanges the first two multiplications; parenthesizing the movement
  lanes fixes the execution mismatches.
- [projectile_update][projectile-particle-impact-2026-09-11]: the repeated
  per-component bounce product lets VC6 reassociate velocity, integer and
  constant; scaling once fixes most failing states.
- [highscore_screen_update][highscore-residual-decomposition-2026-09-13]:
  native label y is `y + 114 - 14` with 32-bit constants; folding or double
  expressions lose it.
- [grim_draw_quad][]: per-lane `p = c; p += d;` and a single-use `neg_dx` keep
  native `fchs`, because C2 folds `a + -b` into `fsub`.

### x87 operand orientation follows source order

**VC6 loads the left operand and `fcomp`s the right, so `0.0f < x` and
`x > 0.0f` give different orientation and `fnstsw` masks.** Interval and clamp
test order sets which value is held for `fcomp st(1)`. Multi-term sums are
evaluated left-associatively in source order, and reversing integer
commutative operands can change global load order. Commuting a single op's
operands is often canonicalized, and operand order can also be id-keyed.

Seen in:

- [player_update][]: `0.0f < player->ammo` restores the native C0 test; the
  clamp `1.0f < length` gives the held `fcomp st(1)`.
- [game_startup_init][]: `timer >= 2 && timer < 4` reproduces the overlapping
  x87 comparisons.
- [play_game_menu_update][]: rotating the first sum to Rush + quest + Survival
  gives native load order at all four tests.
- [projectile_render][]: `camera + position - 30 + displacement` reproduces the
  base-first schedule, while every X/Y product-order variant in the plasma
  loops is byte-identical.

### double locals and cast placement

**A value declared `double` is not narrowed through memory, so C2 keeps it on
x87 across later work and narrows it only at an explicit `(float)` use**, which
gives a non-popping `fst` plus `fcomp [mem]`. Where the cast sits decides
single versus double constants: casting each trig result keeps the products in
single precision, while casting the whole expression promotes the constants to
double.

Seen in:

- [effect_spawn_splitter_hit_burst][]: `distance` as `double` stays live across
  `fcos`/`fsin`, with `fmul st(1)` twice and a pop after the second coordinate.
- [effect_spawn_blood_splatter][]: a `double` direction stays live across `cos`
  and `sin`; a float direction spills and reloads.
- [creature_find_nearest][]: keeping `sqrt` as `double` and casting only the
  compare operand gives native `fst` plus `fcomp [min_dist]`; a float helper
  regresses.
- [projectile_update][]: casting the whole expression promoted the constants to
  double; per-result float casts fix it.

### Float literals must round to the native bits

**C1 converts each decimal literal to the nearest f32, and short spellings can
land one ULP away from the native constant.** Constant-folded products such as
`0.001f * 0.7f` round to their own value, which may differ from the direct
literal. The native bits pin which spelling the original used. Normalized
matches hide this, so dump the immediate bits.

Seen in:

- [player_update][]: `5.497787f` compiles to `0x40afeddf`; `5.4977875f` gives
  native `0x40afede0`.
- [play_game_menu_update][]: `0.0009f` gives `0x3a6bedfa`; the exact decimal or
  `0.09f * 0.01f` gives native `0x3a6bedfb`.
- [ui_button_update][]: the folded `0.001f * 0.7f` is native `0x3a378035`, one
  ULP above a standalone `0.0007f`.
- [creature_spawn][]: `0.0001f` gives `0x38d1b717`; `0.000100000005f` recovers
  native `0x38d1b718`.
- [ui_focus_draw][]: `0.8f / 1000.0f` produces the native rounded constant.

### A local snapshot of a float global

**A float global read twice is loaded twice; a block-local snapshot loads it
once and duplicates it with `fld st(0)`.** The snapshot also changes which arms
the optimizer can merge, in either direction.

```cpp
const float movement_dt = frame_dt;   // fld [frame_dt]; fld st(0)
v.x = movement_dt * m.x;
v.y = movement_dt * m.y;
```

Seen in:

- [player_update][]: snapshots at three movement sites match, and applying them
  to every site overshoots; the snapshot keeps native-distinct arms apart.
- [player_update][player-point-frame-2026-09-11] (point-click): paired
  branch-local snapshots recover the single load and duplicate, and let VC6
  merge the common tail.
- [effects_update][]: a local `dt` and a two-component movement aggregate give a
  single load, x87 duplication and two rounded stores.

### Integer views of a float: memcpy and one-float wrappers

**A plain float local initialized from a constant is folded or kept on x87, and
a plain float-to-float copy already becomes integer moves without a stored
home.** A `memcpy`, a 4-byte aggregate copy or a one-float wrapper class
creates overlapping float and unsigned views of the object, so the float store
stays in memory and the value is reloaded as an integer, which is the dead or
reused store native has. Small `memcpy` calls are scalarized before the late
passes. See [plain float sources][c2-plain-float].

Seen in:

- [projectile_spawn][]: the default damage as a plain float local is folded to
  constants; `memcpy` of it reproduces native integer loads and stores.
- [player_render][]: alpha as a one-float wrapper leaves native's dead
  `[esp+0x24]` store; plain float spellings fall short.
- [projectile_render][remaining-storage-controls-2026-09-26] (K2): a 4-byte
  typed copy of the zero alpha creates overlapping views, and ESI is loaded
  from the stored zero.
- [highscore_screen_update][highscore-label-bitcopy-2026-09-22]: a 4-byte
  `memcpy` of label X removes both the Y copy of an aggregate copy and the
  scalar's stack store and reload.

### Global CSE merges separately written float expressions

**Available-expression CSE gives textually separate identical float expressions
one owner and deletes the later copies.** The first result is then saved as
float32 and reloaded across calls, adding a rounding store and a stack slot
that native may not have. Reading an operand through a reference to the real
field can stop the premature merge; negated constants or double casts change
other bytes.

Seen in:

- [highscore_screen_update][highscore-float-reuse-2026-09-22]: the two profile
  `Y + 114` additions become one owner and the later one is deleted; denying
  reuse in the compiler gives native's bytes, and `/Op` keeps the save and
  reload.
- [projectile_update][projectile-ownership-and-stack-2026-09-13]: a reference
  to the real field for the second speed multiplier prevents the premature
  merge and reproduces the native impulse window.
- [highscore_screen_update][highscore-filter-storage-2026-09-22]: copy and
  order controls do not change the CSE decision; an address-escaping local
  makes the compiler recompute the Y sums instead.

### math.h inline float wrappers

**VC6's `math.h` provides `sinf` and `atan2f` as inline wrappers with float
arguments around the double functions, and the 2003 SDK uses `atan2f` in
`VEC2_Angle`.** Calling the wrapper instead of `(float)atan2(...)` changes the
float argument and return boundaries: X-then-Y loads with `fxch` before
`fpatan`, an otherwise unused address calculation before `fpatan`, and
different scheduling of nearby work.

Seen in:

- [player_update][player-fire-cough-2026-09-14] (Fire Cough): consuming
  `vec2_sub`'s result through `atan2f` recovers the native X load, Y load and
  `fxch`.
- [projectile_update][projectile-rounding-boundaries-2026-09-13]: `atan2f`
  recovers the unused address calculation between the component loads and
  `fpatan` in the ion-chain direction.
- [player_render][overlay-exact-2026-09-12]: `sinf` on the inner shield radius
  restores the outer-radius and rotation schedule.

### Integer values stay integer until the source converts them

**The position of the int-to-float conversion in the source decides where
`fild` lands relative to other stores and calls.** Naming a `rand()` result or
its remainder in a block-local `int` gives it a lifetime that lets C2 put
independent stores between the call, the `idiv` and the conversion, as native
does. Naming the converted operands also picks the conversion instruction.

```cpp
int roll = crt_rand();
creature->color.b = 0.38f;                     // stored before cdq; idiv
float s = (float)(roll % 0x1e) * 0.01f + 0.6f;
```

Seen in:

- [creature_spawn_template][]: block-local roll and remainder lifetimes at
  several template sites gain together; template 0x34's speed roll and splits
  through a function-wide roll are negative (one extra instruction).
- [creature_spawn_template][spawn-exact-2026-09-13]: native separates the
  integer remainder from the float conversion across the alpha stores.
- [projectile_update][projectile-residual-decomposition-2026-09-13]: keep the
  first RNG result an integer until the second draw.
- [game_frame_update][]: converting the elapsed id and limit to named floats
  before dividing gives `fild; fild; fdivp` instead of `fidiv`.

## Instruction selection

Types, signedness and comparison spellings go almost literally into
instructions.

### Source types select instructions

**Declared signedness and width map straight to instructions.** Signed `%` by a
power of two gets a mask plus a negative-remainder fixup, signed `/` gets `sar`
with sign adjust, and other constants get magic multiplies. `signed char`
fields load with `movsx`. Unsigned-to-float conversion pushes a zero high dword
and uses `fild qword`. Narrow `unsigned short` parameters get `and 0xffff` per
argument. A byte local with `>>=` stays byte-width.

Seen in:

- [quest_build_knee_deep_in_the_dead][]: signed `wave % 8` is required for the
  native correction sequence even though `wave` is never negative.
- [grim_draw_fullscreen_color][]: unsigned backbuffer dimensions give the native
  `push 0; push reg; fild qword [esp]` schedule with ordinary casts.
- [creature_update_all][]: native always loads `target_player` with `movsx`, so
  the field is `signed char`.
- [dx_version_pack_4x16][]: `unsigned short` parameters give `and 0xffff` on
  every argument; with 32-bit parameters VC6 proves two masks redundant.
- [grim_keyboard_key_down][]: `unsigned char r = state[key]; r >>= 7; return r;`
  keeps the byte-width load, `shr al,7` and return.

### Integer comparison spellings are kept literally

**C1 and C2 do not canonicalize equivalent integer comparisons**, so the
source's constant and form survive into the `cmp`/`jcc`, and equivalent
predicates can even take different optimization paths. A byte compared to the
literal 1 emits `cmp cl,1`.

Seen in:

- [creature_spawn_template][]: `<= 0x100` instead of the equivalent `< 0x101`
  recovers the compare and branch in the grid loops.
- [quest_build_evil_zombies_at_large][]: `spawn_count - 4 < 10` explains
  `lea eax,[esi-4]; cmp eax,10`.
- [quest_spawn_timeline_update][quest-plain-guard-2026-09-28]: `count < 1`
  changes the optimization and loses the pair that `count <= 0` keeps.
- [grim_config_dialog_populate_display_modes][]: comparing the windowed byte to
  1 produces native `cmp cl,1`.

### Scale-one SIB order differs only in encoded bytes

**For scale-one addresses C2 picks the SIB base and index from the sorted
address sum, so the order depends on symbol numbering and on IV and ownership
structure.** Swapped registers compute the same address, so normalized scores
call them equal; only encoded-body comparison catches them.

```text
8d 44 33 2c   lea eax,[ebx+esi+0x2c]
8d 44 1e 2c   lea eax,[esi+ebx+0x2c]
```

Seen in:

- [ui_menu_layout_init][audit-exe]: reusing the function-level `i` (VC6's
  `for` scope leaks) swaps SIB base and index in an unrelated block; only the
  encoded-body check catches it.
- [quest_build_the_beating][]: deriving offset and trigger from the zero-based
  wave index flips the SIB to native; parenthesized forms keep the old encoding.
- [grim_window_proc][audit-grim]: moving `case WM_MOUSEMOVE` before `WM_CHAR`
  gives the `WM_CHAR` buffer stores native's SIB order.

## Inlining and intrinsics

Under `/O2` the CRT memory and string functions expand inline. Inline helpers
stay visible through reloads and boundaries, and only explicitly inline helpers
are inlined.

### Fixed lowerings of memory and string functions

**Fixed-size `memcpy` and struct assignment lower identically, `memset` of 8
bytes becomes a zero register plus two stores, larger clears and indexed
zeroing loops become `rep stosd`, and `strcpy`/`strcmp`/`strlen` expand
inline.** A loop filling every element with one struct becomes a peeled first
store plus an overlapping `rep movsd`. A string-literal array initializer lowers
differently from `memset` plus character stores. A two-entry constant loop
unrolls, but a three-iteration loop containing calls stays a loop. The
scheduler interleaves these expansions with neighbouring stores, and `strcmp`
operand order sets the inline compare order.

Seen in:

- [unlocked_perks_database_update][]: `memset(columnWidth, 0, 8)` and a
  two-entry loop both unroll to two stores; a whole-array clear regresses.
- [highscore_sync_worker][]: a string-literal initializer lowers to a string
  copy plus a partial zero tail; `memset` plus character stores recovers the
  native code.
- [grim_state_init][audit-grim]: an overlapping `memcpy` smear became a plain
  fill loop; C2 peels the first store and emits the same `rep movsd`.
- [player_reset_all][]: a forward indexed perk-clear loop becomes `rep stosd`
  with the offset in EAX.
- [sfx_entry_start_playback][]: a three-iteration stream-fill loop stays a loop,
  so native's three explicit calls come from three calls in source.

### Inline helper boundaries leave traces

**Ordinary free helpers are not inlined under this profile; `inline` or
`__forceinline` helpers are, but their boundaries stay visible.** A global
pointer argument is re-read once per helper. A helper returning a sentinel
leaves a redundant post-call test. A by-value scalar formal is a copy that can
be scheduled early, while `const T &` borrows the caller's lvalue. Methods of a
local class stay out of line even with `__forceinline`.

Seen in:

- [grim_submit_vertices_transform][]: two inline helpers taking
  `grim_vertex_write_ptr` explain native's pointer reloads, one per helper.
- [music_load_track][]: an inlined free-slot helper returning -1 explains
  native's otherwise redundant `result == -1` test.
- [unlocked_perks_database_update][]: taking the width by `const int &` puts
  the dispatch load before `fild width`; a copied `int` pushes the height too
  early.
- [quest_build_zombie_masters][]: explicit `inline` keeps the helper boundary
  that places the `768.0f` load between the trigger and count stores; an
  ordinary free helper is not inlined.
- [config_load_presets][]: local-class methods stay out of line even with
  `__forceinline`; file-scope `__forceinline` restores the instruction count
  but is still not exact.

Often neutral: `inline` and `__forceinline` variants were identical in
[ui_cursor_render][] and [quest_build_nesting_grounds][].

### Inline growth budget and auto_inline

**VC6 inlines repeated constructor loops only up to an inline-growth budget,
then calls the vector-constructor helper.** With `/Ob2` it auto-inlines every
eligible static helper in a TU, which over-inlines relative to native. Where
native kept specific helpers out of line, `#pragma auto_inline(off)`/`(on)`
around those definitions reproduces it without editing library source
(`AUTO_INLINE_OFF=select_ncolors,create_colorindex` in `scratch.conf`).

Seen in:

- [ui_menu_template_pool_init][]: six direct constructor loops, then six helper
  calls after the budget is reached.
- [grim_jpeg_init_one_pass_quantizer][grim_jaz_jpeg_init_one_pass_quantizer]:
  `/O2 /Ob2 /G6` inlines all three helpers; `auto_inline` off for two matches.
- [zlib deflate_stored, fill_window, deflate_fast, deflate_slow][shared-decoder]:
  `/Ob2` reproduces them, including the inlined input reader.

## Calls and ABI

Return widths, cleanup coalescing and C++ member conventions reveal the true
signature even where decompilers guess wrong.

### Byte-sized returns write only AL

**A byte-sized return whose source type matches the value writes only AL
(`setcc` or `mov al`) with no normalization, leaving residue in upper EAX.** An
`int` return adds a zero extension. Converting a non-bool byte to a `bool`
return adds a normalization tail. So "bool writes only AL" holds only when the
returned value is already bool, such as a comparison or a bool field. A direct
comparison return compiles to `cmp`/`setcc` with no branch, and an ordered
unsigned three-way compare becomes `cmp`/`sbb`.

Seen in:

- [ui_button_update][]: returning an arbitrary-byte field as `bool` adds a
  normalization tail.
- [grim_is_key_down][]: a `bool` return of an `unsigned char` helper result adds
  normalization, and an `int` return adds a zero extension.
- [grim_is_texture_format_supported][]: the terminal `setge cl; mov al,cl`
  contradicts Binary Ninja's `int32_t` return.
- [dx_version_compare_4x16][]: ordered branches reproduce the final `cmp`/`sbb`.

### EAX residue in void functions; tail calls become jmp

**At `/O2` a call in tail position of a void function becomes a `jmp`.** A value
left in AL or EAX by a final call or a loop end pointer is incidental residue,
not a return value.

Seen in:

- [console_push_line][]: the apparent byte result is the last value left in AL;
  the method is `void`.
- [ui_render_loading][]: here and in `bonus_reset_availability` the final call
  or loop leaves EAX, but the exact source is `void`.
- [audio_shutdown_all][]: the final `dsound_shutdown` call is a tail jump.
- [game_status_global_init_thunk][]: 5-byte tail-call thunks referenced from
  the CRT initializer table.

### Struct-by-value returns use a hidden buffer

**A function or member returning a small struct by value gets a hidden
destination pointer as its first stack argument and returns it in EAX.** The
body is byte-identical to an explicit out-pointer contract, so the callee alone
cannot tell them apart. Callers consuming the result through a pointer or a
reference are identical too, but a named value local makes the caller reload
its address. Implicit converting constructors build 16-byte by-value arguments
directly in the outgoing stack area.

Native: ECX = `this`, `[esp+4]` = buffer, `[esp+8]` = `rhs`,
`mov eax,dest; ret 8`.

Seen in:

- [vec2_sub, vec2_add_out][vector-return-contract-2026-09-08]: both contracts
  give the same bodies and caller bodies; a named value local reloads with
  `lea`.
- [grim_get_config_var][]: the earlier `void (unsigned int *out, int id)`
  exposed the hidden buffer; returning by value reproduces the ESI save,
  four-dword copy and `retn 8`.
- [grim_init_system][]: overloaded implicit int and string constructors build
  each 16-byte by-value virtual-call argument on the outgoing stack.
- [grim_apply_config][]: the bool constructor writes only the first byte, while
  the int overload writes the first dword.

### Caller cleanup coalescing

**VC6 defers and merges `add esp,N` across adjacent cdecl calls in some
configurations.** A fixed-argument prototype lets cleanups combine where a
variadic one does not. The C frontend coalesces more aggressively than C++
(`/TP`). Nesting a call as an argument keeps its own cleanup point.

Seen in:

- [grim_backup_textures][]: the fixed `(char *, int)` logger declaration
  combines cleanup for adjacent calls as native does; the variadic one does
  not.
- [game_core_init][]: C mode coalesces five caller-cleaned arguments into one
  `add esp,0x14` and misses an instruction; C++ is required.
- [highscore_build_path][]: C++ emits the cleanup between `sprintf` and
  `console_printf`; C combines both.
- [config_ensure_file][]: passing the nested path-builder result directly
  recovers right-to-left evaluation and cleanup.

`/TP` was byte-neutral in many other profile matrices.

### Arguments are evaluated right to left

**VC6 evaluates call and constructor arguments right to left, so side-effecting
arguments such as `rand()` or picker calls run last-argument-first.** Writing a
call as a nested argument lets VC6 push the outer call's other arguments, call
the inner function, and finish arithmetic just before the outer call. A named
temporary forces the inner call earlier.

Seen in:

- [typo_target_name_assign_random][]: right-to-left evaluation calls the
  pickers in native random-draw order.
- [terrain_generate][]: native RNG order is rotation, Y, X, which a
  constructor plus `operator*=` explains.
- [mods_menu_update][]: `grim->draw(right - grim->measure(s), y, ...)` keeps
  the vtable in ESI and finishes the subtraction before the draw slot; a named
  `text_width` prevents it.

### C++ member calls and constructors

**Fixed-argument members and virtuals are `__thiscall` (ECX `this`, callee pops
with `retn N`); a varargs member falls back to cdecl with `this` pushed and a
plain `ret`.** `new T` with an inlined constructor emits an out-of-line
allocation-failure block that zeroes EAX, which a manual vptr store does not.
Each polymorphic class gets a scalar-deleting destructor (call the destructor,
test flag bit 0, conditionally call `operator delete`, return `this`) once a
constructor instantiates the vtable. A qualified destructor call compiles to a
direct tail jump. Model the real class and methods; avoid free `__stdcall`
substitutes and manual vptr assignment.

Seen in:

- [mod_api_core_printf][]: as a variadic C++ method, `this` goes on the stack
  with a caller-cleaned return.
- [grim_draw_text_small_fmt][]: the printf-style member receives self, x, y and
  fmt on the stack and returns with a plain `ret`.
- [grim_get_interface][]: an inlined constructor gives the success fallthrough
  plus an out-of-line failure block zeroing EAX.
- [grim pixel-format scalar-deleting destructors][shared-pixfmt-dtors]: five
  destructors and three forwarders, exact under `/O1 /G6 /MD`.

### EH frames depend on new-expressions and linkage

**With `/GX`, `new T(args)` emits the `fs:[0]` frame, a state slot, a
`__CxxFrameHandler` thunk, FuncInfo, an unwind map and cleanup funclets
naturally.** Declaring the constructing function `extern "C"` makes VC6 omit
the constructor unwind graph that C++ linkage keeps. Compiler-local `$L`/`$T`
EH labels renumber when the source length changes.

Seen in:

- [grim_load_texture_internal][]: an otherwise identical `extern "C"`
  declaration omits the unwind graph; the decorated free function reproduces
  the frame and funclet.
- [grim_create_texture][]: the native SEH frame comes from
  `new GrimTexture(name)`.
- [grim_decode_jaz_texture][]: shortening the source renumbers `$L519`/`$T507`
  to `$L516`/`$T503`.

### Static callees in provider objects use custom conventions

**In the statically linked D3DX and IJG objects, TU-local static callees use
custom register conventions** (arguments in EAX/EDX, EDI, ESI or EAX, and
fastcall tail jumps). The local compiler surrogates reproduce them only when
the callee and an ordinary call site share the translation unit. This is shown
for provider objects, not for VC6-compiled game code.

Seen in:

- [IJG private error helper, jquant2 select_colors, Floyd-Steinberg allocator,
  YCbCr table builder][shared-decoder]: the matcher source keeps the official
  IJG routine as a TU call site so the compiler reproduces the convention.

### Unused trailing arguments show only at call sites

**A cdecl callee that ignores a trailing argument compiles identically whether
or not the parameter is declared**, so only the callers' pushes and cleanup
reveal it. Old-style C declarations can keep extra arguments that the callee
ignores.

Seen in:

- [projectile_update][]: restoring the third float argument of `vec2_add` at
  native call sites adds the native `push 0x40800000` and `add esp,0xc`.
- [highscore_submit_full_version_guard][]: an old-style C declaration keeps the
  native extra record argument pushed to `game_is_full_version`.

### Code after noreturn imports is still emitted

**VC6 does not treat imported `longjmp`, `exit` or `_endthread` as noreturn**, so
the normal epilogue or register restores follow the call. Function extents that
stop at the call truncate real compiler output.

Seen in:

- [grim_jaz_jpeg_error_exit][]: the final `pop esi` is unreachable cleanup after
  the imported `longjmp`.
- [statistics_update_check_worker][]: the ordinary epilogue continues after
  `crt_endthread`, as in `highscore_sync_worker`.
- [D3DX IJG jerror fatal path][shared-decoder]: keeps the unreachable `pop esi`
  after `exit`.

## Data, sections and linking

Compiler-local symbols (`$S`/`$E` guards, thunks, array callbacks) bind code to
its owner and constrain linking. See also [Native linking](native-linking.md).

### Function-local statics: guards and $E thunks

**Statics in one guard scope share a guard variable, one bit per object in
declaration order; a new local-static scope introduces another guard and
shifts `$E` numbering.** Each object with a destructor, even a trivial one,
gets a COFF-local `$E<n>` thunk registered via `atexit`, and a trivial
destructor compiles to a single `ret`. Local-static scope ordinals change when
guard scopes are introduced or other functions share the TU. The registration
push binds each `$E` thunk to the owner function's object.

Native: `test`/`or` of guard bits, `push $E2; call atexit`, and one-byte `ret`
thunks.

Seen in:

- [play_game_menu_update][]: seven statics under native guard bits and seven
  one-byte `ret` destructor thunks.
- [quest_select_menu_update][]: one guard holds the color bits and a second
  guard scope holds the checkbox and Back button; `$E10` is skipped where the
  second scope is introduced.
- [options_menu_update][]: an extra checkbox scope changes local-static
  ordinals, not the objects; aliases must name the emitted scopes.
- [UI callback thunks][lifecycle-ownership-2026-09-08]: each one-byte `ret`
  thunk pushed to `crt_atexit` binds to its owner's object; this records
  co-residence of callback and local static, not a complete original TU.

### Global object arrays and static initializers

**A global array of a class with a destructor makes VC6 emit a reverse
array-destruction callback as COFF-local `_$E2`.** A static symbol cannot
satisfy an external reference, so the owning TU must be co-located to link.
Placement-constructing over static storage, whose address is provably
non-null, removes the null check and reproduces the generated initializer
exactly.

Native: a 6-instruction `_$E2` callback calling `??_M` (the EH vector
destructor iterator) with the stride and destructor; a guarded
vector-constructor helper call with the native stride; or
`mov ecx,offset obj; jmp ctor`.

Seen in:

- [quest_meta_table_destroy][]: the 50-entry array yields a `_$E2` callback that
  calls `??_M` with a `0x2c` stride; an explicit reverse loop is longer, and
  linking needs TU co-location.
- [perk_meta_table_init][]: expressing that the static array is non-null emits
  the guarded vector-construction helper with a `0x14` stride.
- [console_global_init][]: load the queue as `this` and tail-call the
  constructor.
- [weapon_table_defaults_global_init][]: placement construction reproduces the
  initializer, with an induction pointer at `damage_scale` and an inlined
  `strcpy`.

### The linker folds identical bodies

**Identical COMDAT bodies (no-op constructors, identical destructors, empty
debug functions with different prototypes) fold to one address, so callers of
several decorated identities resolve to one implementation.** The caller's
prototype still decides its stack cleanup. Where each folded identity has a
natural identical body, emit both and let the linker fold them. Use an explicit
weak-external alias only when an identity has no recoverable body of its own.

Seen in:

- [ui_menu_template_pool_init][]: `effect_vertex_cpp_t::construct` and
  `ui_vec2_cpp_t::construct` are the same natural no-op, folded at link
  without inventing aliases.
- [bonus_meta_entry_release][]: the `bonus_meta_cpp_t` and `perk_meta_cpp_t`
  destructors resolve to the same implementation.
- [grim_decode_jaz_texture](native-linking.md): both cleanup calls branch to the
  one-byte `grim_noop`, modelled as the weak alias
  `GrimJazDecodeScope::~GrimJazDecodeScope -> _grim_noop`.

### String literals live in writable .data

**VC6 emits string literals into writable `.data` and pools identical
NUL-terminated contents, so section permissions cannot identify literal
storage.** `/O2` emits diagnostic literals as separate pooled COMDAT objects in
address order, while `/Ox` flattens or aliases them.

Seen in:

- [zlib_inflate_init2][reference-content-provenance-2026-09-11]: native loads
  the first byte of the `1.1.3` version literal from `.data`.
- [grim_window_proc][]: diagnostic literals are separate pooled COMDAT data
  objects in address order, matching `/O2`; `/Ox` flattens them.

## Toolchain and flags

Fix the profile from PE, Rich and archive provenance, then work on source. Flag
matrices almost never explain a residual in game code.

### Game code: stock VC6 /O2 /GB

**Game and Grim engine code match `msvc6.5 /O2 /GB /W3 /GR-`, with `/MD` for
`grim.dll`.** The Rich records name `Utc12` build 9782 (VC6 SP6), and builds
8966 and 9782 tie on every function. `/G5`, `/G7`, `/Ob1`, `/Ot`, `/Oa`,
`/Ow`, `/Zp8`, `/GX`, `/Gy`, `/Zd`, `/Zi`, `/Z7`, PCH and decomposed
`/Og /Oi /Ot /Oy` are usually byte-neutral. `/G6`, `/Oy-`, `/Op`, `/Os`,
`/O1`, `/Oi-`, `/Ob0`, the 6.5 Processor Pack and VC7 regress, `/Og-`
collapses, and `/ZI` conflicts with `/O2`. A better score from another profile
usually compensates for a source residual and is not provenance, and a profile
can produce exact bodies while being ruled out by Rich records. `/Ox` ties on
bytes but changes literal pooling and references.

Seen in:

- [player_update][]: in a profile matrix VC6.0, 6.5 and 6.6 are identically
  best, while the Processor Pack, VC7 and every non-neutral flag regress.
- [creature_apply_damage][]: builds 8168 through 9782 are byte-identical, and a
  flag matrix moves nothing.
- [bonus_label_for_entry][match-readme-toolchain]: calibration is exact with
  msvc6.5 and 6.6, not 6.5pp or 7.0; switching `/G6` to `/GB` kept every exact
  match.
- [fx_queue_add][]: the Processor Pack scheduled the store exactly but would
  leave build-9044 Rich records absent from the exe; a stock source shape was
  found that matches without it.
- [quest_build_the_lizquidation][]: `/G6` was historically best; after source
  recovery canonical `/GB` won and the override was removed.

### C2 builds 8966 and 9044 lower the same source differently

**Historical builds use different C2 builds: 1.0.2 to 1.4.0 and 1.9.1 at 8966,
1.9.8 at 9044 (Processor Pack), 1.9.9 to 1.9.93 at 9782.** 9044 lowers
float-compare branches as `test ah,5; jnp` where 8966 uses `test ah,1; jne`,
drops some dead IV-copy stores, and can choose different IV anchors and frames.
One source may be exact for one build and miss the other. The 8966 and 9782
optimizers tie on every function, so 1.9.93 is matched with msvc6.5.

Source: `--build 1.9.8` compiles with that build's profile and
`/DCL_BUILD=10908`. Guard behavioural changes with `CL_BUILD`. Use a
code-generation-only guard only when no shared spelling is exact for both
builds, and record that search in the scratch notes.

Seen in:

- [quest_spawn_timeline_update][quest-history-sources-2026-09-28]: for the
  canonical source, 8966 and 9044 differ only in float-compare lowering, and no
  flag control makes the canonical source produce 1.9.8.
- [projectile_render][]: one shared source is exact for 1.9.8 (6.5pp, frame
  `0x180`) and 1.9.93 (6.5, frame `0x19c`).
- [grim.dll 1.9.8][decomp-readme]: an incremental build in which some C++
  objects were recompiled with C2 9044 while the rest remain 8966.
- [CMOD_GetMod, CMOD_GetInfo, r_roks.cpp][match-readme-sdk]: the 2003 MOD SDK
  DLLs, built `/MT /W3 /GX /O2`, reproduce under 6.5pp and serve only for
  calibration.

### Statically linked provider code needs its own compiler

**Members of DirectX 8.1 `d3dx8.lib` carry product 29 build 9178 (XP DDK), not
VC6.** That backend selects `and byte [..],0` where VC6 and VC7.1 emit
`mov byte [..],0`, which is the typical residual under a surrogate;
`msvc7.0ddk /O1 /G6` reproduces those objects. Per-family flags are build
property inferences: `/O1` for the D3DX pixel-format family, `/Oi` for inline
`rep` sequences (it also changes TU-wide register allocation), `/O2 /Ob2 /G6`
for parts of the JAZ IJG copy. Compile pinned upstream source (IJG 6a, zlib
1.1.3, libpng 1.0.5) without shaping it. Rich-header 8047 and 9178 counts come
from import and archive members, not the engine compiler.

Seen in:

- [grim_jpeg_start_pass_one_quantizer][]: `jquant1.obj` is build 9178; the
  13.10 surrogate misses the native `and`-clear before the method-pointer
  store, and the DDK profile emits it.
- [D3DX pixel-format constructors][shared-pixfmt-ctors]: exact only at
  `/O1 /G6 /W3 /GR- /MD`; under `/O2` the description load is hoisted.
- [png_info_destroy, jdinput, jdmaster][shared-decoder]: `/Oi` is required for
  `rep stosd` and the inline table copy, and TU-wide for register allocation.
- [grim.dll Rich records][match-readme-ddk]: relinking reproduces the 8047
  counts from `msvcrt.lib`; aggregate counts are provider ancestry.

Some D3DX bodies (Huffman, the 4×4/2×2 and slow-int IDCTs, progressive
smoothing) are not reproduced by any available compiler.

### Translation-unit neighbours are usually neutral

**Symbol ids and most code generation are per function, so compiling address
neighbours or shared classes in one TU is normally byte-neutral.** The
exceptions: the preceding function can decide tail cloning or merging, and
compiler-local names (`$S`/`$E`, `$L`/`$T`) renumber with TU contents. C2 9044
(1.9.8) also remembers functions it compiled earlier in the unit. A call to one
of them keeps the registers and globals that the callee leaves alone, so
reloads and register choices around the call change. 8966 does not do this.
Probe with `probe_neighbor_translation_unit.cpp` or a cluster in native address
order.

Seen in:

- [player_update][]: traced to the block mover sizing tails with the previous
  function's frame flags; any FPO function defined first gives the exact
  object.
- [grim_draw_text_mono][]: the same predecessor dependence (exact only after
  `grim_draw_quad_points`), without a traced mechanism.
- [creature_apply_damage][]: a four-function predecessor chain and the
  `projectile_update` successor in one unit are byte-identical.
- [projectile_update][]: 1.9.8 is exact only with the real `vec2_add` and
  `creature_find_in_radius` bodies ahead of it. Without them, the miss block
  reloads `shock_chain_projectile_id` and the compare loads its operands in
  the other order. With a stub callee, a pointer survives the call in ECX.
  1.9.93 is exact either way.
- [unlocked_perks_database_update][]: with the weapons sibling in one TU the
  bytes are identical, but the guard and thunks become `$S4`/`$E5`/`$E6`.

### /MD dllimport and cached import addresses

**Under `/MD`, CRT calls go through the import table only when declared
`dllimport`, and C2 caches a repeatedly called import address in a
callee-saved register.** The bundled VC6 headers do not always select
`dllimport`, so explicit declarations are needed.

Native: `call [__imp__strdup]`, or `mov esi,[__imp__strdup] ... call esi`.

Seen in:

- [grim_set_config_var][]: the `/MD` ABI caches the import in the native
  register.
- [grim_lookup_blob_load][]: explicit `dllimport` declarations reproduce
  dynamic-CRT import calls that the bundled headers do not select.
- [grim_state_init][]: `/MD` reproduces the import-indirect `_strdup`.

### SDK header packing guards

**The Wine `d3d8` header applies `pshpack4` only under `__i386__`, which VC6
does not define (it defines `_M_IX86`), so DirectX structures silently grow and
every frame displacement shifts.** Apply `#pragma pack(4)` explicitly around
DirectX Win32 structures. One site, but a silent and general trap.

Seen in:

- [grim_d3d_init][]: `D3DADAPTER_IDENTIFIER8` grew from `0x42c` to `0x430`
  (`sub esp,0x440` instead of `0x43c`); the shared `grim_d3d8.h` with
  `pack(4)` restores the frame without regressions elsewhere.

### CRT entries that fall through into shared code

**Some VC6 `libcmt` math entries (`_pow`, `_acos`) are short assembler prefixes
that fall through into code shared with `__CIpow`/`__CIacos`, and an archive
symbol's section range can run on into private helpers.** Analyzers split
these, so match them against the archive member with an explicit
`ARCHIVE_SIZE`.

Native: a 9-byte entry, `lea edx,[esp+N]; call _fload_with_fb`, with no `ret`.

Seen in:

- [crt_pow_entry, crt_acos_entry][crt-math]: `pow.obj` and `acos.obj` prefixes
  in the pinned VC6 SP6 `libcmt.lib`.
- [crt_ffexpm1][crt-ffexpm1-2026-09-12]: `ARCHIVE_SIZE=67` selects the extent;
  the archive symbol extends further.

## Scoring pitfalls

### Raw match% moves with alignment, not semantics

**Branch labels compare as byte offsets, and VC6 rotates scratch registers, so
one extra temporary renames every later register, one size change relabels
every later branch, and one frame difference shifts every later stack
operand.** Correct changes can lower the raw score while label-masked views
rise. Fixing one region repairs downstream displacements and looks like a big
gain. Sequence alignment pairs identical shapes from the wrong arm, producing
phantom reference mismatches. Equal instruction counts can hide offsetting
errors. Score winners that delete native temporaries or move the instruction
count away from native are alignment artifacts.

Seen in:

- [player_update][]: the auto-target loop fix lowered the raw score while every
  masked view improved; the old loop had realigned a long stretch by accident.
- [projectile_render][ion-endpoint-rounding-2026-09-13]: a wrong-widen control
  kept the baseline score while failing every strip comparison, and the correct
  fix lowered the score.
- [highscore_sync_worker][]: an equal instruction count hid a missing `lea`
  balanced by an extra cleanup `mov`.
- [creature_spawn_template][]: the sole reference mismatch was the retry jump
  table, every entry displaced by `+0x11` from one upstream tail-fold.
- [controls_menu_update][reference-tu-audit-2026-09-08]: a content-scanning
  heuristic overread byte maps into the next table; tooling, not code.

## Matching methodology

The full workflow is in [`tools/match/README.md`][match-readme]. The lessons
that kept recurring:

- **Test interactions, not single mutations.** Many exact matches needed
  several coordinated changes that were each neutral or negative alone. Sweep
  pairs and full combinations, and propagate a lifetime change to every
  homologous site before calling something a residual.
- **A negative sweep holds only for its baseline.** After an ownership or
  lifetime change, replay the rejected spellings. Several "compiler only"
  residuals were later closed by plausible source.
- **Do not trust raw match%.** Judge with label-, register- and stack-masked
  views, encoded-body identity, a relocation-aware reference audit and the
  instruction count. Reject winners that delete native temporaries, add
  reference mismatches, change the lowering kind or move the count away from
  native.
- **Check semantics as well as bytes.** Run native and candidate at PC24 and
  PC64 to find float32 store points, dump literal bits for one-ULP constants,
  and execute mutation controls.
- **Fix the frame, extent and ABI first.** Map native ESP-relative homes per
  access, treat a frame-size delta as one root cause, and settle the function
  extent (epilogues after noreturn calls, guard-bounded switch tables) and the
  calling convention (`ret imm`, ECX use, EAX residue) before chasing
  instruction deltas.
- **Provenance comes from Rich, `@comp.id` and archive evidence**, not from the
  best-scoring profile. Rule flags out once with a matrix, then work on source.
- **Borrow house style from exact siblings and authenticated headers** (the
  2003 SDK `vec2_t`, `gdi*` constructor chains, quest-builder append counts),
  but retest per site.
- **Use C2 instrumentation to find the deciding pass.** Interventions, dead-store
  pads and `volatile`/`register` tricks are diagnostics and never earn match
  credit.
- **Native evidence outranks a minimal-source prior.** No-op parentheses, split
  increments and overwritten default stores are real when they move toward
  native without adding reference mismatches.

[c2-compiler]: https://github.com/banteg/crimson/blob/master/tools/match/c2/compiler/README.md
[audit-exe]: https://github.com/banteg/crimson/blob/master/tools/match/PLAUSIBILITY-AUDIT-2026-09-25.md
[audit-grim]: https://github.com/banteg/crimson/blob/master/tools/match/PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md
[tutorial_timeline_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/tutorial_timeline_update/NOTES.md
[highscore_screen_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/highscore_screen_update/NOTES.md
[unlocked_weapons_database_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/unlocked_weapons_database_update/NOTES.md
[creature_handle_death]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_handle_death/NOTES.md
[perks_update_effects]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/perks_update_effects/NOTES.md
[survival_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/survival_update/NOTES.md
[grim_get_key_char]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_get_key_char/NOTES.md
[bonus_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_render/NOTES.md
[audio_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/audio_update/NOTES.md
[grim_keyboard_poll]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_keyboard_poll/NOTES.md
[bonus_try_spawn_on_kill]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_try_spawn_on_kill/NOTES.md
[highscore-row-induction-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-row-induction-2026-09-22/README.md
[typo_word_pick_highscore_name]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/typo_word_pick_highscore_name/NOTES.md
[projectile_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/projectile_render/NOTES.md
[creature-render-exact-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-render-exact-2026-09-12/README.md
[highscore_sync_worker]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/highscore_sync_worker/NOTES.md
[quest_build_gauntlet]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_gauntlet/NOTES.md
[quest_build_major_alien_breach]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_major_alien_breach/NOTES.md
[quest_build_the_beating]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_the_beating/NOTES.md
[quest_build_syntax_terror]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_syntax_terror/NOTES.md
[quest_build_survival_of_the_fastest]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_survival_of_the_fastest/NOTES.md
[quest_build_nagolipoli]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_nagolipoli/NOTES.md
[creatures_none_active]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creatures_none_active/NOTES.md
[grim_run_loop]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_run_loop/NOTES.md
[statistics_update_check_worker]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/statistics_update_check_worker/NOTES.md
[quest_build_arachnoid_farm]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_arachnoid_farm/NOTES.md
[plaguebearer_spread_infection]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/plaguebearer_spread_infection/NOTES.md
[quest_build_the_gang_wars]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_the_gang_wars/NOTES.md
[creature_spawn]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_spawn/NOTES.md
[creature_spawn_template]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_spawn_template/NOTES.md
[quest_build_minor_alien_breach]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_minor_alien_breach/NOTES.md
[quest_build_the_unblitzkrieg]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_the_unblitzkrieg/NOTES.md
[quest_build_spideroids]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_spideroids/NOTES.md
[quest_build_8_legged_terror]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_8_legged_terror/NOTES.md
[console_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/console_render/NOTES.md
[quest_build_everred_pastures]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_everred_pastures/NOTES.md
[creature_render_type]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_render_type/NOTES.md
[quest_build_spiders_inc]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_spiders_inc/NOTES.md
[quest_select_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_select_menu_update/NOTES.md
[projectile_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/projectile_update/NOTES.md
[typo_target_name_assign_random]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/typo_target_name_assign_random/NOTES.md
[perk_apply]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/perk_apply/NOTES.md
[grim_lookup_blob_size_for_path]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_lookup_blob_size_for_path/NOTES.md
[quest_start_selected]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_start_selected/NOTES.md
[projectile-particle-update-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-particle-update-2026-09-11/README.md
[highscore-state-owners-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-state-owners-2026-09-22/README.md
[gameplay_update_and_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/gameplay_update_and_render/NOTES.md
[typo_player_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/typo_player_update/NOTES.md
[statistics_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/statistics_menu_update/NOTES.md
[highscore-prefix-lifetime-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-prefix-lifetime-2026-09-22/README.md
[ui_render_hud]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_render_hud/NOTES.md
[grim_zlib_decompress_alloc]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_zlib_decompress_alloc/NOTES.md
[quest_build_monster_blues]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_monster_blues/NOTES.md
[quest_build_frontline_assault]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_frontline_assault/NOTES.md
[quest_build_army_of_three]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_army_of_three/NOTES.md
[grim_set_rotation]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_set_rotation/NOTES.md
[config_init_defaults]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/config_init_defaults/NOTES.md
[player-fire-cough-2026-09-14]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-fire-cough-2026-09-14/README.md
[grim_flush_input]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_flush_input/NOTES.md
[play_game_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/play_game_menu_update/NOTES.md
[quest_results_screen_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_results_screen_update/NOTES.md
[music_update_fades]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/music_update_fades/NOTES.md
[creature-state-publication-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-state-publication-2026-09-11/README.md
[overlay-render-owners-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/overlay-render-owners-2026-09-12/README.md
[perk_selection_screen_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/perk_selection_screen_update/NOTES.md
[ui_menu_layout_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_menu_layout_init/NOTES.md
[controls_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/controls_menu_update/NOTES.md
[terrain_generate_random]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/terrain_generate_random/NOTES.md
[game_frame_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/game_frame_update/NOTES.md
[gameplay_reset_state]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/gameplay_reset_state/NOTES.md
[sfx_entry_load_ogg]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/sfx_entry_load_ogg/NOTES.md
[ui_cursor_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_cursor_render/NOTES.md
[creature_update_all]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_update_all/NOTES.md
[player_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/player_update/NOTES.md
[ui_scrollbar_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_scrollbar_update/NOTES.md
[quest-history-controls-2026-09-28]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/quest-history-controls-2026-09-28/README.md
[grim_d3d_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_d3d_init/NOTES.md
[ui_element_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_element_render/NOTES.md
[quest_failed_screen_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_failed_screen_update/NOTES.md
[quest_build_spider_spawns]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_spider_spawns/NOTES.md
[ui_list_widget_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_list_widget_update/NOTES.md
[ui_menu_assets_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_menu_assets_init/NOTES.md
[quest_spawn_timeline_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_spawn_timeline_update/NOTES.md
[ui_draw_progress_bar]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_draw_progress_bar/NOTES.md
[quest_build_knee_deep_in_the_dead]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_knee_deep_in_the_dead/NOTES.md
[quest_build_the_lizquidation]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_the_lizquidation/NOTES.md
[ui_element_set_rect]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_element_set_rect/NOTES.md
[renderer-house-style-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/renderer-house-style-2026-09-13/README.md
[creature_spawn_tinted]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_spawn_tinted/NOTES.md
[projectile_spawn]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/projectile_spawn/NOTES.md
[fx_queue_add]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/fx_queue_add/NOTES.md
[effect_spawn]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/effect_spawn/NOTES.md
[bonus_hud_slot_activate]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_hud_slot_activate/NOTES.md
[c2-tools]: https://github.com/banteg/crimson/blob/master/tools/match/c2/README.md
[vc6-timeline-zero-splitting-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vc6-timeline-zero-splitting-2026-09-12/README.md
[input_detect_active_analog_axis]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/input_detect_active_analog_axis/NOTES.md
[highscore-quest-ordering-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-quest-ordering-2026-09-22/README.md
[projectile-id-window-2026-09-28]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-id-window-2026-09-28/README.md
[grim_window_proc]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_window_proc/NOTES.md
[spawn-exact-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/spawn-exact-2026-09-13/README.md
[player-angle-propagation-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-angle-propagation-2026-09-22/README.md
[vc6-timeline-consumers-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vc6-timeline-consumers-2026-09-11/README.md
[creature-pointer-rematerialization-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-pointer-rematerialization-2026-09-22/README.md
[creature-pool-base-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-pool-base-2026-09-22/README.md
[render-owner-lifetimes-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/render-owner-lifetimes-2026-09-11/README.md
[player-update-residuals-2026-09-27]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-update-residuals-2026-09-27/README.md
[grim_state_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_state_init/NOTES.md
[projectile-primary-secondary-residuals-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-primary-secondary-residuals-2026-09-13/README.md
[highscore-label-bitcopy-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-label-bitcopy-2026-09-22/README.md
[bonus_spawn_at_pos]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_spawn_at_pos/NOTES.md
[console_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/console_update/NOTES.md
[effect_spawn_ion_hit_sparks]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/effect_spawn_ion_hit_sparks/NOTES.md
[sfx_entry_start_playback]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/sfx_entry_start_playback/NOTES.md
[hud-exact-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/hud-exact-2026-09-12/README.md
[player-update-arithmetic-2026-09-27]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-update-arithmetic-2026-09-27/README.md
[overlay-dead-body-size-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/overlay-dead-body-size-2026-09-11/README.md
[vc6-redundant-stores-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vc6-redundant-stores-2026-09-11/README.md
[vc6-timeline-pointer-home-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vc6-timeline-pointer-home-2026-09-12/README.md
[quest-plain-guard-2026-09-28]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/quest-plain-guard-2026-09-28/README.md
[quest-history-sources-2026-09-28]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/quest-history-sources-2026-09-28/README.md
[hud-stack-coloring-2026-09-10]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/hud-stack-coloring-2026-09-10/README.md
[mods_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/mods_menu_update/NOTES.md
[highscore-filter-storage-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-filter-storage-2026-09-22/README.md
[resource_open_read]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/resource_open_read/NOTES.md
[fx_spawn_secondary_projectile]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/fx_spawn_secondary_projectile/NOTES.md
[grim_set_color_ptr]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_set_color_ptr/NOTES.md
[wrap_text_to_width_alloc]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/wrap_text_to_width_alloc/NOTES.md
[vc6-timeline-decomposition-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vc6-timeline-decomposition-2026-09-12/README.md
[timeline-copy-aliases-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/timeline-copy-aliases-2026-09-22/README.md
[grim_draw_quad]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_draw_quad/NOTES.md
[player-projectile-boundaries]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/PLAYER-PROJECTILE-BOUNDARIES-2026-09-08.md
[creature_apply_damage]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_apply_damage/NOTES.md
[demo_purchase_screen_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/demo_purchase_screen_update/NOTES.md
[highscore_rank_index]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/highscore_rank_index/NOTES.md
[grim_is_key_active]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_is_key_active/NOTES.md
[grim_draw_text_mono]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_draw_text_mono/NOTES.md
[bonus_pick_random_type]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_pick_random_type/NOTES.md
[bonus-pick-layout-trace-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/bonus-pick-layout-trace-2026-09-13/README.md
[bonus-pick-flow-graph-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/bonus-pick-flow-graph-2026-09-11/README.md
[grim_zlib_status_is_error]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_zlib_status_is_error/NOTES.md
[game_state_set]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/game_state_set/NOTES.md
[input_configure_for_label]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/input_configure_for_label/NOTES.md
[player-hot-tempered-2026-09-14]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-hot-tempered-2026-09-14/README.md
[typo_target_name_draw_labels]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/typo_target_name_draw_labels/NOTES.md
[ion-chain-product-2026-09-10]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/ion-chain-product-2026-09-10/README.md
[fire-overlay-lifetimes-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/fire-overlay-lifetimes-2026-09-13/README.md
[creature-corpse-vectors-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-corpse-vectors-2026-09-13/README.md
[creature-retarget-distance-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/creature-retarget-distance-2026-09-13/README.md
[c2-codeless]: https://github.com/banteg/crimson/blob/master/tools/match/c2/compiler/codeless-tuples.md
[c2-plain-float]: https://github.com/banteg/crimson/blob/master/tools/match/c2/compiler/plain-float-sources.md
[projectile-plague-schedule-2026-09-28]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-plague-schedule-2026-09-28/README.md
[projectile-particle-impact-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-particle-impact-2026-09-11/README.md
[highscore-residual-decomposition-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-residual-decomposition-2026-09-13/README.md
[game_startup_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/game_startup_init/NOTES.md
[effect_spawn_splitter_hit_burst]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/effect_spawn_splitter_hit_burst/NOTES.md
[effect_spawn_blood_splatter]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/effect_spawn_blood_splatter/NOTES.md
[creature_find_nearest]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/creature_find_nearest/NOTES.md
[ui_button_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_button_update/NOTES.md
[ui_focus_draw]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_focus_draw/NOTES.md
[player-point-frame-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/player-point-frame-2026-09-11/README.md
[effects_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/effects_update/NOTES.md
[player_render]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/player_render/NOTES.md
[remaining-storage-controls-2026-09-26]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/remaining-storage-controls-2026-09-26/README.md
[highscore-float-reuse-2026-09-22]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/highscore-float-reuse-2026-09-22/README.md
[projectile-ownership-and-stack-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-ownership-and-stack-2026-09-13/README.md
[projectile-rounding-boundaries-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-rounding-boundaries-2026-09-13/README.md
[overlay-exact-2026-09-12]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/overlay-exact-2026-09-12/README.md
[projectile-residual-decomposition-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/projectile-residual-decomposition-2026-09-13/README.md
[grim_draw_fullscreen_color]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_draw_fullscreen_color/NOTES.md
[dx_version_pack_4x16]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/dx_version_pack_4x16/NOTES.md
[grim_keyboard_key_down]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_keyboard_key_down/NOTES.md
[quest_build_evil_zombies_at_large]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_evil_zombies_at_large/NOTES.md
[grim_config_dialog_populate_display_modes]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_config_dialog_populate_display_modes/NOTES.md
[unlocked_perks_database_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/unlocked_perks_database_update/NOTES.md
[player_reset_all]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/player_reset_all/NOTES.md
[grim_submit_vertices_transform]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_submit_vertices_transform/NOTES.md
[music_load_track]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/music_load_track/NOTES.md
[quest_build_zombie_masters]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_zombie_masters/NOTES.md
[config_load_presets]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/config_load_presets/NOTES.md
[quest_build_nesting_grounds]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_build_nesting_grounds/NOTES.md
[ui_menu_template_pool_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_menu_template_pool_init/NOTES.md
[grim_jaz_jpeg_init_one_pass_quantizer]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_jaz_jpeg_init_one_pass_quantizer/NOTES.md
[shared-decoder]: https://github.com/banteg/crimson/blob/master/tools/match/shared/grim_decoder_callbacks.md
[grim_is_key_down]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_is_key_down/NOTES.md
[grim_is_texture_format_supported]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_is_texture_format_supported/NOTES.md
[dx_version_compare_4x16]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/dx_version_compare_4x16/NOTES.md
[console_push_line]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/console_push_line/NOTES.md
[ui_render_loading]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/ui_render_loading/NOTES.md
[audio_shutdown_all]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/audio_shutdown_all/NOTES.md
[game_status_global_init_thunk]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/game_status_global_init_thunk/NOTES.md
[vector-return-contract-2026-09-08]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/vector-return-contract-2026-09-08/README.md
[grim_get_config_var]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_get_config_var/NOTES.md
[grim_init_system]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_init_system/NOTES.md
[grim_apply_config]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_apply_config/NOTES.md
[grim_backup_textures]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_backup_textures/NOTES.md
[game_core_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/game_core_init/NOTES.md
[highscore_build_path]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/highscore_build_path/NOTES.md
[config_ensure_file]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/config_ensure_file/NOTES.md
[terrain_generate]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/terrain_generate/NOTES.md
[mod_api_core_printf]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/mod_api_core_printf/NOTES.md
[grim_draw_text_small_fmt]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_draw_text_small_fmt/NOTES.md
[grim_get_interface]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_get_interface/NOTES.md
[shared-pixfmt-dtors]: https://github.com/banteg/crimson/blob/master/tools/match/shared/grim_pixel_format_deleting_destructors.md
[grim_load_texture_internal]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_load_texture_internal/NOTES.md
[grim_create_texture]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_create_texture/NOTES.md
[grim_decode_jaz_texture]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_decode_jaz_texture/NOTES.md
[highscore_submit_full_version_guard]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/highscore_submit_full_version_guard/NOTES.md
[grim_jaz_jpeg_error_exit]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_jaz_jpeg_error_exit/NOTES.md
[options_menu_update]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/options_menu_update/NOTES.md
[lifecycle-ownership-2026-09-08]: https://github.com/banteg/crimson/blob/526d6cd046e2b59dda368701aef44d0faeb6ed43/tools/match/evidence/lifecycle-ownership-2026-09-08/README.md
[quest_meta_table_destroy]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/quest_meta_table_destroy/NOTES.md
[perk_meta_table_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/perk_meta_table_init/NOTES.md
[console_global_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/console_global_init/NOTES.md
[weapon_table_defaults_global_init]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/weapon_table_defaults_global_init/NOTES.md
[bonus_meta_entry_release]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/bonus_meta_entry_release/NOTES.md
[reference-content-provenance-2026-09-11]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/reference-content-provenance-2026-09-11/README.md
[match-readme-toolchain]: https://github.com/banteg/crimson/blob/master/tools/match/README.md#toolchain
[decomp-readme]: https://github.com/banteg/crimson/blob/master/decomp/README.md
[match-readme-sdk]: https://github.com/banteg/crimson/blob/master/tools/match/README.md#2003-mod-sdk-calibration-oracle
[grim_jpeg_start_pass_one_quantizer]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_jpeg_start_pass_one_quantizer/NOTES.md
[shared-pixfmt-ctors]: https://github.com/banteg/crimson/blob/master/tools/match/shared/grim_pixel_format_constructors.md
[match-readme-ddk]: https://github.com/banteg/crimson/blob/master/tools/match/README.md#xp-ddk-build-9178-attribution-control
[grim_set_config_var]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_set_config_var/NOTES.md
[grim_lookup_blob_load]: https://github.com/banteg/crimson/blob/master/tools/match/scratches/grim_lookup_blob_load/NOTES.md
[crt-math]: https://github.com/banteg/crimson/blob/master/tools/match/CRT-MATH-ENTRIES-2026-09-08.md
[crt-ffexpm1-2026-09-12]: https://github.com/banteg/crimson/blob/06189f2852203c12278143b1f45f5c3628df222c/tools/match/evidence/crt-ffexpm1-2026-09-12/README.md
[ion-endpoint-rounding-2026-09-13]: https://github.com/banteg/crimson/blob/cd628967c71891e06d341393ae20cc84136f329d/tools/match/evidence/ion-endpoint-rounding-2026-09-13/README.md
[reference-tu-audit-2026-09-08]: https://github.com/banteg/crimson/blob/526d6cd046e2b59dda368701aef44d0faeb6ed43/tools/match/evidence/reference-tu-audit-2026-09-08/README.md
[match-readme]: https://github.com/banteg/crimson/blob/master/tools/match/README.md
