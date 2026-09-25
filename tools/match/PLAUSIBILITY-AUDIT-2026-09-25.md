# Plausibility audit of exact matches (2026-09-25)

This audit covered the 961 exact source scratches, excluding vendored
libjpeg, zlib and CRT code. It looked for constructs that only exist to
steer the compiler, and it tried plainer source for each one. 52 scratches
were rewritten. Each rewrite stays exact: normalized instructions, relocation
references and encoded body bytes all match, and the pinned `msvc6.5`
compiler, flags and aliases are unchanged. Removing a construct counts as
evidence against it only when the replacement is byte-identical.

## Shapes C2 already produces from plain code

Do not hand-write the forms below. Stock VC6 `/O2` derives each one from
ordinary source.

| Hand-written form | Plain source | C2 mechanism |
| --- | --- | --- |
| `while ((int)p < (int)&pool[N]) { ...; ++p; }` | `for (i = 0; i < N; i++) pool[i]...` | Strength reduction turns `pool[i]` into a pointer IV. Linear test replacement compares that pointer with the end address and keeps the int's signed `jl`/`jge`. |
| Pointer anchored at the struct base (`cmp byte [ecx], 0`; `[ecx+0x14]`) | an index loop with a local `const vec2f_t *position = &pool[i].position;` | A pure index loop anchors the IV at the most-used field offset. Taking a field address gives the base-anchored IV. |
| `n = N; do { ... } while (--n);` and `if (n > 0) do ... while (--n)` | `for (i = 0; i < n; i++)` with an unused index | Loop reversal turns an unused counted index into `dec`/`jne`. For a constant trip count the entry guard folds away. |
| `extra = (1 - x) >> 1; x += extra * 2; do ... while (--extra)` | `while (x < 0) { ...; x += 2; }` | IV elimination computes the trip count and the final value in closed form (`survival_update`). |
| Cursor plus container-of: `(T *)((char *)p - offsetof(T, f))`, `p[-5]`, `p += sizeof(T) / sizeof(int)` | `pool[i].field` | These are the same strength-reduced addresses. |
| `int one = 1; x = (unsigned char)one;` and a byte copy through `int key_state` | `x = 1;` and `if (f())` | C2 keeps a repeated byte constant in a register without help. |
| `*(int *)&dst = *(int *)&src` for a float copy | `dst = src;` | Float copies with no arithmetic are already lowered to integer moves. |
| `register int i` | `int i` | VC6 ignores `register`. |

Two caveats came up during the rewrites:

- **VC6 C++ `for` scoping.** A `for (int i ...)` variable leaks into the
  enclosing scope. Reusing a function-level `i` for a new loop can change
  register allocation elsewhere. In `ui_menu_layout_init` it swapped SIB base
  and index registers in an unrelated block. The normalized diff stayed at
  100%, and only `body_byte_exact` caught it. Give each loop its own index.
- **Cached globals can be real.** `perk_apply` keeps
  `player_count = config_player_count` reloads inside two loops. Removing
  them changes register allocation (77% match). A cached count refreshed
  after a call is also an ordinary habit.

## Rewritten scratches

- **Indexed loops (int-cast pointer walks removed):**
  `audio_suspend_channels`, `bonus_alloc_slot`, `bonus_hud_slot_activate`,
  `bonus_pick_random_type`, `bonus_reset_availability`,
  `bonus_try_spawn_on_kill`, `controls_menu_update`, `creature_alloc_slot`,
  `creature_reset_all`, `creature_spawn_slot_alloc`, `creatures_none_active`,
  `credits_screen_update`, `credits_secret_alien_zookeeper_update`,
  `fx_spawn_particle`, `fx_spawn_particle_slow`,
  `fx_spawn_secondary_projectile`, `fx_spawn_sprite`, `gameplay_reset_state`,
  `input_primary_just_pressed`, `music_release_all`, `perk_apply`,
  `plaguebearer_spread_infection`, `player_apply_move_with_spawn_avoidance`,
  `player_reset_all`, `projectile_reset_pools`, `projectile_spawn`,
  `sfx_release_all`, `tutorial_timeline_update`, `ui_element_update`,
  `ui_elements_max_timeline`, `ui_elements_reset_state`,
  `ui_elements_update_and_render`, `ui_get_element_index`,
  `ui_menu_layout_init`.
- **Field-address anchors:** `bonus_spawn_at_pos`, `creature_find_nearest`.
- **Counted loops (countdowns removed):** `bonus_spawn_at`,
  `creature_apply_damage`, `creature_handle_death`,
  `effect_spawn_blood_splatter`, `effect_spawn_burst`,
  `effect_spawn_explosion_burst`, `effect_spawn_freeze_shatter`,
  `effect_spawn_ion_hit_sparks`, `effect_spawn_shrinkifier_hit`,
  `quest_start_selected`, `ui_profile_menu_update`, `ui_render_hud`.
- **Closed-form trip count:** `survival_update`.
- **Owner array instead of the next-symbol bound:**
  `quest_select_menu_update` now indexes
  `texture_handles.ui_quest_number_textures[stage]`.
- **Fully plain rewrites:** `perks_rebuild_available` (the first loop
  is `i < perk_id_max + 1`) and `weapon_refresh_available`.

Notable behavior that the plain forms make visible:

- `bonus_hud_slot_activate` starts its duplicate scan at
  `check_index = 16`, one past the table. The plain nested loop reproduces
  that off-by-one.
- `tutorial_timeline_update` stage 1 runs its body inside the player loop,
  then returns.

## Retained or open

- **`highscore_screen_update` float controls.** The two `double`
  intermediates became single-use `float` locals, still byte-exact. The
  `memcpy` label copies are retained: every plainer copy loses the integer
  register candidate (82.8–90.4%). See
  [plain-float-sources.md](c2/compiler/plain-float-sources.md).
- **`player_render_overlays` alpha byte copy.** Retained for now. Native stores
  `tint.a` to a shared stack slot, and it also keeps the value in a register.
  An alpha wrapper type copied implicitly into the tint
  (`player_render_alpha_t a` member, constructed from `transition_alpha`) is
  byte-exact without `memcpy`; plain float spellings reach 96.73%
  ([post-promotion-stores.md](c2/compiler/post-promotion-stores.md)).
- **`typo_word_pick_highscore_name`.** Settled: plain nested loops that index
  `highscore_table[record_index]` directly are byte-exact. A `record` local
  reaches 98.37% because the derived IVs are created in reverse order of last
  use ([strength-reduction.md](c2/compiler/strength-reduction.md)).
- **`ui_element_render`.** Settled: all three alpha loops are plain indexed
  loops and byte-exact. Converting only one or two of them swaps one `fadd`,
  because commutative x87 operands sort by symbol id mod 8
  ([x87-scheduling.md](c2/compiler/x87-scheduling.md)).
- **`effect_spawn_splitter_hit_burst`.** Settled: a plain `for` with the
  `(int)radius` cast inside the body is byte-exact and needs no guard.
- **`controls_menu_update`.** The axis-peak scan walks seven separately
  declared globals, so it needs an array owner first.
- **`projectile_update`.** Twelve countdowns remain. Auto-converting them
  loses three references.
- **`*_global_init` countdowns.** These are compiler-generated array
  constructor loops for statics with constructors. A plain `T arr[N];` with an
  inline constructor reproduces all 13 initializers and their thunks
  byte-exact, with `SYMBOL='_$E1'`/`'_$E2'`. Adopting them needs native relink
  clusters and data-definition ownership first
  ([array-constructors.md](c2/compiler/array-constructors.md)).
