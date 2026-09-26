# Stack stores that survive register promotion

This note answers one question about the pinned VC6 back end (C2.DLL 12.00.8966, image base
0x10700000): which source produces a store to a stack home that register promotion did not remove,
so that the store is still in the output, often dead, while the value itself lives in a register.
Two scratches need such a store:

- `player_render_overlays` keeps `tint.a` in `esi` and also stores it to `[esp+0x24]`:
  `mov edx, [esp+0x10]; mov esi, edx; mov [esp+0x24], edx`.
- `quest_spawn_timeline_update` keeps `&entry->template_id` in `edi` and also stores it to the slot
  that `spread` reuses at once: `lea edi, [esi+0xc]; mov [esp+0x10], edi; mov [esp+0x10], ebx`.

"Traced" below means observed on a real compile with the preserving observer (§1). "Read" means static
reading in Binary Ninja only. Every control named here was compiled; its source is summarised in the
tables.

Short version:

1. Promotion (`pass_mark_register_candidates` 0x107284d8) marks operands, not variables. A store stays
   a memory store if its own operand was not marked (float, 8-byte or odd-sized type, volatile), or if
   the store is created later. Stores are created later by lowering (intrinsics, block copies,
   `__int64` halves, int-to-float temporaries, parameter homes), by `build_live_ranges` (store-backs and
   overlapping views returned to memory) and by global colouring (demotion and splitting).
2. Nothing deletes a dead memory store after the global optimizer. The late passes forward loads
   (`late_register_value_cse` 0x10736b27) but never remove the store they forwarded from, and
   `late_stack_temp_forwarding` 0x1073e591 only removes class-3 temporaries.
3. `player_render_overlays` needs a **4-byte aggregate copy out of an object whose float member was
   stored as a float**. A one-member alpha type passed by value reproduces the function byte for byte
   without `memcpy` (§5).
4. `quest_spawn_timeline_update` needs a **copy of the pointer into a local that has no other
   reference left when promotion runs**. Of the paths in §3, only a `0x190` copy intrinsic (a byte
   loop, or `memcpy` with a size that is not a literal) or a `volatile` home produce it. No plain
   spelling was found (§6).

## 1. Tool: `scripts/c2/store_trace.py`

```sh
uv run python scripts/c2/store_trace.py <scratch-dir> --out <new-dir> --symbol _spread [--symbol ...]
uv run python scripts/c2/store_trace.py <scratch-dir> --out <new-dir> --detail --symbol '#550'
uv run python scripts/c2/store_trace.py --report-only <trace-dir> --symbol _cp [--verbose]
```

It runs the scratch through `crimson match c2-trace`'s preserving harness (whole-COFF, replay and
missing-stream checks unchanged) with the readable IL dump of [`iv_trace.py`](../../../../scripts/c2/iv_trace.py).
The IL is dumped at entry to the stock pass boundaries, at entry and return of promotion, at entry to
global colouring and at entry to every post-allocation pass. `--detail` adds the steps inside
`build_live_ranges` 0x10726d75 and global colouring, including each `insert_live_range_spill_store`
and `demote_live_range` call.

For the selected symbols and all their parts (typed or field views, printed `#id^parent+offset`) the
report prints one line per dump with five counts: memory stores (kind-2 destinations), register
definitions (kind 1), memory reads, register reads and address operands. The tuples are printed
whenever the counts change, so the pass responsible for a change is the one between two lines. A line
is flagged when there are more memory stores than right after promotion. Unnamed symbols (inlined
parameters, typed views) are selected by `#id`; take the id from `snapshots.json`.

## 2. What promotion decides

`pass_mark_register_candidates` 0x107284d8 (read, and traced on every control below) walks every tuple's
destination list, then its source list. A kind-2 operand gets the placeholder home 0x107ae040 unless:

- the operand (`+0x10` bit 0x40) or its symbol (`+5` bit 0x40) is volatile;
- the symbol class is 0xa;
- `type_is_register_candidate` 0x107059e2 rejects the operand type. The table
  `g_type_is_register_candidate` 0x107a0230 accepts int and unsigned of 1, 2 and 4 bytes, 4-byte
  pointers, floats, and aggregates of 1, 2 and 4 bytes (type 0x5004 is promotable). It rejects 6- and
  8-byte integers, other pointer sizes, aggregates of any other size and type classes 6 and 7;
- the operand is float (class 0x4000). The pass rejects floats separately, even without `/Op`;
- it is the first source of a call (the callee operand).

The decision is **per operand**. One symbol can have a promoted uint view and an unpromoted float view
of the same four bytes. Operands created after this pass are not marked by it. `build_live_ranges`
later re-examines symbols (§3.3).

## 3. Every path that creates or keeps a stack store after promotion

| # | Path | Where (C2 VA) | Source construct | Store target | Evidence |
|---|---|---|---|---|---|
| A | Unpromoted typed store | promotion leaves it kind 2 | any float local; an 8-byte or odd-sized aggregate or `__int64`; a `volatile` local | the local | traced: `float_wrap4`, overlay, `volatile_ptr`, `int64_local` |
| B | x87 copy retype | `fold_x87_copy_sequences` 0x1072fef2, in global colouring | a float memory-to-memory copy (`alpha = transition_alpha`) | same local, now `mov [x], r32` | traced: overlay (the `fstp` of `alpha` becomes an integer store) |
| C | Copy intrinsic | `lower_intrinsic` 0x10754cc8 (memcpy id 0xac) | a loop recognised by `convert_loop_stores_to_block_op` 0x10747ed0; `memcpy`/`memset` whose size is not a literal at IL read | the destination | traced: four-byte witness, `memcpy_varsize_guard` |
| D | Block copy | `lower_block_copy` 0x10756732, `lower_small_block_copy_as_scalar` 0x10751e0d | a struct copy that reaches lowering (an 8-byte float `vec2` copy; sizes other than 1/2/4/8) | the destination | traced: `offset = zero_offset` in the timeline (two dword moves) |
| E | `__int64` halves | `lower_int64_tuple` 0x1075ac4f | an `__int64` local | both 4-byte halves | traced: `int64_local`. `build_live_ranges` then made both halves register candidates, so no store survived |
| F | Int-to-float temporary | `lower_x87_tuple` 0x10762fc3 | `(float)expr` with a register source | a class-3 temporary | traced asm: `int_to_float_expr` (`mov [esp+4], eax; fild [esp+4]`) |
| G | Parameter home | `assign_parameter_homes` 0x107296de | a `__fastcall`/`__thiscall` register parameter whose address is taken | the parameter home | traced: `fastcall_param_addr` (store appears in that pass) |
| H | Store-back | `insert_live_range_spill_store` 0x10726309, called from `build_live_ranges` at 0x1072f6cc | a promoted definition whose storage is read later as memory: an overlapping part read through another type, an indirect read or call whose alias class contains it, a volatile operand, or a symbol with `flags6 & 1` (set by 0x1075ec2e for symbols referenced after the EH ops 0x192, 0x1a0 and 0x1a4; read) | the local's own home, after each definition | traced: `fild_local` (`(float)s` needs `s` in memory) |
| I | View returned to memory | inside `build_live_ranges`, between 0x10726e00 and the end of `insert_upward_exposed_reloads` 0x1072e7cb | a promoted uint view of storage whose float view is stored in memory (path A plus a 4-byte aggregate copy) | the read goes back to memory | traced: `float_wrap4 --detail`, overlay |
| J | Escape to a call | `build_live_ranges` | `&local` passed to a function | the whole local returns to memory; the call is followed by a reload | traced: `escape_call` |
| K | Demotion | `demote_live_range` 0x10725eed from `prune_low_use_live_ranges` 0x10725b42 or `handle_unprofitable_live_range` 0x10732001 | a range with fewer than two references, or benefit ≤ 0 (low use, many live values) | every definition becomes a memory store | traced: `fild_local`, `pressure` |
| L | Split spill | `insert_live_range_spill_store`, called from `sub_10720e2a` at 0x10720f53 (split pieces) | a range split at block entries | the home | read; hooked in `--detail`, not isolated |
| M | Local allocator spill | 0x1076860c, 0x1076925b, 0x1078ba26 | too many local temporaries in one block | a class-3 spill temporary | read |
| N | x87 depth spill | `x87_spill_stack_entries` 0x1076ea17 | more than 8 live x87 values | a class-3 temporary | read; a 10-level nested control did not reach depth 8 |
| O | EH state | `cxx_eh_lower_state_transitions` 0x10760276 | objects with destructors under `/GX` | the state variable | read |
| P | Block-end demotion of a dead definition | `demote_unused_candidate_def` 0x107318e5, from `insert_upward_exposed_reloads` at 0x1072eb81 | a local definition that survives the final dead-code pass but is dead at `build_live_ranges` (in practice only behind a lowered copy intrinsic or `volatile`) | the local | traced: `DEMOTE #13c4z4'_copied` in the timeline witness ([qst-dead-store.md](qst-dead-store.md)) |

### 3.1 Why the store survives

After the global optimizer, no pass deletes a dead store to a memory local:

- `late_register_value_cse` 0x10736b27 (traced) replaces a load from a stack slot with the register
  that holds the stored value, inside one extended block. It removes the **load**. The store stays.
- `late_stack_temp_forwarding` 0x1073e591 (read) deletes a store/load pair only for symbols of class 3
  with no definition link (compiler temporaries).
- Frame layout runs before `late_register_value_cse`, so a slot whose load is forwarded afterwards
  still has its store/load pair counted. When both sit before another object's first store, the two
  objects share a slot. That is why the overlay's `alpha` and the timeline's copy share a slot with a
  later local.

The global optimizer does delete dead stores. The dead-copy controls show this: a 12-byte struct
copy, a 12-byte `memcpy`, a copy of a 4-byte class with a constructor and a variable-size `memcpy`
whose destination is never read are all gone before promotion. A dead store survives only when its
last read disappears after the optimizer's last dead-code elimination (the timeline witness), or when
the read survives until `late_register_value_cse` removes it (the overlay).

### 3.2 Lowered stores and `build_live_ranges`

A store created by lowering (paths C, D, E) is a kind-2 operand. `build_live_ranges` re-examines it:

- If the destination still has promoted references, the lowered store is absorbed into its live
  range and becomes a register definition. Traced: `memcpy_varsize_used` (the `cp` store becomes
  `reg-def` at 0x1072f8fc), and both `__int64` halves in `int64_local`.
- If the destination has no other reference, it stays a memory store. Traced: `copied` in the witness
  and `cp` in `memcpy_varsize_guard`.

So a lowered copy leaves a dead store exactly when its destination's reads are gone by promotion
but the copy itself was not deleted.

### 3.3 Overlapping typed views

In the overlay the parameter `alpha` (#1421, float) and its uint view (#1430, `alpha+0`) are two parts
of one four-byte object. Promotion marks the uint read and leaves the float store. Traced with
`--detail` on `float_wrap4`: between `assign_candidate_indices` 0x10727bd3 and `sub_1072e5b9`, every
reference to the object becomes a placeholder, including the float store. After
`insert_upward_exposed_reloads` 0x1072e7cb, the float store and the uint read are memory again. The
destination of the copy (`tint.a`, a separate object) stays promoted. It is read by the float argument
pushes, which lowering retypes to integer pushes under `/Ot`, and it gets `esi`.

## 4. Predicting from source

1. Find the value's final register and the dead store. Is the stored value the same value that stays
   live in a register?
2. If the stored object is a float, or has any float view that is stored as a float, the store is
   path A. It survives if a later read through a promotable view (a 4-byte struct copy or `memcpy` of
   a literal 4) keeps it alive until `late_register_value_cse`. That read must be in the same extended
   block.
3. If the stored value is a pointer or an integer, promotion accepts the store. It can only survive
   as a copy produced by lowering (paths C, D) into a destination that has no other reference at
   promotion, or as a volatile store. Plain copies, address-taken holders and pointer wrappers are
   folded by the global optimizer (controls `ptr_wrap4`, `obj4_copy_used`, `byval_inline`,
   `addr_pp_read`, `addr_struct_*`, `plain_copy_late_guard*`).
4. A `memcpy` with a literal size becomes a block copy (0x16b) at IL read. A 4-byte one is scalarized
   in the global optimizer (traced: the overlay `memcpy` is 0x16b at optimizer entry and 0x15b
   `uint` by `pass_narrow_byte_lanes`). A `memcpy` whose size is a variable stays a 0x190 intrinsic up
   to lowering, even after the size folds to a constant (traced: `memcpy_varsize_guard`).
5. Integers converted to float (`fild`) are stored back and then usually demoted (path H then K), so
   they end up in memory. The timeline's `spread` is this case.

## 5. `player_render_overlays`: plain source

Traced on the canonical scratch (`memcpy(&a, &alpha, sizeof(a))` in the constructor):

| Dump | `alpha` #1421 (float) and view #1430 (uint) | `tint.a` #550 |
|---|---|---|
| global optimizer entry | `0x16b` 4-byte copy `[&tint+12] = [#1421]` | — |
| optimizer exit | `#1421 = transition_alpha` (float store); `#550 = #1430` (`0x15b`, type 0x2004) | uint definition |
| promotion return | float store stays kind 2; `#1430` read marked | marked |
| `build_live_ranges` exit | `#1430` read is memory again (§3.3) | promoted, read by the four pushes |
| global colouring (0x1072fef2) | `fld/fstp` become `mov edx, [ta]; mov [#1430], edx` | — |
| `late_register_value_cse` | the load `mov esi, [#1430]` becomes `mov esi, edx` | `esi` |

The store needs a 4-byte **aggregate** copy whose source object's float member was **stored as a
float**. `memcpy` is one way to write that copy. A one-member type is another:

```cpp
struct player_render_alpha_t {
    float value;

    player_render_alpha_t(float v) : value(v) {}
};

struct player_render_tint_t {
    float r;
    float g;
    float b;
    player_render_alpha_t a;

    player_render_tint_t(
        float red, float green, float blue, player_render_alpha_t alpha)
        : r(red), g(green), b(blue), a(alpha)
    {
    }
};

    player_render_tint_t tint(
        1.0f, 1.0f, 1.0f, player_render_alpha_t(transition_alpha));
    grim_interface_ptr->grim_set_color(tint.r, tint.g, tint.b, tint.a.value);
    // the two multiplayer calls also pass tint.a.value
```

This is byte-exact: `match=100.00% prefix=1148/1148 refs=340/0/0 body_byte_exact=True`. Its trace
has the same lifecycle as the `memcpy` form: the float store to the temporary's `value`, the 0x2004
copy into `tint.a`, the view back in memory after `build_live_ranges`, and the last read removed by
`late_register_value_cse`. The canonical scratch was not changed.

Acceptance tests. Each prediction was written before the compile.

| Variant | Prediction | Observed |
|---|---|---|
| `w2`: the source above | exact | **exact** |
| `w1`: same types, no wrapper constructor; `player_render_alpha_t alpha; alpha.value = transition_alpha;` passed by value | exact | **exact** |
| `p2f`: `float` constructor parameter, body `a = player_render_alpha_t(alpha);` (wrapper with a default constructor) | exact | **exact** |
| `w3`: wrapper member, `float` parameter, body `a.value = alpha;` (no aggregate copy) | 96.73% | 96.73%, `push ebx` from `[esp+0x10]` |
| `p2h`: `float` parameter, `a(alpha)` through the wrapper's converting constructor | 96.73% | 96.73% |
| `p2g`: 8-byte wrapper `{value, pad}` by value | not exact | 96.73%. The 8-byte copy is scalar-replaced |
| `p2k`: wrapper with a user-defined member-wise copy constructor | not exact | 96.02%. The tint constructor is emitted out of line |
| `p2e`: wrapper passed by `const &`, `a(alpha)` | 96.73% | **exact**. Miss: the implicit copy constructor `a(alpha)` is still a 4-byte aggregate copy from the temporary. The rule is about the copy, not about passing by value |
| `w4`: wrapper by value, called with a plain `float` (implicit conversion) | not predicted | 96.02%, the tint constructor is emitted out of line |

8 of 9 predictions held. The miss refined the rule to "any implicit copy of the wrapper object".

## 6. `quest_spawn_timeline_update`: what the store needs

Follow-up ([qst-dead-store.md](qst-dead-store.md)): the lowered copy is promoted first and then
demoted by path P, not left in memory. What the triplet needs is a local definition that is dead at
`build_live_ranges`; the intrinsic is only the known way to survive the final dead-code pass.

Native: `lea edi, [esi+0xc]; mov [esp+0x10], edi; mov [esp+0x10], ebx`, heading via `[edi-4]`,
template via `[edi]`.

- **The heading base follows from the copy.** In the four-byte witness
  ([evidence](../../evidence/timeline-four-byte-home-2026-09-13/README.md)), replacing
  `((float *)template_id)[-1]` with plain `entry->heading` gives the same body, still
  `mov eax, [edi-4]`. Traced: the group loop's strength reduction sees `&entry->template_id` as a
  value (the copy's source), keeps `entry + 12` (#216), and hoists the heading and y addresses as
  `#216 - 4` and `#216 - 8`. So any source that copies the pointer as a value produces `[edi-4]`.
  The canonical source, which only dereferences the pointer, gets `[esi+8]`.
- **The store is not a spill of `edi`.** `edi` is a global range defined by the `lea`. A spill or
  store-back (paths H, K, L) would store the range's own home and later reload it. The native slot is
  overwritten by `spread` at once, so at frame layout the copy had no read after its store.
- **So the copy's destination has no reference left at promotion, and the copy was not deletable.**
  By §3.2 that is a lowered copy (path C or D) or a volatile store (path A):
  - The byte loop in the witness and `unsigned int n = sizeof copied; memcpy(&copied, &selected, n);`
    give identical bodies (traced prediction: 86.09%, prefix 14, 115 instructions, all five native
    signatures [FDPRE]).
  - A literal-size `memcpy`, a plain copy, a copy through `int **`, an address-taken holder struct
    (read directly, through an inline reference helper, or only by a guard), a 4-byte pointer wrapper
    (by value, by copy, or as an inline parameter) and dead 12-byte struct or `memcpy` copies are all
    folded or deleted before promotion in the synthetic controls (§7). The witness evidence records
    the same for a literal `memcpy` and a plain assignment inside the timeline itself.
  - A dead variable-size `memcpy` is deleted. A used one is absorbed into the register range (§3.2).
    Only a copy whose last read disappears after the optimizer's final dead-code pass (the witness
    guard `copied != selected && entry->count <= 0`, removed in `rebuild_flow_graph` 0x10743190 at
    0x107136f2 per the witness evidence) leaves the store.
  - Escaping the pointer to a call (path J) puts the whole variable in memory with a reload after
    the call.

No plain spelling satisfies these conditions. The store in native therefore points to a copy
construct in the original source, a `volatile` home, or a compiler difference. Both witnesses are
diagnostic, not recovered source.

## 7. Control summary

Each control is compiled as `quest_spawn_timeline_update` (only the IL matters) against
`struct rec_t { float x, y, heading; int template_id; int trigger; int count; }` with `e = &table[g_index]`
and `sel = &e->template_id`.

| Control | Body (short) | Predicted | Observed store lifecycle |
|---|---|---|---|
| `float_wrap4` | `wrap_t w; w.value = g_alpha; wrap_t c = w;` pushed twice | overlay pattern | `mov eax,[g_alpha]; mov esi,eax; mov [esp+4],eax; push esi` ✔ |
| `fild_local` | `s = 0; loop { sink_f((float)s); s += 40; }` | store-back then demotion | store-backs at 0x1072f6cc, demoted in colouring, `s` in memory ✔ |
| `volatile_ptr` | `int *volatile vp = sel;` | memory throughout | memory throughout ✔ |
| `escape_call` | `int *p = sel; sink_pp(&p); sink_i(*p);` | store-back plus reload | whole variable memory after `build_live_ranges` (store and reload) — partly missed |
| `int64_local` | `__int64 v = g_count; v *= g_index;` | halves stored at lowering | halves created at lowering, then register candidates ✔ / extra |
| `struct_arg8` | 8-byte struct passed by value | pushes, no local store | pushes from registers ✔ |
| `fastcall_param_addr` | `__fastcall` helper taking `&value` | home store in `assign_parameter_homes` | ✔ |
| `pressure` | seven live ints in a loop | demotion in colouring | `j` demoted in colouring ✔ |
| `memcpy4`, `memcpy4_live` | literal `memcpy(&cp, &sel, 4)` | scalarized, no store | no store ✔ |
| `memcpy_varsize_guard` | `memcpy(&cp, &sel, n)` + witness guard | dead store from lowering | `lea esi,[eax+0xc]; mov [esp+4], esi` ✔ |
| `memcpy_const_guard` | same with literal size | no store | no store ✔ |
| `loop_copy_guard` | byte loop + guard | dead store | dead store ✔ |
| `memcpy_varsize_dead` | variable-size `memcpy`, destination never read | not decided | deleted before promotion |
| `memcpy_varsize_used` | variable-size `memcpy`, destination dereferenced | not decided | lowered store absorbed into the live range |
| `idiom_copy`, `dead_copy12`, `dead_memcpy12`, `dead_obj4` | dead copies | deleted | deleted ✔ |
| `ptr_wrap4`, `obj4_copy_used`, `byval_inline` | 4-byte pointer wrapper copies | folded, no store | folded ✔ |
| `addr_pp_read`, `addr_struct_*`, `plain_copy_late_guard*` | address-taken holders and plain copies with guards | folded | folded ✔ |

## 8. Open questions

- Which helper in `build_live_ranges` (between 0x10726e00 and 0x10726e59) turns kind-2 operands of
  candidate symbols into placeholders, and the exact rule in `insert_upward_exposed_reloads` that
  returns overlapping views to memory. Both are traced at the pass boundary only.
- The exact rule that returns an escaped local wholly to memory in `build_live_ranges` (control
  `escape_call`), as opposed to storing it back before the call.
- In `pressure`, the demotion of `j` happens between a split spill-store call and the next
  `demote_live_range` call; the responsible call was not isolated.
- Which globopt pass deletes a dead variable-size `memcpy` (`memcpy_varsize_dead`), and the full list of
  steps that run after the last dead-code elimination.
- The x87 depth spill (path N) was not exercised.
- Symbol class 0xa and type class 7, both rejected by promotion, were not identified.
