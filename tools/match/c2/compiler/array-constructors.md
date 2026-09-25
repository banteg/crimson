# Array constructors, dynamic initializers and the `*_global_init` countdowns

This note explains where the `*_global_init` countdown loops in `crimsonland.exe` come from and how
to write them as the source they came from: a plain definition such as `particle_cpp_t
particle_pool[0x80];`. The front end (C1XX) emits a call to the compiler-generated
`vector constructor iterator`. C2's inliner then expands that iterator and the element constructor,
and the loop optimizer turns the result into the `mov eax,arr; mov ecx,N; ...; add eax,size; dec
ecx; jne` loop.

All 13 `*_global_init` array initializers, their 13 `*_global_init_thunk` CRT entries and the
`invoke_callback_n` helper were rebuilt from array definitions in a work directory. All 27 are
byte-exact under the canonical `/O2 /GB /W3 /GR-` flags (§7). Each claim below is marked as traced
(observer run), compiled (predicted, then checked by compiling) or read (Binary Ninja only).

## Observing it: `scripts/c2/inline_trace.py`

```sh
uv run python scripts/c2/inline_trace.py <scratch-dir> --out <new-dir> --report
uv run python scripts/c2/inline_trace.py --report-only <trace-dir>
```

The tool runs the scratch through `crimson match c2-trace`'s preserving harness, using the readable
IL observer from `iv_trace.py`. Hooks:
- the per-function call to `inline_function_calls` 0x107180fd (IL before inlining);
- the first pass boundary 0x107130cb (IL after inlining);
- the top-level (0x10718134) and recursive (0x1071888b) calls of `inline_expand_calls` 0x107181a8;
- its call to `inline_substitute_formals` 0x1075c9b0.

For each compiled function the report prints the call tuples before inlining, the depth of every
expansion, and the calls that are still there at the first pass. The whole-COFF, replay and
missing-stream checks are unchanged. The inliner function names used below are proposed by this
investigation and have not yet been applied to the Binary Ninja database or `c2_symbols.json`.

## 1. What the front end emits

C1XX, not C2, decides the shape of a dynamic initializer. It emits one compiler function per
role. The functions are COFF-local (`IMAGE_SYM_CLASS_STATIC`) symbols `_$E<n>`, each in its own
`.text` COMDAT section. The `.CRT$XCU` slot is a local data symbol `_$S<n>`. A single counter per
translation unit numbers all `$E` and `$S` symbols (including local-static guards) in creation
order (compiled):

| Namespace-scope definition | Functions, in section and emission order | `.CRT$XCU` points at |
| --- | --- | --- |
| `T a[N]`, `T` has a constructor, no destructor (any `/GX`) | `$E2: jmp $E1`, then `$E1` construct | `$E2` (`$S3`) |
| `T a[N]`, destructor, no `/GX` | `$E4: call $E1; jmp $E3`, `$E1` construct, `$E3: push $E2; call _atexit; pop ecx; ret`, `$E2` destroy | `$E4` (`$S5`) |
| `T a[N]`, destructor, `/GX` | same four functions; `$E1`/`$E2` call the CRT's `??_L`/`??_M`; the constructor and destructor are emitted out of line between `$E1` and `$E3` | `$E4` (`$S5`) |
| scalar `T x` | the same roles, without the iterator | as above |

The iterator C1XX asks for depends on `/GX` and the destructor (compiled):

| Case | `$E1` asks for | `$E2` (destroy) asks for |
| --- | --- | --- |
| no `/GX`, or no non-trivial destructor | `??_H@YGXPAXIHP6EX0@Z@Z` `vector constructor iterator(t, size, N, &T::T)` | `??_I@YGXPAXIHP6EX0@Z@Z` `vector destructor iterator(t, size, N, &T::~T)` |
| `/GX` and a non-trivial destructor (an empty user `~T() {}`, or an implicit one from a member) | `??_L@YGXPAXIHP6EX0@Z1@Z` `eh vector constructor iterator(t, size, N, &T::T, &T::~T)` (external CRT) | `??_M@YGXPAXIHP6EX0@Z@Z` `eh vector destructor iterator` (external CRT) |

- `??_H` and `??_I` are synthesised by C1XX as ordinary inline IL functions. They appear in the `ex`
  stream with formals `__t`, `__s`, `__n`, `__f` (see the `sy` and `gl` streams of any trace), and
  every object that uses them emits them as public COMDATs, even when every call was inlined.
  `??_H` is `while (--__n >= 0) { (__t->*__f)(); __t += __s; }`. `??_I` first advances `__t` by
  `__n*__s` and then runs `t -= s; (t->*f)()` in the same countdown.
- `??_L` and `??_M` are CRT library functions (`ehvecctr.obj`, `ehvecdtr.obj`, already matched as
  `grim_vector_constructor_iterator_eh` and `grim_vector_destructor_iterator`). C2 cannot inline
  them, so a `/GX` array with a destructor always produces `push dtor; push ctor; push N; push size;
  push arr; call ??_L`. This is the `bonus_meta_table`/`quest_meta` pattern at 0x4123d0 and 0x412450.
- Multi-dimensional arrays are flattened: `E grid[4][8]` passes `N = 32` (compiled).
- `N = 1` still calls `??_H` with `n = 1` (visible under `/Ob0`). C2 folds the one-trip loop into
  a single store (compiled).
- **Function-local statics** (`static T a[N];` in a function body) get a guard bit in `$S<n>`
  (`mov cl,[$S]; test cl,1; jne skip; or cl,1; ... mov [$S],cl`), the same inlined constructor
  loop placed inline in the function, and an `atexit($E<n>)` call. The atexit call happens **even
  when `T` has no destructor**: `$E<n>` is then an empty `ret` (compiled). This explains
  `perk_selection_choice_items_destroy` (0x406150, a lone `ret`). Under `/GX` with a destructor, the
  local-static path also calls `??_L`/`??_M` (compiled).

## 2. What C2 does: the inliner (P2/inline.c) [traced + read]

`compile_functions` calls `inline_function_calls` 0x107180fd (previously named
`function_prepare_temps`) at 0x107580fa, before the first stock pass boundary. It runs these steps:
1. It sets `g_inline_total_size` 0x1079f234 to the function's own size estimate (`fe_function+0x6d`).
2. It calls `inline_expand_calls(fn, depth 1, budget, 0)`, where the budget is `clamp(2*size, 1000,
   35000)`. Every small initializer traced gets budget 0x3e8.

`inline_expand_calls` 0x107181a8 (ecx = function, edx = depth) does the following:
1. It sets `fe_function+0x73` bit 0x10 on the function it is expanding, and clears it on return.
2. It collects call sites with `inline_collect_call_sites` 0x10718a2a.
3. For each call site, it enforces the per-callee size limit (`+0x6d <= 0x28`, or within the
   budget) and the global cap of 35000, and issues warnings C4710/C4714/C4711 (`warning(4, 0x2c6 +
   4*forceinline)`, `0x2c7`).
4. It reads the callee's IL.
5. It binds the actuals that are **address constants** to the callee's formals
   (`inline_bind_address_actuals` 0x1075bdb3). It drops the bindings of formals that the callee
   writes (0x1075d816) and replaces every remaining formal use by the address operand
   (`inline_propagate_address_formals` 0x1075d889).
6. It **recurses** into the callee body with depth+1 (0x1071888b).
7. It substitutes the remaining formals with `inline_substitute_formals` 0x1075c9b0 and splices the
   body in place of the call tuple.

Step 5 is what makes array construction collapse. `&T::T` is an address-constant actual of
`??_H`, so inside the callee copy `(__t->*__f)()` becomes a direct call of the constructor. The
recursive step then finds it and inlines it. The trace of `bonus_pool` shows this:
- `$E1` before inlining: one call tuple (op 0x184, kind 0xe) to the `??_H` function operand, with
  the constructor address among its arguments.
- Expansions at depth 2 (`??_H`) and depth 3 (the constructor).
- No call left at the first pass.
- `$E2` keeps its call to `$E1` in IL. It becomes `jmp $E1` only in the late tail-call lowering
  ([frame.md](frame.md) §4).
- `??_H` itself is compiled as a normal function afterwards, with its indirect `call ebx`.

**Recursion guard.** The collector skips a callee whose `+0x73` bit 0x10 is set, meaning it is
already being expanded. The one exception is when the `inline_recursion` pragma state is on: the
aux of marker tuple op 0x1b8, bits 8..11, which the collector consumes (0x10718df5). An element
type with a **member array of class type** (`effect_entry` with `vertex vertices[4]`) therefore
behaves like this:
- The outer `??_H` expands, and so does the element's implicit constructor.
- That constructor's own `??_H` call is **not** expanded, because `??_H` is in progress. It stays
  a real call, and the vertex constructor is emitted out of line because its address is taken.
- Traced: depths `[2, 3]` and one call left.
- With `#pragma inline_recursion(on)` the trace shows depths `[2, 3, 4, 5]` and no call left. The
  whole initializer collapses to `ret`, which confirms the prediction.

This is the native `effect_pool_vertices_global_init` shape: an outer countdown over 0x200 entries
around `push ctor; push 4; push 0x1c; push esi; call ??_H`.

Other C2-side facts (all compiled):
- `/Ob0` stops the expansion (`$E1` pushes four arguments and calls `??_H`). `??_H` is inline IL, so
  `/Ob1` (the `/O2` default) is enough.
- A constructor that is not inline (defined out of class without `inline`) is not expanded at
  `/Ob1`. `??_H` still is, so the loop calls the constructor. The pointer and counter move to
  `esi`/`edi` because they must survive the call.
- An empty inline constructor leaves an empty loop, which is deleted. `$E1` is a lone `ret`, as at
  0x41e0c0 `unused_global_noop_init` (its bytes cannot tell a scalar from an array).

## 3. The loop shape

After expansion, `$E1` is an ordinary counted loop with a constant trip count. Its shape comes from
the normal loop passes ([strength-reduction.md](strength-reduction.md)):
- the counter is a countdown `mov ecx,N ... dec ecx; jne`. `--__n >= 0` with a known `N` has its
  guard folded, and the exit test is rewritten to count down;
- the element pointer is a pointer IV `add eax,sizeof(T)`;
- the pointer is anchored at a field offset chosen by the anchor rules, for example
  `mov eax,creature_spawn_slot_table+0x10` with `[eax-0x10]..[eax]` stores, or
  `mov eax,bonus_hud_slot_table+4` with stores from `[eax-4]` to `[eax+0x18]`;
- the order of stores in the loop body is the order of the constructor body. Constructor argument
  temporaries and base-class constructor boundaries matter, as they do for any inlined code
  (§7, `player_state_table`).

The destroy side without `/GX` (`??_I` inlined) starts at `a + N*size` and runs `sub eax,size; dec
ecx; <dtor body>; jne` (compiled).

The hand-written countdowns in the canonical scratches (`int remaining = N; T *e = pool; do { ... ++e;
} while (--remaining != 0);`) reach the same IL loop by another route. That is why they match. The
array definition is the plausible source.

## 4. Crimson mapping

Every `*_global_init_thunk` is the `.CRT$XCU` entry `$E2`. The table at 0x471004 lists them in
address order, for example 0x412220, 0x412250, 0x412290, 0x412350 and 0x4123c0. Every
`*_global_init` is `$E1`. None of these arrays has a destructor (their thunks are single `jmp`s, with
no `$E3`/atexit). They are therefore independent of `/GX`.

| Native | Source that reproduces it (work dir, all byte-exact) |
| --- | --- |
| `bonus_pool_global_init` 0x412230 | `struct bonus_pool_entry_t : bonus_entry_t { bonus_pool_entry_t() { bonus_id = BONUS_ID_NONE; } }; bonus_pool_entry_t bonus_pool[16];` |
| `bonus_pool_sentinel_global_init` 0x41f570 | the same type, scalar `bonus_pool_entry_t bonus_pool_sentinel;` |
| `creature_spawn_slot_table_global_init` 0x412260 | 32 × constructor `owner=0; interval_s=0.5f; timer_s=0.5f; count=0; limit=-1;` |
| `particle_pool_global_init` 0x41e520 | 0x80 × the canonical body as the constructor, including `crt_rand()` |
| `projectile_pool_global_init`, `secondary_projectile_pool_global_init`, `sprite_effect_pool_global_init`, `credits_line_table_global_init`, `fx_queue_global_init`, `creature_pool_global_init` (0x181) | the canonical loop body moved into the element constructor, in the same order |
| `player_state_table_global_init` 0x41e5d0 | **two constructor levels**: an entity base constructor (the ten `entity_*` fields) and the player constructor. Flattening them into one constructor moves one store (98.00%) |
| `bonus_hud_slot_table_global_init` 0x41a7d0, `weapon_table_defaults_global_init` 0x451910 | the existing `*_cpp_t` classes, defined as `bonus_hud_slot_cpp_t bonus_hud_slot_table[0x10];` and `weapon_storage_entry_cpp_t weapon_ammo_class[0x40];` (the placement-new wrappers are not needed) |
| `effect_pool_vertices_global_init` 0x42de10 | a vertex class with an empty inline constructor, used as `vertices[4]` inside a 0xbc-byte entry; `effect_entry_cpp_t effect_pool[0x200];` |
| `invoke_callback_n` 0x4010f0 | not a hand-written helper: it is the `??_H` COMDAT (`SYMBOL='??_H@YGXPAXIHP6EX0@Z@Z'` from any of the sources above) |

The entity field set is identical in `creature_pool_global_init` and `player_state_table_global_init`.
Together with the two-level constructor result, this suggests a shared entity base class (inferred).

## 5. What the scratch system and native link need

- **Matcher.** Nothing blocks it. Set `SYMBOL='_$E1'` for the initializer and `SYMBOL='_$E2'` plus
  `REFERENCE_ALIASES='$E1:<name>_global_init'` for the thunk. The source is one array definition.
  Array references resolve either C++-mangled (`?bonus_pool@@3PAU...@@A`) or C-named, and both
  pass. For the nested case, `??_H` resolves to `invoke_callback_n` and the out-of-line constructor
  needs an alias to its native name (`ui_template_slot_ctor_noop`). `crimson match validate`
  accepts all of them.
- **Symbol numbers depend on the whole translation unit.** A single-array scratch gives
  `$E1`/`$E2`. Two arrays in one file give `$E1`/`$E2` and `$E4`/`$E5`. A destructor array takes
  four numbers. Local statics take guard `$S` numbers from the same counter. The bytes do not
  change, but `SYMBOL` and aliases must use the numbers of the file that is actually compiled.
- **Native relink.** `$E` symbols are static, so separate scratch objects cannot supply them to
  each other. The existing mechanism is a translation-unit cluster in
  `tools/native/translation_units/crimsonland.exe.json`, as `bonus-meta-lifecycle` already does,
  binding `{function, symbol}` pairs to one scratch object. The thunk/init pair of each array needs
  one such cluster. A single-array TU has two members, `_$E2` and `_$E1`.
- **Data ownership.** The array definition now lives in the scratch object. To keep the relink
  pointing at one array, define it with C linkage (`extern "C" { T bonus_pool[16]; }`, which is
  byte-exact and emits `_bonus_pool`). Its generated definition in
  `tools/native/data_definitions` must then be retired. Otherwise the link gets a duplicate
  `_bonus_pool`, or with C++ linkage a second, private BSS copy. The existing `bonus_meta_table`
  cluster has the second problem: its object defines `?bonus_meta_table@@3PAVbonus_meta_cpp_t@@A`
  while the rest of the link uses the generated `_bonus_meta_table`.
- **Headers.** The shared headers declare these arrays as `extern "C" <C struct> name[N]`. The
  owning TU needs a C++ element type with a constructor. Deriving from the C struct, as above,
  keeps the layout and the field names. It cannot include a header that declares the same name with
  another type.
- **Section layout** needs nothing extra. The `.CRT$XCU` slot and BSS come with the object, and
  COMDAT order within the object is the order in the tables of §1.

## 6. Predicting from source (checklist)

1. Is the object at namespace or function scope? Function scope means a guard, an inline loop and
   an always-present atexit.
2. Does it have a non-trivial destructor, and is `/GX` on? Both yes: `??_L`/`??_M` calls, four `$E`
   functions and out-of-line constructor and destructor. Destructor without `/GX`: four `$E`
   functions, with the inline countdown in `$E1` and the reverse countdown in `$E2`. No destructor:
   two functions, `jmp` thunk plus `$E1`.
3. Is the constructor inline (in-class, or declared `inline`) under `/Ob1`+? Yes: its body is the
   loop body. No: the loop calls it, with the pointer and counter in `esi`/`edi`.
4. Does the element contain a member array of class type? Then that inner `??_H` stays a call
   (unless `inline_recursion` is on), and its element constructor is emitted out of line.
5. Is `N` 1, or is the constructor empty? `N = 1` gives straight-line stores. An empty constructor
   gives `$E1 = ret`.
6. The loop registers, anchor and store order follow the ordinary rules
   ([strength-reduction.md](strength-reduction.md), [x87-scheduling.md](x87-scheduling.md)).

## 7. Acceptance tests

The experiment sources are not kept in the repo; section 7(a) gives the source form and
`scripts/c2/inline_trace.py` regenerates the traces.

**(a) `bonus_pool_global_init` and its thunk: passed.**
- Prediction from the source `bonus_pool_entry_t bonus_pool[16];` with an inline constructor that
  zeroes `bonus_id`:
  - `$E2 = jmp $E1`;
  - `$E1 = mov eax,bonus_pool; mov ecx,16; mov [eax],0; add eax,0x1c; dec ecx; jne; ret`.
- Observed: `match=100.00% prefix=7/7 refs=1/0/0 body_byte_exact=True` and `prefix=1/1
  body_byte_exact=True`.
- The `extern "C" { }` definition gives the same result.

**(b) All array initializers: passed.**
- The 13 `*_global_init` scratches rebuilt as array definitions are all byte-exact, and so are
  their 13 thunks. The table in §4 lists them.
- `bonus_pool_sentinel_global_init` (scalar of the same type) and `invoke_callback_n` (as `??_H`)
  are also byte-exact.
- One prediction failed on the first try. `player_state_table` with a single flattened constructor
  scored 98.00%: one store, `[eax+0x320]`, is scheduled first. Splitting the entity fields into a
  base-class constructor makes it exact. The inline boundary between the base and derived
  constructors matters, as it did for the canonical scratch's separate `construct_entity()` helper.

**(c) Negative controls** (each predicted, then compiled against `bonus_pool_global_init`):

| Variant | Predicted | Observed |
| --- | --- | --- |
| constructor defined out of class, not inline | loop calls the constructor through `esi`/`edi` | 10.53%, 12 instructions |
| `/Ob0` | `$E1` calls `??_H` | 15.38%, 6 instructions |
| empty destructor + `/GX` | `??_L` call | 14.29%, 7 instructions (`push`×5, call, ret) |
| effect pool + `#pragma inline_recursion(on)` | everything inlined, `$E1 = ret` | 12.50%, 1 instruction; trace depths `[2,3,4,5]` |

## Open questions

- Which object owns the single linked `??_H` copy at 0x4010f0? The linker keeps the first COMDAT in
  link order, but the first object (0x401000–0x4010ea) shows no array construction.
- Whether the `$E1`/`$E2` pairs at 0x412220–0x4123c0 (bonus pool, spawn slots, game status, the
  0x48-byte table at 0x482b10, bonus metadata) come from one translation unit or from several. The
  bytes are the same either way; only the `$E` numbers would change.
- `inline_1075cc23` (the operand-copy helper used when splicing) and the exact meaning of
  `fe_function+0x6b` were not traced.
- The flag 0x107ae240 set around the top-level inliner call and the `/Os` size threshold at
  0x10799280 were only read.

## Corrections to other notes and scratches

- `invoke_callback_n` (0x4010f0) is the compiler-generated `vector constructor iterator`
  `??_H@YGXPAXIHP6EX0@Z@Z`, not a game helper. The same holds for its declaration in
  `effect_pool_vertices_global_init` and `ui_menu_template_pool_init`.
- `function_prepare_temps` 0x107180fd is the per-function inliner entry. Its "temp sizing" is the
  inline budget.
- The PLAUSIBILITY audit's description holds, but the loops are generated in two stages: C1XX asks
  for `??_H`, and C2's inliner plus loop optimizer produce the countdown. No front-end loop is
  involved.
