# Translation-unit preludes: what a real DirectX 8.1 SDK prelude changes (C2.DLL 8966)

Snail-mail's `read_repeating_text_input_key_code` became byte-exact only after a prelude of the real DirectX 8.1
SDK headers moved `RstrASC`'s frontend id into a wrapping window ([call-operand-order.md](call-operand-order.md),
[frontend-ids.md](frontend-ids.md)). This note tests whether the same prelude (`<windows.h>`, `<d3d8.h>`,
`<d3dx8.h>` in front of the Crimsonland headers) matters for Crimson:

1. whether it moves the id-keyed residuals of `player_update` and `projectile_render`;
2. whether native evidence pins the prelude;
3. whether `D3DXVECTOR2`'s operators supply `player_update`'s missing alias classes.

Addresses are C2.DLL virtual addresses (image base 0x10700000). All compiles use the pinned `msvc6.5` driver
with each scratch's own flags (`/O2 /GB /W3 /GR-` for the two targets). Evidence labels:

- **verified**: seen in compiles, listings or a preserving trace;
- **read**: static reading in Binary Ninja;
- **inferred**: fits every compile, not traced.

## Short answer

1. **No. The prelude changes nothing in either function** [verified]. With every prelude variant, both functions
   compile to the same listing as cf7f728f3. That covers eight variants: with and without `windows.h` and `d3dx8.h`,
   `WIN32_LEAN_AND_MEAN`, `d3dx8.h` first, the prelude after the Crimsonland headers, and a full game prelude
   with `mmsystem.h`, `dinput.h` and `dsound.h`. The listings also stay the same under 384 uniform id offsets
   (every residue 0..127 and every multiple of 0x100). The residuals named in the question are keyed by C2's
   **per-function** counters, not by C1XX ids:
   - the `move_speed` owner id is a globopt expression owner;
   - the square order uses CSE temp and local ids;
   - K6/K7 are field-symbol and optimizer-temp indices.

   A trace of every commutative sort and every Sethi-Ullman decision confirms it. The only keys that move with
   the prelude are those of call-bearing operands (need 8), and none of them ever ties on need and size.
2. **No, not from the Crimson scratches.** Among the 613 crimsonland.exe C++ source scratches, one function
   depends on frontend ids at all: `dx_get_version_fallback_from_files`. It sits in its own translation unit,
   and it constrains only the id of its first string literal **mod 64**: 58 of 64 residues are exact. No site
   ties to `player_update`'s or `projectile_render`'s translation unit, so no prelude can be pinned for them.
   The mechanism is new: C2 frees unused constant-candidate live ranges in bucket order of a hash keyed on the
   frontend id mod 64 (§3). Every C++ scratch was also scanned for call-hash ties, the snail-mail mechanism
   (§4.3).
3. **No.** `D3DXVECTOR2`'s operators give byte-identical code and exactly the same class count as the 2003 MOD
   SDK `vec2_t` operators already measured in [pu-alias-budget-sources.md](pu-alias-budget-sources.md).
   Rewriting the 81 `player_update_vec2_set` sites adds 184 classes with either set (first pointer class
   609 → 793). With the real SDK type through casts it is also 793, with identical code. The D3DX pointer
   helpers (`D3DXVec2Add`/`Subtract`/`Scale`) *remove* 233 classes. Neither is a source for the missing ~200.
4. **Adopting the prelude repo-wide is harmless but buys nothing.** After minimal conflict fixes in 5
   scratches, all 613 surveyed crimsonland scratches compile to identical listings, including the 609 exact
   ones. For the grim.dll check, see §6.3.

## 1. Where C1XX frontend ids reach C2 code generation

| Path | Where | What the id does | Effect on output |
|---|---|---|---|
| Call and label operand hash | `hash_operand` 0x1070db59, kind 4: `v = fe->id; v>>16 ^ v&0xffff` | enters the 16-bit hash of every tree that contains a call or label | decides only when need and size tie: commutative sort (`compute_tree_cost_and_sort` 0x1070d90c) or SU order (`emit_tree_as_tuples` 0x1070e114). See [call-operand-order.md](call-operand-order.md) |
| Constant-candidate hash | `make_constant_candidate_operand` 0x10727f41 | bucket = `value % 64` for an int constant (kind 7), `fe_id(sym->parent) % 64` for `&sym` (kind 3), `sym+0xc % 64` otherwise; chains in `g_constant_symbol_hash` 0x1079d750 | live-range id recycling (§3) [read, verified] |
| Frontend scope hash | `fe_symbol_lookup_id` 0x10740f64, `id & 0x3ff` ([core.md](core.md)) | lookup only | no order effect found (period-1024 offsets gave no change) |

What the ids do **not** reach [verified]:

- C2 symbol ids: locals 1..31, globals from 32, temps, per function
  ([call-operand-order.md](call-operand-order.md) §3);
- globopt expression owners ([pu-factor-order.md](pu-factor-order.md) §1);
- CSE temps ([x87-scheduling.md](x87-scheduling.md) §5);
- alias classes ([pu-alias-budget-sources.md](pu-alias-budget-sources.md)).

With a +0x8000 shift, the `player_update` sort trace differs in exactly the 232 keys of call-bearing operands
(`need=8`), and nowhere else. The `move_speed` field keys `0x10007 | (owner&3)<<14` and all local keys are
unchanged.

## 2. Q1: prelude variants on the two targets

Frontend ids measured with `fe_id_probe.py ids`. The SDK headers are the DirectX 8.1 SDK set that snail-mail
uses (`fetch_dx81_sdk.sh`), passed as `/I<dx81>`, so they come ahead of MSVC's `Include` and `third_party/headers`.

| Variant | `player_update` id | `crt_rand` id | `projectile_render` id |
|---|---|---|---|
| cf7f728f3 (no prelude) | 0x1122 | 0xeb7 | 0x110c |
| `windows.h` | 0xb3f8 | 0xb18d | 0xb3e2 |
| `windows.h`, `d3d8.h` | 0xbbea | 0xb97f | 0xbbd4 |
| `windows.h`, `d3d8.h`, `d3dx8.h` | 0xcbfc | 0xc994 | 0xcbe6 |
| `d3d8.h`, `d3dx8.h` (no explicit `windows.h`) | 0xcbfc | 0xc994 | 0xcbe6 |
| `d3dx8.h`, `windows.h` | 0xcbfc | 0xc994 | 0xcbe6 |
| `WIN32_LEAN_AND_MEAN` + the three | 0xac4e | 0xa9e6 | 0xac38 |
| + `mmsystem.h`, `dinput.h` (0x0800), `dsound.h` | 0xda15 | 0xd7ad | 0xd9ff |
| the three after the Crimsonland headers | 0xcbfc | 0xeb7 | 0xcbe6 |

The three-header prelude is +47,834 ids in front of `player_update`. That is less than snail's 48,169, because
`math.h` is already counted in the base.

Every row compiles to the base listing (md5-identical `crimson match dump`), so the scores are those of cf7f728f3:

| Function | Raw | Labels masked | Structural | Stack masked | Refs |
|---|---|---|---|---|---|
| `player_update` | 74.40% | 83.76% | 84.55% | 94.11% | 863/0/0 |
| `projectile_render` | 94.23% | 99.20% | 99.20% | 99.57% | 544/0/0 |

Per-site order is therefore unchanged in every variant:

- **`player_update` `move_speed` lanes.** 19 of the 25 `fmul [edi+0x68]` directly follow `fsin`/`fcos`;
  native has 18. So one lane is still in the wrong order, the same one as at cf7f728f3.
- **`player_update` square order.** Unchanged.
- **`projectile_render` K6 and K7.** The same regions remain: K6 at 0x424c5e, K7 at 0x424cd0, 0x424d75,
  0x424e37 and 0x424efd.

### 2.1 Conflicts between the SDK and the scratch headers

Only one conflict appears in the two targets. The scratches declare
`vec2f_t *__stdcall D3DXVec2Normalize(vec2f_t *, const vec2f_t *)` inside `extern "C"`, and `d3dx8math.h`
declares it with `D3DXVECTOR2 *`, which gives C2733. The fix: drop the local declaration and cast at the calls,
`D3DXVec2Normalize((D3DXVECTOR2 *)&v, (const D3DXVECTOR2 *)&v)`. The code is identical.

`crimsonland_types.h`, `crimsonland_gameplay.h`, `grim2d_cpp.h` and the owner headers need no change. Redefining
`vec2f_t` as `D3DXVECTOR2` is impossible: many unions in `crimsonland_types.h` hold a `vec2f_t`, and a class with
constructors cannot be a union member (33 C2620 errors).

### 2.2 Why nothing moves: the tie census

`sort_trace.py` and `su_order_trace.py` on the base build and on +0x8000 / SDK builds:

| Function | Sort events with a call-bearing operand | Of those, a need/size tie with a neighbour | SU decisions (dependent) | Ties | Flips |
|---|---|---|---|---|---|
| `player_update` | 116 | 0 | 3533 (212) | 0 | 0 |
| `projectile_render` | 0 | 0 | 2628 (2) | 0 | 0 |

A call's need is 8 (7 for the call plus its argument subtree). Every operand it is compared with has a lower
need, so the hash never decides. The frontend id therefore cannot change either function. The one exception
would be the constant-candidate path (§3), and all 64 residues were compiled to rule it out.

## 3. The second path: constant-candidate buckets recycle live-range ids

`dx_get_version_fallback_from_files` (0x0041cfe0, DirectX version probe, 1014 instructions, exact at cf7f728f3) is the
only surveyed function whose listing depends on frontend ids. Two independent parameter reloads at the entries of
three blocks, `mov edi,[esp+0x424]` and `mov esi,[esp+0x420]`, swap order.

- **The listing depends on the offset D mod 64 only.** Relative to the scratch, D ≡ 8, 9, 13, 27, 35 or 42
  (mod 64) gives 99.70%, and every other residue is exact. This set was measured in 0x5a00..0x5aff and it
  predicted 0x0..0xff and 0xb000..0xb0ff exactly, so 768 offsets agree. [verified]
- **The IL is identical up to lowering** (`il_stage_trace.py`) and the scheduler input order differs
  (`sched_trace.py`, seq 1/2 swapped at L16, L48, L120). `priority_trace.py` shows the same symbols with the
  same priorities and tie keys, but **different live-range ids**, so the colouring queue's id-ordered
  tie-breaks ([regalloc.md](regalloc.md) §3.7) pick another order. [verified]
- **Why the ids differ** [read]:
  1. `promote_immediates_to_candidates` 0x1072795a turns int constants (kind 7), symbol addresses (kind 3) and
     code addresses (kind 4, outside call and branch tuples) into class-0xd candidates.
  2. `make_constant_candidate_operand` 0x10727f41 files them in `g_constant_symbol_hash` 0x1079d750. The bucket
     for a symbol address is **the frontend id of the symbol's fe record mod 64**; string literals have
     frontend ids ([frontend-ids.md](frontend-ids.md) §3). Each candidate gets a live range at once.
  3. `create_web_live_ranges` 0x1072f55d walks the 64 buckets in ascending order and frees every constant range
     without uses (`free_live_range` 0x10724a85 pushes it on `g_live_range_free_list` and keeps its id).
  4. `new_live_range` 0x10723758 pops that LIFO list first, so the webs created next inherit the freed ids in
     reverse bucket-walk order.

  Moving every string's id by D changes the bucket interleaving of the strings against the fixed int-constant
  buckets. That changes which recycled id each web gets.

A simple collision model does not reproduce the bad residue set: the colliding pairs at bad and good residues
overlap. Predicting the set from source needs a replay of the candidate list, which is not done here (open
question). The measured set, expressed in absolute ids, is: **the `"\\ddraw.dll"` literal's id mod 64 must not
be 5, 12, 42, 43, 47 or 61** (base id 0xa3e2; the other seven literals follow at fixed distances).

## 4. Q2: can a prelude be pinned from native evidence?

### 4.1 Survey

All 613 crimsonland.exe C++ source scratches compiled with `msvc6.5` (609 exact; the others are
`player_update`, `projectile_render`, `quest_spawn_timeline_update` and `reserved_color_global_init`). Each was
compiled with:

- a pad of 0x5a5b ids;
- pads of 1, 2, 4, 7, 16, 32, 45 and 59 ids (8 residues);
- the SDK prelude.

That is 6,130 compiles. Only `dx_get_version_fallback_from_files` changed, at 0x5a5b (residue 27).

### 4.2 Site table

| Site | Translation unit | Required frontend-id condition | Candidates that satisfy it |
|---|---|---|---|
| `dx_get_version_fallback_from_files`, parameter reload order at 3 block entries | DirectX version probe (its own `.cpp`) | `"\\ddraw.dll"` id mod 64 ∉ {5, 12, 42, 43, 47, 61} | see below |
| `player_update`, `projectile_render` | player / projectile render | none: no tie at any offset | all |

Candidates for the DirectX version translation unit, predicted from the measured string id before
compiling, then compiled:

| Prelude in front of the scratch (which has `windows.h`, `string.h`) | `ddraw` string id | mod 64 | Predicted | Observed |
|---|---|---|---|---|
| none (SDK include path only) | 0xa3f4 | 52 | exact | exact |
| `d3d8.h` | 0xabe6 | 38 | exact | exact |
| `ddraw.h`, `dinput.h` 0x0800 | 0xb467 | 39 | exact | exact |
| `ddraw.h`, `dinput.h`, `dmusici.h` | 0xc6d5 | 21 | exact | exact |
| `d3d8.h`, `d3dx8.h` | 0xbd58 | 24 | exact | exact |
| full game set (`mmsystem`, `d3d8`, `d3dx8`, `dinput`, `dsound`) | 0xcb73 | 51 | exact | exact |
| `ddraw.h`, `dplay8.h`, `d3d8.h` | 0xb80c | 12 | **mismatch** | mismatch (99.70%) |
| `WIN32_LEAN_AND_MEAN` + `d3d8.h`, `d3dx8.h` | 0x9daa | 42 | **mismatch** | mismatch (99.70%) |

Adding the SDK include directory alone shifts this unit by 18 ids (0xa3e2 → 0xa3f4). The SDK's `basetsd.h`
shadows VC6's; see §6.

A one-in-64 filter per translation unit cannot select a header set: any candidate passes with probability 58/64.
It only rules out single candidates such as the two above. The only site is in a translation unit that has no
target with an open residual, so nothing pins the player or projectile prelude.

### 4.3 Call-hash ties codebase-wide

`sort_trace.py` and `su_order_trace.py` were run on all 613 base scratches. The scan looked for decisions
where two call-bearing operands (need ≥ 7) tie on need and size, which is the snail-mail `RstrASC` shape.
**None exist.** The scan covered 49,670 SU decisions plus every commutative sort. Only 4 SU decisions had
call-bearing operands on both sides, and each was decided by need or size. So no crimsonland C++ function has
a call-hash window like snail's. [verified]

## 5. Q3: `D3DXVECTOR2` operators and the alias budget

`player_update` at cf7f728f3 with the SDK prelude. The `player_update_vec2_set` calls after the helpers were
rewritten mechanically (`scratchpad/tu-prelude/q3.py`):

- 69 `set(&d, a.x ± b.x, a.y ± b.y)` → `d = a ± b`;
- 1 `set(v, s * m.x, s * m.y)` → `*v = s * m`;
- 11 others → `d = T(x, y)`.

The operators come from one of three sources:

| Source of the operators | First pointer class | Markers / symbols | Code |
|---|---|---|---|
| none (cf7f728f3, current `vec2_t` shell) | 609 | 193 / 412 | base, 74.40% |
| MOD SDK `cltypes.h` style (`vec2_t` members, free `operator*(s, v)`) | 793 | 285 / 504 | 51.74% raw, 761/0/15 refs |
| `D3DXVECTOR2` declarations and `d3dx8math.inl` bodies transplanted onto `vec2_t` | 793 | 285 / 504 | identical to the row above |
| same, every operand cast `*(T *)&(e)` (either style) | 793 | 285 / 504 | identical |
| the real SDK `D3DXVECTOR2` through `*(D3DXVECTOR2 *)&(e)` | 793 | 285 / 504 | identical |
| `D3DXVec2Add`/`Subtract`/`Scale` pointer helpers for the 70 arithmetic sites | 376 | 116 / 256 | 66.38% raw, 808/0/1 refs |

- The operator style costs +184 classes for 81 sites (92 markers + 92 temporaries, about 2.3 per site),
  whichever header supplies it. C2 sees only the inlined bodies, and `D3DXVECTOR2`'s bodies
  (`return D3DXVECTOR2(x + v.x, y + v.y)`, ctor `x = fx; y = fy;`) have the same shape as `cltypes.h`'s.
  Const members, out-of-line `D3DXINLINE` definitions and member-vs-free `operator*` change nothing.
- So D3DX supplies no class that the cltypes value style (+307 in the natural set of
  pu-alias-budget-sources.md) does not already count. The last ~200 classes still have no source.
- The D3DX pointer helpers bind their pointer formals to address constants and locals, so the formals do
  not survive. They also delete the 70 `vec2_set` scope markers and float formals.

## 6. Landing, tooling and recommendation

### 6.1 What a landing would need

No prelude or rewrite improves any score, so there is no `best.diff`. The conflict fixes are in
`scratchpad/tu-prelude/sdk-compat.diff`, for reference. If the prelude is adopted anyway:

- **The SDK files.** They are gitignored in snail-mail, fetched by `tools/match/fetch_dx81_sdk.sh` (the pinned
  archive.org `dx81sdk_full.exe`, sha256 73f6…2d02). Crimson would need the same fetch step, or a path to
  snail's copy.
- **The include path.** `scratch.conf` has no include key. Options:
  - a `/I` in `CFLAGS` (works today; this is how every variant here was built);
  - a new cl.sh `INCLUDE` entry;
  - a `tools/match/include/crimson_prelude.h` that includes the SDK by relative path, as snail's
    `rshell_prelude.h` does.

  `CRIMSON_MATCH_INCLUDE_OVERLAY` is not usable for this: `compile_scratch` pops it from the environment and
  sets it only from `ScratchConfig.include_overlay`, which only `mutate --source` fills.
- **Header shadowing.** The SDK directory shadows these VC6 headers: `basetsd.h`, `ddraw.h`, `dinput.h`,
  `dsound.h`, the `d3d*.h` set and about 40 DirectShow headers. It also shadows the MinGW-derived
  `third_party/headers` copies of `d3d8*.h`, `d3dtypes.h`, `d3dvec.inl`, `ddraw.h`, `dinput.h`, `dinputd.h` and
  `dsound.h`. Build-cache keys follow the include graph, so a landing invalidates every cached object.

### 6.2 Minimal conflict fixes (all verified identical)

| Scratch | Conflict | Fix |
|---|---|---|
| `player_update`, `projectile_render`, `projectile_update` | local `D3DXVec2Normalize(vec2f_t *, const vec2f_t *)` against the SDK's | drop the declaration, cast the arguments to `D3DXVECTOR2 *` |
| `crimsonland_main` | local `IUnknown *WINAPI Direct3DCreate8(unsigned)` | drop it; `IDirect3D8 *direct3d = Direct3DCreate8(0xdc);` |
| `fx_spawn_particle`, `fx_spawn_particle_slow` | `extern "C" float cos(float)`/`sin` stand-ins against `math.h`'s C++ `float cos(float)` | drop them |
| `projectile_spawn` | same | drop them. Also `(float)(cos(angle) * 1.5f)` → `(float)cos(angle) * 1.5f`: with the real overload the unparenthesized-cast spelling multiplies in double (`fmul qword`, 98.41%). `cosf(angle) * 1.5f` is also exact |

### 6.3 Recommendation

Do not adopt the prelude repo-wide now:

- It changes no listing among the 613 crimsonland scratches:
  - the 609 exact ones;
  - `quest_spawn_timeline_update` (91.23%);
  - the two targets.
- It moves no residual.
- It adds an external SDK dependency, seven source edits and a cache invalidation.
- It gives no pinning power: one mod-64 site in a separate translation unit.

Keep it as a probe. When a residual traces to a call/label hash tie (need-8 operands tied on need and size) or to
live-range id order, run `fe_offset_sweep.py` on that scratch. Adopt a prelude for that translation unit only
if an offset fixes it.

A repo-wide change of the include path (a cl.sh `INCLUDE` entry) would also reach grim.dll, and there it
breaks things. I compiled the 603 grim.dll source scratches with only the SDK include directory added and no
prelude text:

- 553 compile to identical listings;
- 48 fail to compile, and 2 already fail as copies.

The grim headers are written against Wine's `d3d8.h`:

- `grim_d3d8.h` has `typedef void *HMONITOR`, and the SDK's `d3d8.h` then declares it again (C2371).
- `set_var.cpp` has `enum { D3DSGR_NO_CALIBRATION = 1 }`, which collides with the SDK macro.

A `#define HMONITOR_DECLARED` in `grim_d3d8.h` fixes 15 of the 48, with identical code. The rest reach the SDK's
`d3d8.h` along another path; not pursued. So if Crimson ever adopts the prelude, scope it to crimsonland.exe
translation units: a `/I` in their `CFLAGS`, or a Crimson prelude header. Do not change cl.sh.

## 7. Predicting from source

1. A frontend-id offset can change a function only in two ways:
   - **(a)** two call- or label-bearing operands of a commutative node, or of a reorderable binary node,
     tie on need and size;
   - **(b)** the function has address-constant candidates (string literals or global addresses as
     immediates), and its colouring queue has ties decided by live-range id.
2. For (a), check the trace: `sort_trace.py`/`su_order_trace.py`, looking for equal `key >> 16` with need ≥ 7.
   The window follows from `hash = callee + 2*arg + 0x3f` ([call-operand-order.md](call-operand-order.md) §4).
3. For (b), only the offset mod 64 matters. Measure the 64 residues once with
   `fe_offset_sweep.py --deltas 0:64:1`. Then any header set is predicted by its effect on the first string's
   id mod 64 (`fe_id_probe.py ids`).
4. Everything keyed by C2's own per-function counters is prelude-independent:
   - owner ids and field sort keys;
   - local and CSE-temp keys;
   - slot order;
   - alias classes.

## 8. Acceptance tests

| Test | Prediction (before compiling) | Observed |
|---|---|---|
| SDK prelude on `player_update`/`projectile_render` | no tie on need/size in either trace, so identical listings | identical (md5) |
| 7 other prelude variants on both | identical | identical |
| 256 offsets ×0x100 and 128 unit offsets on both | identical | identical |
| sort keys base against +0x8000 | only need-8 keys differ | 232 need-8 keys differ, nothing else |
| `dx_get_version…` residues in 0x0000..0x00ff and 0xb000..0xb0ff, from the set found in 0x5a00..0x5aff | same 6 residues bad | exact match (768 offsets) |
| SDK prelude + pads 17, 18, 19, 20, 23, 37, 45, 52, 53 on `dx_get_version…` (SDK residue 54) | bad for 18, 19, 23, 37, 45, 52; exact for 17, 20, 53 | 9/9 |
| 8 prelude candidates on `dx_get_version…` (table in §4.2), from their measured string ids | 6 exact, 2 mismatch | 8/8 (two negative controls) |
| Q3 `real` `D3DXVECTOR2` against the transplanted bodies | same bodies, so same code and classes | identical code, 793 = 793 |
| Q3 cltypes against D3DX operators | same inlined shapes, so identical | identical |
| negative control: `vec2f_t` as `D3DXVECTOR2` | unions reject a class with constructors | C2620 × 33 |

## 9. Tool

```sh
uv run python scripts/c2/fe_offset_sweep.py <scratch-dir> --out <new-dir> --deltas 0:64:1 \
    [--prelude prelude.h] [--cflags "/IZ:<dx81>"] [--jobs 8]
```

It pads the translation unit with an enum that consumes exactly D ids (1 + D − 1 enumerators), optionally after
a prelude file. It compiles and scores each copy with `residual_map.py`'s masks, and groups the offsets by
candidate listing. On `dx_get_version_fallback_from_files` it prints 58 exact offsets and the 6 bad ones.

## 10. Open questions

- The exact bad residue set of §3 from source: this needs a replay of the constant-candidate list, of which
  constant ranges are freed (`def < 1` in `create_web_live_ranges`), and of the colouring ties.
- What kind 4 hashes in `make_constant_candidate_operand` (`sym+0xc % 64`, a code address outside call and
  branch tuples): not traced.
- C translation units (`.c` scratches) and msvc7.0 were not surveyed.
