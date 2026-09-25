# Plain sources for retained float and countdown spellings

Two exact scratches kept source spellings that look unnatural:

- `highscore_screen_update` had two `double` intermediates and two `memcpy` label copies.
- `effect_spawn_splitter_hit_burst` had a guarded `do/while` countdown.

This note gives plain replacements that stay byte-exact, the compiler rules behind them, and the
controls that fail. All results come from the pinned `msvc6.5` C2 with `/O2 /GB /W3 /GR-`. Each
candidate is a copy of the canonical scratch, checked with `uv run crimson match scratch`. Scheduler
evidence comes from `scripts/c2/sched_trace.py` and loop evidence from `scripts/c2/iv_trace.py`.

See [x87-scheduling.md](x87-scheduling.md) for FROUND and the 81-node window,
[optimizer.md](optimizer.md) for forward propagation, CSE and loop inversion, and
[strength-reduction.md](strength-reduction.md) for trip counts and countdowns.

## Summary

| Function | Retained spelling | Plain replacement | Result |
|---|---|---|---|
| `highscore_screen_update`, separator | `double center_offset = 128 - title_half_width;` and `position.x + (float)center_offset` | `float center_offset = 128 - title_width / 2;` and `position.x + center_offset` | 100%, 2004/2004, refs 639/0/0, `body_byte_exact=True` |
| `highscore_screen_update`, checkbox X | `double x_value = right_panel.x; filter_x = (float)x_value; widget_position((float)x_value, ...)` | `float x_value = right_panel.x; filter_x = x_value; widget_position(filter_x, ...)` | 100% (alone and combined with the separator) |
| `highscore_screen_update`, labels | `memcpy(&label_x, &right_panel.x, sizeof label_x)` in both branches | none found | best plain form is 90.42% |
| `effect_spawn_splitter_hit_burst` | `remaining` copy, `if (remaining > 0) { int radius_i = (int)radius; do {...} while (--remaining != 0); }` | `for (i = 0; i < count; i++)` with no guard, and `crt_rand() % (int)radius` written inside the loop | 100%, 75/75, refs 23/0/0, `body_byte_exact=True` |

The two highscore replacements together are exact (`combo_sep_width_chk_single`). They are also exact
with the `title_half_width` local removed entirely (`combo_no_half_local_chk_single`).

## 1. Checkbox X: a single-use float local replaces the double

Native code is `fld [right_panel.x]; fst [filter_x]; fstp [widget.x]`. The two stores share one x87
value.

**Rule.** A plain float-to-float copy is lowered to integer MOVs. This happens between the
`0x30a40` and `0x336f4` snapshots (see the float-owners evidence). An x87 operation between the load
and the stores keeps the copy on the x87 stack. There are two ways to get one:

- **The canonical `double`:** C1 emits float-to-double and double-to-float conversions. `x_value` is
  read twice, so it is not forward-propagated and has no FROUND.
- **The plain form:** `float x_value = right_panel.x; filter_x = x_value;`. `x_value` has one def and
  one use, so `forward_propagate_definitions` 0x10711afa moves the load to the `filter_x` store and
  inserts a FROUND (0x162), because the type class is 0x4000. `filter_x` then feeds the constructor.

**Trace** (`sched_trace.py`, window 142):

| Variant | Window | Nodes |
|---|---|---|
| canonical `double` | 16 nodes, 15 machine + 1 FROUND | `fld s592; fst s594; fstp s1576; fld s591; FROUND; fstp ...` |
| plain single-use float | 17 nodes, 15 machine + 2 FROUND | `fld s592; FROUND; fst s594; fstp s1576; ...` (same machine order) |
| `filter_x = right_panel.x;` with no temp | 17 nodes, 16 machine + 1 FROUND | `mov eax <- s606; mov s3466 <- eax; mov ecx <- eax; mov s595 <- ecx` (integer copy) |

FROUND emits no instruction. The machine nodes and their order are identical to the canonical.

**Controls** (whole function):

| Checkbox form | Result |
|---|---|
| `float x_value` read twice (`filter_x = x_value; widget(x_value, ...)`) | 87.30%, 2005 instructions. No FROUND, because it has two uses. |
| `filter_x = right_panel.x; widget(filter_x, ...)` | 87.30% |
| `widget(filter_x = right_panel.x, ...)` | 87.30% |
| `filter_x = right_panel.x; widget(right_panel.x, ...)` | 89.75% |
| `widget = right_panel; filter_x = widget.x;` | 90.10% |
| `widget(right_panel.x, ...); filter_x = widget.x;` | 99.80% |
| `float x_value` single use, `widget(x_value, ...); filter_x = widget.x;` | 99.80% |
| `float x_value` single use, then `filter_x = x_value; widget(right_panel.x, ...)` | 90.20% |
| **`float x_value` single use → `filter_x`, `widget(filter_x, ...)`** | **100%, byte-exact** |

## 2. Separator: a single-use float local, provided the half width is recomputed

**Window mechanics** (verified; `sched_trace.py` window 4 is the capped window):

- **Exact forms:** the capped window ends at node 81, which is the Y `fadd`. The Y FROUND opens window
  5, so the interface load is scheduled before `fstp Y`.
- **What that requires:** a FROUND right after the offset's `fild`, which is the sixth FROUND in the
  window. Any single-use float-class local initialised from the integer offset provides it:

  ```
  fild s2839; FROUND; fadd s10; FROUND; fstp s1447; fld s12; fadd s2775 | window 5: FROUND; fstp s1625; mov ecx <- s41 ...
  ```

  The canonical double and the plain float produce this same window listing. Only the temp's
  number differs (s2840 vs s2839).
- **Forms without that FROUND** fail at 99.95%: `position.x + (float)(128 - half)`,
  `position.x + (128 - half)` and an `int` local. The window ends at node 80, which is the Y FROUND,
  and `fstp Y` wins.
- **A float local for the X or Y sum** also fails at 99.95%. The inlined constructor parameter
  already puts a FROUND after the X `fadd`, so this local adds no node.
- **Member stores** (`separator.x = ...; separator.y = ...`) lose the constructor FROUNDs: 4 FROUND
  instead of 6, 99.80%.

**Why the float local failed before.** With `float center_offset = 128 - title_half_width;` the
separator window is correct, but the function drops to 87.68% (1990 instructions, prefix 466). The
difference is in the score-row loop: EBP/ESI/EBX are permuted, and the three `sprintf` argument arms
then tail-merge differently. The result is a 2×2 pattern:

| | `128 - title_half_width` (half width read twice) | `128 - title_width / 2` (half width read once or not at all) |
|---|---|---|
| `double` offset | **100%** (canonical) | 87.68% |
| `float` offset | 87.68% | **100%** |

- Adding 1, 2, 3, 8 or 9 dead named `int` locals next to the float local does not change the 87.68%.
  So the count of named user symbols is not the cause.
- The inference is that some quantity created before the loop, such as a compiler temp, an
  expression symbol or a propagation, feeds a register-allocation tie-break in the row loop. Both the
  extra double-to-float conversion and the second read of `title_half_width` change that quantity by
  one. This is not traced (see open questions).

## 3. Labels: why `memcpy`, and why struct or field copies do not work

Native code is `call game_is_full_version; mov edi, [right_panel.x]; test al, al`. The label X then
stays in EDI and is pushed twice. The listings show:

- **`memcpy(&label_x, &right_panel.x, 4)` in both branches** (canonical): `label_x` lives in EDI. The
  copy acts as a 4-byte integer copy, so the destination behaves as an integer register candidate.
- **A plain float assignment** (`label_x = right_panel.x;` in both branches) gives 82.89%, 2011
  instructions. The copy itself uses integer MOVs, but the float-typed `label_x` gets a stack home:
  `mov ecx,[right_panel.x]; mov [label_x],ecx` inside the branch, then `mov edx,[label_x]` at each use.
  This is the audit's 82.9%.
- **Assigning before the `if`** (plain or `const float`) gives 90.42%. `label_x` is stored before the
  call and reloaded into EDI after it.
- **A whole-struct copy `highscore_vec2_t label = right_panel;`** in both branches gives 86.83%, 2006
  instructions. This is the only plain form that puts X in EDI (`mov edi,[right_panel.x]` right after
  the call), but it also copies the unused Y (`mov ecx,[right_panel.y]; mov [label+4],ecx`). Those
  two extra instructions match optimizer.md's DCE rule that symbols which partly overlap their
  aggregate always count as live. Declared before the `if`, the struct copy gives 90.42%.
- **A field copy `label.x = right_panel.x`** is float-typed and gives 82.79%.

No plain spelling reproduces an integer-class copy of a float scalar without its aggregate partner.
The `memcpy` stays. The alternatives, a union or `*(int *)&` punning, are no plainer.

## 4. Splitter: move the cast into the loop and drop the guard

Native code is `test edi,edi; jle out; fld radius; call __ftol; ...; dec edi; jne loop`.

**Plain form.** `for (i = 0; i < count; i++) { ... distance = crt_rand() % (int)radius; ... }`, with
no guard and no `remaining` copy. Three steps produce the native code:

1. **Loop inversion.** Loop inversion 0x107447ad copies the header test to the entry as `0 < count`
   and creates the preheader.
2. **Hoisting the cast.** The loop-invariant float-to-int conversion `(int)radius` ends up in that
   preheader, after the entry test. In the iv_trace report, `cvt #167 <= radius` sits in preheader
   block 2 after `cleanup_preheader_after_sr`.
3. **The countdown.** `i` is used only by its exit test, so `convert_exit_test_to_countdown`
   0x107452db creates the counter `#143 = count` with `-1` and a `!= 0` test.

With the loop written this way, the guard is redundant.

**Why the guarded `for` re-tests.** Inversion always creates the entry copy of the loop test. The copy
is folded away only when a dominating compare on the **same ordered operand pair** is known. The
controls below show that the pair `(count, 0)` from `count > 0` does not fold the copy `0 < count`
(from `i < count` with `i = 0`). They also show that an implied relation on the same ordered pair does
fold: `count > 0` folds `count != 0`. A different constant does not fold: `count >= 1` does not
fold `count > 0`.

| Loop shape (cast hoisted by hand unless noted) | Entry copy | Result |
|---|---|---|
| `if (count > 0)` + `for (i = 0; i < count; i++)` | `0 < count` vs `count > 0` | re-test, 78.95% |
| `if (0 < count)` + `for (i = 0; i < count; i++)` | same pair | 100% |
| `if (count > 0)` + `for (i = 0; count > i; i++)` | same pair | 100% |
| `if (count > 0)` + `for (; count > 0; count--)` | same pair | 100% |
| `if (count > 0)` + `while (count > 0) {...; count--;}` | same pair | 100% |
| `if (count > 0)` + `for (i = count; i > 0; i--)` | same pair after copy propagation | 100% |
| `if (count > 0)` + `for (; count != 0; count--)` | implied NE, same pair | 100% |
| `if (0 < count)` + `for (i = 0; i != count; i++)` | implied NE, same pair | 100% |
| `if (count >= 1)` + `for (; count > 0; count--)` | different constant | re-test, 78.95% |
| `if (count > 0)` + `for (; count >= 1; count--)` | different constant | re-test, 78.95% |
| `if (count <= 0) return;` + `for (i = 0; i < count; i++)` | `(count, 0)` vs `(0, count)` | re-test, 78.95% |
| `if (count <= 0) return;` + `for (; count > 0; count--)` | same pair | 100% |
| `if (0 >= count) return;` + `for (i = 0; i < count; i++)` | same pair | 100% |
| `if (count > 0)` + `do {...} while (--count != 0)` (no `remaining`) | none | 89.33%. Same shape, but the count sits in EBX instead of EDI. |
| `if (count > 0)` + `do {...} while (++i < count)` | none | 68.83% (up-counter kept) |
| `while (count-- > 0)` / `while (count--)` inside the guard | none | 96.05% (`dec`/`inc` pair) |
| no guard, cast hoisted before the loop | none | 66.67% (`ftol` before the test) |
| **no guard, `(int)radius` inside the loop, `for (i = 0; i < count; i++)`** | preheader | **100%** |
| no guard, `(int)radius` inside, `for (; count > 0; count--)` | preheader | 100% |
| `if (count > 0)` + inline cast + `for (i = 0; i < count; i++)` | preheader | 100% |
| no guard, inline cast, `while (count-- > 0)` | none | 84.97% |

The type of `i` does not matter: `unsigned i` with the misordered guard still re-tests. The count is
an `int` parameter, and native uses signed `jle`.

**Where the fold happens (partly open).**

- optimizer.md places compare folding from available facts in phase-3 full-mode CSE
  (`evaluate_compare_from_available` 0x1070b9da). It also says that in full mode a call kills every
  available expression.
- One control adds a real call, `crt_rand();`, between the `0 < count` guard and the loop. The re-test
  still folds: 76 instructions, the extra call being the only addition. The misordered version
  re-tests: 78 instructions.
- So the fact survives a call. Either the fold is not the full-mode CSE path, or the kill rule does
  not apply to relational facts on a non-aliased parameter. This is recorded as an open question.

## Acceptance walkthrough

**Predictions written before the runs:**

| Prediction | Observed |
|---|---|
| Moving `(int)radius` into the loop lets loop-invariant hoisting place `ftol` in the inverted loop's preheader, so a plain `for` without a guard is exact | ✓ exact. iv_trace shows the cvt in preheader block 2 and a countdown counter from `count`. |
| Separator forms without a local (`(float)(128 - half)`, implicit, `int` local) keep the old 99.95% | ✓ all three give 99.95%, prefix 108 |
| `if (count >= 1)` / `count >= 1` loop test mismatched against `count > 0` → re-test | ✓ both 78.95% |
| Early return `if (count <= 0) return;` + up-counting `for` → re-test (order mismatch); `if (0 >= count) return;` → exact | ✓ both |
| Under the phase-3 CSE hypothesis, a call between guard and loop forces a re-test | ✗ no re-test. This falsifies the hypothesis, see above. |

**Predictions that failed, and hypotheses formed after the fact:**

- The operand-order hypothesis came from the first batch: `count > 0` + up-`for` re-tests, while
  `count > 0` + down-`for` is exact.
- I first predicted that `count != 0` after `count > 0` would re-test. It folds, so the rule was
  refined to "same ordered pair, implied relation".
- I predicted that a float local for the X sum might shift the window. It does not, because the
  constructor-parameter FROUND already exists (checked with `sched_trace`).
- The checkbox single-use-float fix was a tested idea, not a firm prediction. The FROUND
  explanation was then verified with `sched_trace`.

**Negative controls** are listed in the tables in §1-§4: every failing form with its score.

## Open questions

- **The row-loop tie-break.** Which quantity decides the score-row loop's register permutation that
  couples `float` vs `double` with the use count of `title_half_width`? Named dead locals do not
  affect it. A regalloc trace of the row loop, comparing `sep_float_local` with the canonical, would
  settle it.
- **The fold routine.** Which routine folds the loop-inversion entry test against a dominating
  compare, and why does the fact survive a call?
- **`memcpy` lowering.** The exact mechanism by which `memcpy` of a 4-byte scalar makes `label_x` an
  EDI candidate (address-taken status dropped, integer typing) is inferred from listings, not traced.

## Reproduce

The two exact sources are now the canonical scratches. The variant generators are not kept in the
repo; each control in the tables above is a one-line edit of the canonical source.

The trace commands:

```sh
uv run python scripts/c2/iv_trace.py <splitter-variant> --out <new-dir> --report
uv run python scripts/c2/sched_trace.py <highscore-variant> --out <new-dir>   # windows 4/5 and 142
```
