# Codeless tuples and parenthesis rounds (C2.DLL 8966)

This note covers the scheduler nodes that emit no instruction. In practice that means the FROUND pseudo
op (IL 0x162). The main finding is a FROUND source that the other notes miss: **the front end emits a
0x162 for every parenthesized float or double expression that is not a leaf**. The cast does not
produce it. Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000). "Verified"
means a preserving trace (`scripts/c2/sched_trace.py`, `scripts/c2/il_stage_trace.py`) of real
compiles. "Read" means Binary Ninja only.

Short version:

1. `(a + b) * c` puts a FROUND between the `fadd` and the `fmul`. So do `x = (a + b);`, `(d * 2.0)`,
   `(float)(a + b)` and `(t = a + b) * c`. Each pair of parentheses around a non-leaf float or double
   expression adds one: `((a + b))` gives two FROUNDs. `(s->a)`, a leaf, gives none. Integer
   expressions give none. [verified]
2. The cast itself adds nothing. `float(a + b)` and `static_cast<float>(a + b)` give no FROUND, and
   `(float)(a + b)` gives exactly one, the same as `(a + b)`. This also holds for a real double→float
   narrowing: `static_cast<float>(d * 2.0)` gives none. [verified] This corrects
   [x87-scheduling.md](x87-scheduling.md) §3 and [weapon-arm-schedule.md](weapon-arm-schedule.md) §3.
   Their `(float)(expr)` FROUNDs come from the parentheses.
3. C2 factors `a*c + b*c` into `(a + b)*c` before globopt, and `x*4 + 4` into `(x + 1)*4`. The
   factored sum carries **no** FROUND. So `speed * 4.0f + 4.0f` compiles to the same bytes as
   `(speed + 1.0f) * 4.0f`, `fld; fadd [1.0]; fmul [4.0]`, but without the scheduler node. [verified]
4. The FROUND is the only codeless tuple that reaches the scheduler in normal code. In 47,756 window
   tuples across every saved trace (player_update, projectile_render, highscore, ui_element_render and
   one Snail Mail function), the only IL pseudo ops were 0x162, labels 0x1ae (which end a
   window) and 0x1b5 (which stops a window before itself). REGUSE 0x19e, MOVE 0x1ad, 0x1b2, 0x145 and
   0x190 never appeared. The other codeless nodes are machine tuples that post-schedule passes delete
   ([x87-scheduling.md](x87-scheduling.md) §2). [verified for this corpus]

## 1. Where the round comes from

`il_stage_trace.py` with the `globopt` preset shows the `round` tuple at `globopt_run` entry
(0x107581ee). The tuple sits directly after the arithmetic tuple that produces the parenthesized value:

```
+  ty4004 #325 <= [speed] 1.0f
round ty4004 #326 <= #325          <- the parentheses
*  ty4004 #327 <= #326 4.0f
=  [sprite+0x88] <= #327
```

- The tuple is present before forward propagation. It appears whether or not a type changes, so it
  does not come from `convert_operand` 0x10710180, which inserts 0x15f/0x162 only for a type change.
  Inference: the front end (C1XX, since these are `.cpp` scratches) emits it for its
  parenthesized-expression node. The C1XX code was not located. Plain C (C1.DLL) was not tested.
- Once emitted, the marker survives to the scheduler unchanged. `sched_all` on the probes below shows
  one FROUND per paren level in the scheduled window.
- `decide_tree_substitution` 0x1070bd4e treats 0x162 as a tuple that must stay materialized, so later
  tree passes do not fold it away (read).

**Factoring** (verified with a hook on the return of `factor_out_common_operand` 0x1070f0c7 at call
site 0x1070d4ca). The call chain is `optimize_expression_trees` 0x1070fc45 (mode 1, called at
0x107581a4, before globopt) → `simplify_expression_tree` 0x1070bf4c → `simplify_tree_bottom_up`
0x1070c2d5 → `factor_common_terms` 0x1070d47f → `factor_out_common_operand(tree, 0x16f, 0x161)`. It
returned 1 only for `s->c = s->a * 4.0f + 4.0f` and returned 0 for `(s->a + 1.0f) * 4.0f` and
`(float)(s->a * 2.0f)`. It fires again inside globopt, where the tree is already factored. A bare
constant term is treated as `1 * c`, so `x*4 + 4`, `4*x + 4`, `x*4 + 1*4` and `x/0.25 + 4` all become
`(x + 1)*4`. `x*4 + 1` stays `fmul; fadd`.

## 2. Probe results (micro functions, /O2 /G5)

FROUND counts are nodes in the scheduled window (`sched_trace.py`). The micro functions were
compiled appended to a Snail Mail scratch; they use only a local `MicroS` struct.

| Source | FROUNDs | Code |
|---|---|---|
| `s->c = (s->a + 1.0f) * 4.0f;` | 1 | fld; fadd; fmul; fstp |
| `s->c = s->a * 4.0f + 4.0f;` / `4.0f * s->a + 4.0f` / `s->a * 4.0f + 1.0f * 4.0f` | 0 | same as above (factored) |
| `s->c = float(s->a + 1.0f) * 4.0f;` / `static_cast<float>(…) * 4.0f` | 0 | same |
| `s->c = (float)(s->a + 1.0f) * 4.0f;` | 1 | same |
| `s->c = ((s->a + 1.0f)) * 4.0f;` | 2 | same |
| `s->c = (s->a + 1.0f);` (redundant top-level parens) | 1 | fld; fadd; FROUND; fstp |
| `s->c = s->a + 1.0f;` | 0 | fld; fadd; fstp |
| `s->c = (s->a) * 4.0f;` / `((s->a)) * 4.0f` (leaf) | 0 | |
| `s->c = s->b + (s->a + 1.0f);` | 1 | |
| `s->c = (s->a * s->b) + (s->d * 4.0f);` | 2 | |
| `(s->a + 1.0f) * (s->b + 2.0f)` | 2 | |
| `s->c = (s->a + s->b) * s->d;`, `s->d * (s->a + s->b)`, `(s->a - 1)/4`, `(s->a*2)*4`, `-(s->a+1)*4`, `((float)s->i - 1)*4` | 1 each | |
| `s->a * s->d + s->b * s->d` | 0 | factored to `(a+b)*d` |
| `s->e = (s->e + 1.0) * 4.0;` (double) | 1 | |
| `s->c = (float)(s->e * 2.0);` / `s->c = (s->e * 2.0);` | 1 | |
| `s->c = static_cast<float>(s->e * 2.0);` / `s->c = s->e * 2.0;` | 0 | |
| `s->c = (float)((s->a + s->b));` | 2 | |
| `if ((s->a + 1.0f) > s->b)` | 1 | before the fcomp |
| `s->c = (0, s->a + 1.0f) * 4.0f;` | 1 | |
| `float t; s->c = (t = s->a + 1.0f) * 4.0f;` | 2 | paren plus forward propagation of t |
| `s->i = (s->i + 1) * 4;`, `(int)(s->i + 1)` | 0 | |
| inline setter with an `int` param: `seti(s, s->i + 1)` | 0 | |
| inline setter with a `float` param: `setf(s, s->a + 1.0f)` | 1 | forward propagation ([x87-scheduling.md](x87-scheduling.md) §3) |
| local pointer copy `MicroS* t = s;`, reference `float& r = s->c;`, struct copy `MicroS t = *s;` | 0 | no pseudo tuple; the struct copy is `rep movs` plus `_epush/_epop`, which emit push/pop |

## 3. Codeless tuples at scheduling time

| Candidate | Reaches the scheduler? | Counts toward 81? | Can change code? |
|---|---|---|---|
| FROUND 0x162 from parentheses (§1) | yes | yes | yes. It takes an issue cycle and is ready 3 cycles after an fadd/fmul. Between a producer and an `fstp` it removes the +1 store latency ([x87-scheduling.md](x87-scheduling.md) §4) |
| FROUND from forward propagation or float inline params | yes | yes | same |
| C-style cast `(float)` on a float expression | only through its parentheses | – | – |
| Machine tuples that `post_schedule_merge_moves` / `late_stack_temp_forwarding` delete | yes | yes | they occupy DAG slots and cycles |
| 0x1b5 epilogue marker | stops the window before itself; skipped for counting at a window start | no | – |
| Labels 0x1ae, dead-label marks 0x1bc | 0x1ae ends the window | it is the last node | – |
| REGUSE 0x19e, MOVE 0x1ad, set marker 0x1b2, NOP 0x145, 0x1b4/0x1b6/0x1b7, intrinsic 0x190 | not observed in 47,756 window tuples | – | – |
| Named locals, pointer copies, references, int inline params, struct copies | no pseudo tuple survives | – | only through register/slot changes |

A window cut can be moved by one node without changing any instruction. Add or remove one pair of
parentheses around a non-leaf float subexpression. Removing a pair is only safe where C2 does not need
it for precedence; otherwise use `float(…)` / `static_cast<float>(…)` or the factored spelling. Check
the new FROUND's own cycle: it can still reorder its own window (§4).

## 4. Using it on a residual

A paren FROUND between an `fadd` and an `fmul` delays the `fmul` by one issue cycle, so a ready load
with a lower priority than the `fmul` but a higher one than the FROUND can issue first. Dropping the
parentheses (the factored spelling `x * 4.0f + 4.0f`, or `float(…)`) removes the FROUND without
changing the arithmetic, and the `fmul` wins again. (Verified byte-exact on Snail Mail's
initialize_star_field, where native's other parenthesized lanes keep their FROUNDs.)

## Tools

```sh
uv run python scripts/c2/il_stage_trace.py <scratch> --out <dir> --lines 73-73   # 'round' at glob entry
uv run python scripts/c2/sched_trace.py <scratch> --out <dir> --lines 71-79      # window nodes, FROUND cycles
```

## Open questions

- Where C1XX emits the paren round. It is not located, and C1 (plain C) was not tested.
- EH state tuples (/GX with destructors) were not probed. /O2 without /GX emitted no EH pseudo tuples
  for a local with a destructor.

## Corrections to other notes

- [x87-scheduling.md](x87-scheduling.md) §3, "C1 explicit casts": the 0x162 comes from the
  parenthesized operand, not from the cast. `static_cast<float>(d * 2.0)` gives none, and `(d * 2.0)`
  alone gives one. Add a table row: "parenthesized non-leaf float/double expression, e.g.
  `(a + b) * c` or `x = (a + b)`: yes, one per paren level".
- [weapon-arm-schedule.md](weapon-arm-schedule.md) §3: the source rule `(float)(float_expr)` works
  because of the parentheses. `(random_offset.y * 15.0f)` without the cast gives the same FROUND.
