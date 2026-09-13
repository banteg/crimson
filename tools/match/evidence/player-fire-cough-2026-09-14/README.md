# Fire Cough return consumer and position lifetimes

The retained `player_update` change restores four native data-flow details:

* Subtract Y before X when forming the initial spread vector, then store X/Y.
* Consume `vec2_sub`'s returned vector through `atan2f`, recovering the native
  X load, Y load, and `fxch` before `fpatan`.
* Form a separate projectile position in the `move_delta` homes, retaining the
  relative muzzle offset across `projectile_spawn`.
* Reuse those homes for smoke velocity, then translate the retained offset to
  form the smoke position.

**The function is not exact.** Both exactness flags remain false; no scope,
alias, compiler option, or target extent changes. This is not a newly
demonstrated gameplay bug: before and after both agree with native in the
bounded execution matrix.

## Native evidence and remaining differences

At `0x413aea..0x413afb`, native subtracts Y then X and stores X/Y at
entry-relative homes −16/−12. At `0x413b7f`, it calls `vec2_sub`, loads `[eax]`
followed by `[eax+4]`, exchanges them, and computes the angle. At
`0x413ba2..0x413bbd`, it constructs the projectile point at −16/−12. After the
projectile call it overwrites those homes with smoke velocity and translates
the retained relative offset for `fx_spawn_sprite`. The selected candidate
now shares that projectile/velocity home pair.

The SDK's `cl_crimsonroks/src/cltypes.h` implements `VEC2_Angle` through
`atan2f`. VC6's `math.h` supplies an inline float-parameter wrapper around
`atan2`. Earlier caller controls used `(float)atan2`; the new wrapper recovers
the returned-vector load order. This does not establish every original game
source declaration.

The candidate still delays `fpatan` until after position arithmetic. Native
computes and spills the angle first. Native also subtracts through the
reselected player's position; the retained source still uses the original
player-position pointer. Tested receiver rewrites introduce additional
positional reference mismatches and are not promoted. Other vector homes,
including the previous-position snapshot, still differ.

Changing Fire Cough also changes an x87 square/sum sequence in the nearest-
target loop, whose source expression is unchanged. This compiler side effect
is included in the full-function execution comparison, not presented as
another matching improvement. Naming or reusing the angle scalar does not
remove it or recover native's early angle spill.

| Native matcher measurement | Before | Retained |
| --- | ---: | ---: |
| Candidate instructions / native 4,206 | 4,060 | 4,068 |
| Prefix | 7 | 7 |
| References: clean / unresolved / mismatched | 805 / 0 / 2 | 805 / 0 / 2 |
| Instruction ratio | 64.04549% | 64.00774% |
| Normalized / encoded exact | false / false | false / false |

The small ratio reduction is explicit. The source is retained for the native
return consumer, position construction, and temporary reuse, not a higher
score. Eight extra candidate instructions are not eight newly exact instructions.

## Controls and execution proof

`controls.json` reconstructs the baseline at commit
`7811c5e2a64cd29545536f924ec2d2ad21c5167e` and 31 compiler controls. These isolate
float wrappers, separate positions, receiver ownership, nested vector arguments,
scalar reuse, value-return ABI forms, and the distance consumer. Each recipe
includes its actual config, including private ABI aliases. Only
`cough-expression-initial-False` is retained; its name means the selected-player
receiver rewrite is disabled. No control is a full match.

`verify.py` force-compiles and checks body hashes, counts, reference audits,
and exactness flags. It compares native, before, and retained machine code on
the existing 3,827-case matrix at gameplay x87 PC=24. Every ordered call and
final observed state must agree, including the native observation digest
recorded by the earlier point-frame proof. The matrix reaches 4,198/4,206
native instructions; the receipt lists the eight unvisited instructions.

Movement, heading, vector length/subtraction, and CRT conversion helpers run
as original machine code. Input, RNG, sound, effects, allocation, reload, and
damage callbacks are modeled. This covers those fixtures and call models,
not whole-game equivalence or hypothetical callback mutations. The compiler
layout probe checks the structures used by the runner.

Before and retained stack maps reach every instruction, have no conflicting
ESP depths at joins, and balance both returns. Annotated assembly and compiler
objects are emitted to the output directory.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/player-fire-cough-2026-09-14/verify.py \
  --out /tmp/player-fire-cough-proof --all-controls
```

Use a fresh output directory. Omit `--all-controls` to compile only before and
retained sources. `--controls-only` skips execution. Inputs and dependencies
are pinned; the verifier expects the canonical source at this recovery
revision, so use that checkout after later matching changes.
