# Retained renderer position boundaries

The Fire overlay arithmetic can now be retained together with better whole-body
alignment. The decisive interaction is to use complete vector expressions in
Fire, all three conventional billboards, and all three secondary rocket bodies.
The billboard type is also reloaded after the rotation callback, as native does.

The baseline is `fef3cd3bc4dfb17a5a9262539e84718e06bc8725`. Its source is pinned
in [the preceding proof's before.cpp](../fire-overlay-lifetimes-2026-09-13/before.cpp),
SHA-256 `48ff88ff9f9e78427d1e6b28af863bedbc983c6ccf1d4c8fe9c9563b7fce3750`.
The retained formatted source is
`a51887e6e550d8b414d5f109e6e046cc7f25b86f024a10eedf4f87a899adcc31`.

## Native source constraints

Fire at `0x4253eb..0x425441` adds camera X and projectile X, adds Y, stores
the Y sum, subtracts 32 from the still-wide X sum, stores final X, then reloads
and subtracts from Y. The complete expression reproduces this boundary:

```cpp
projectile_render_vec2_t draw_pos =
    camera_offset
    + *(projectile_render_vec2_t *)&projectile->position
    - 32.0f;
```

The native pistol, type-4 and fallback billboard paths use the same order with
half-sizes 3, 4 and 2. Their arithmetic begins at `0x425537`, `0x42558a` and
`0x4255eb`; the shared draw returns at `0x42563b`. Selecting this callsite is
necessary because the splitter also submits an earlier 20px quad.

At `0x42552f`, immediately after rotation returns, native reloads the type from
the current record before choosing billboard size. The retained source makes
this reload explicit. Twelve synthetic callback controls temporarily change
type during rotation and restore it after the billboard draw. The retained
source follows native in every case; a freshly compiled source with only the
reload removed fails all twelve. This proves an external-call dependency;
it does not assert that real Grim mutates projectile type.

The three secondary-body paths at `0x42588c`, `0x425906` and `0x42598f` also
store Y-sum and final-Y in separate temporary homes. Completing their vector
expressions preserves this distinction. Position calculation stays before the
color callback, as in native. Fire's separate type gate still uses slot 95,
including when that slot is inactive; the remaining overlay fields use the
current record.

## Matching interaction

| Source | Alignment | Instructions | Clean/unresolved/mismatched refs |
| --- | ---: | ---: | ---: |
| Baseline | 60.726846% | 2,950/3,021 | 479/0/8 |
| Fire expression alone | 53.589958% | 2,954/3,021 | 419/0/10 |
| Fire plus three billboards | 61.160341% | 2,960/3,021 | 488/0/7 |
| Plus post-rotation type reload | 61.651622% | 2,961/3,021 | 488/0/7 |
| Plus three secondary body expressions, retained | 62.934492% | 2,963/3,021 | 487/0/6 |

The retained change gains 277.081594 fuzzy-weighted bytes. Frame allocation
remains 388 against native's 412 bytes, and prefix remains zero. Both normalized
and encoded-body exactness remain false. Positional reference improvements do
not establish eight independently fixed runtime accesses.

Completing only the rocket body after the type reload pairs five more references
cleanly than completing all three bodies, but has lower whole-body alignment
(62.767380%). Both have six mismatched references. The retained form consistently
recovers native's separate Y temporaries across these three branches; the
alternative remains inspectable. Aliases, compiler flags, native extent and
exactness rules are unchanged.

## Bounded experiments and validation

`source-controls.json` contains checked patches for 83 experiments and the
formatted retained source: 84 compilations, with 78 distinct source hashes.
`controls-results.json` records fresh native runs on the 26 combined Fire
rounding witnesses for each control. The groups are:

- `boundaries`: all 16 combinations of Fire and three secondary body boundaries.
- `shared`: 16 combinations of proposed shared position objects. Native stack
  home reuse motivated these controls but did not establish source-local identity.
- `owner`: 12 retained projectile/tail/copy-owner forms with two scopes and
  scalar or complete Fire expressions. These remain regressive.
- `call-temporary`: ten direct-call, helper, copy and naming forms. Nine recover
  the Fire witnesses but do not recover overall allocation.
- `billboards`: all 16 Fire/pistol/type-4/fallback expression combinations.
- `reload`: five ways to make the post-rotation type access explicit.
- `final-secondary/boundaries`: eight secondary-body combinations after the
  complete Fire/billboard expressions and type reload. The first bit is fixed
  to zero because the Fire expression is already present.
- `retained`: the formatted source used for promotion and full replay.

`fixtures.jsonl` pins 656 native cases: the prior 608 Fire and mixed-pool cases
plus 48 billboard cases (eight Y-rounding witnesses per branch at both PC24 and
PC64). The independent oracle checks submitted coordinate and size words. The
retained source passes every ordered call trace and pool/write check. The old
source fails 22 Fire and 24 billboard cases, all at PC64. All PC24 cases agree.

`results.json` records those cases and the twelve callback controls, including
the separately compiled no-reload negative control. `replays.json` contains
fresh receipts for all 11,854 historical renderer cases, without the redundant
full CFG payload. The historical wrong-ion-width control is still rejected.
Receipts pin source, object, encoded body, native image and verifier hashes.

The existing executor enforces stack balance, saved registers, allowed code,
x87 state and non-stack writes. External functions remain modeled. These finite
caller tests do not establish arbitrary-input, GPU or complete renderer parity.

## Reproduce

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/renderer-position-boundaries-2026-09-13/verify_controls.py \
  --out /private/tmp/renderer-position-controls

uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/renderer-position-boundaries-2026-09-13/verify.py \
  --source /private/tmp/renderer-position-controls/retained/scratch.cpp \
  --out /private/tmp/renderer-position-proof

for suite in historic conventional laser; do
  uv run --no-sync --with unicorn==2.1.4 python \
    tools/match/evidence/renderer-house-style-2026-09-13/replay.py \
    --source /private/tmp/renderer-position-controls/retained/scratch.cpp \
    --suite "$suite" --out "/private/tmp/renderer-position-$suite"
done
```
