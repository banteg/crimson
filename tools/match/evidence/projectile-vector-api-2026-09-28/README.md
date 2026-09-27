# projectile_render: exact through the vector API

The stock MSVC 6.5 build is now **byte-exact**, with all 3,021 instructions,
all 544 references, the 412-byte frame, and no padding matching native.
The source SHA-256 is
`0bdd68c99b01b8f49df47ed8629e5203f372b9b5a4cd50e918cdd765a27f5f26`.

This replaces the artificial ID-padding witness from
[the earlier investigation](../projectile-id-window-2026-09-28/README.md).
The final source contains ordinary vector operations; there are no dummy
stores, unused calls, inline assembly, compiler modifications, or byte patches.
This is a source reconstruction that reproduces the executable, not a claim
that the original author's exact C++ spelling has been recovered.

## Source changes

The vector exposes both named and indexed components through its union.
Scalar constructor and multiplication arguments use const references.
Compound assignments take vector operands by value, update the two fields,
then assign the updated object to a named return value. Their return type is
a value, including the scalar subtraction overload.

The muzzle-flash pass retains named camera components. Subsequent scalar
camera reads use the index operator, as do the primary pass's `base`
components. These access forms and value boundaries matter to C2's internal
symbol allocation even when their inline machine code disappears.
The independently verified
[plague parentheses](../projectile-plague-schedule-2026-09-28/README.md)
remain in place.

## Why the last two additions changed

The earlier trace established that C2 orders some commutative additions by
internal IDs modulo 2,048. Successive coherent API controls reduced the
remaining disagreement to the first two ion-arc x additions. The penultimate
source used reference operands for compound assignment. Its relevant IDs
straddled the wrong wrap boundary:

| Arc addition | Reference operand IDs | Value operand IDs |
|---|---|---|
| `point1 += direction * scale * 10.0f` | 4,074 and 4,089: both below 4,096 | 4,046 and 4,097: straddle 4,096 |
| `point2 += direction * scale * 10.0f` | 4,094 and 4,101: straddle 4,096 | 4,106 and 4,113: both above 4,096 |

With value operands, both pairs have native ordering. The first addition
retains native's `fld; fadd st(1); fstp; fstp st(0)` sequence, and the next
uses its direct memory `fadd`. The source also preserves the native load
schedule after the arc. The preserving exact-source trace reports C0
`0x1200`, 5,143 pool-E slots, 1,923 pool-B records and 173 tie pairs. These are
compiler observations; no observer or intervention is used for acceptance.

## Rebuilt source controls

[verify.py](verify.py) independently rebuilds the previous canonical source,
the final source, and seven controls with the normal compiler profile.
[results.json](results.json) retains identities, reference audits and frames.

| Source | Agreement | Prefix | Instructions | References ok/unresolved/mismatch |
|---|---:|---:|---:|---|
| Previous canonical, `08bfc728d` | 97.8463% | 1,322 | 3,015 | 544/0/0 |
| Final | **100%** | **3,021** | **3,021** | **544/0/0** |
| Compound operand by reference | 99.8676% | 2,021 | 3,021 | 544/0/0 |
| Return `*this` directly | 98.2450% | 1,322 | 3,019 | 544/0/0 |
| Scalar constructor by value | 68.4593% | 0 | 3,041 | 518/0/2 |
| Scalar multiplier by value | 98.0795% | 1,322 | 3,019 | 544/0/0 |
| Direct camera fields throughout | 97.9125% | 129 | 3,015 | 543/0/0 |
| Direct primary `base` fields | 98.1457% | 1,322 | 3,019 | 544/0/0 |
| Indexed muzzle camera fields too | 99.7021% | 110 | 3,021 | 537/0/0 |

All controls reject whole-body exactness. Their individual effects are not
additive; small source changes can cross an allocation boundary elsewhere.

## Native execution

All **13,046** pinned native/candidate fixture cases pass with Unicorn 2.1.4:

- [Historic rendering](historic.json): 2,696, covering plasma, beams, ion
  chains, laser ownership and secondary projectiles. Its wrong-alpha control
  changes the two expected color calls and is rejected.
- [Position boundaries](positions.json): 656 plus 12 callback mutations.
- [Ion endpoint rounding](ion.json): 524.
- [Conventional corner rounding](conventional.json): 4,118.
- [Laser trig rounding](laser.json): 5,040.

These suites check modeled external calls, state and pinned trace identities.
They are finite CPU execution evidence, not GPU rendering tests. Whole-body
exactness is established separately by the normal relocation-aware matcher.

## Reproduce

From the repository root, choose fresh output directories:

```sh
uv run crimson match scratch tools/match/scratches/projectile_render
uv run python tools/match/evidence/projectile-vector-api-2026-09-28/verify.py \
  --out /tmp/projectile-vector-controls
uv run python scripts/c2/id_delta_profile.py tools/match/scratches/projectile_render \
  --out /tmp/projectile-vector-ids
```

For `historic`, `positions` and `ion`, repeat with the corresponding suite:

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/remaining-storage-controls-2026-09-26/verify_execution.py \
  --source tools/match/scratches/projectile_render/scratch.cpp \
  --suite historic --out /tmp/projectile-vector-historic
```

For `conventional` and `laser`, use
`tools/match/evidence/renderer-house-style-2026-09-13/replay.py` with the same
arguments. macOS must permit Unicorn's JIT for the execution suites.
