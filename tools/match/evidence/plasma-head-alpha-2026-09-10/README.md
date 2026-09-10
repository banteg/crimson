# Native small-plasma head alpha

The live Plasma Minigun, Spider Plasma, and Shrinkifier heads use **half the
transition alpha**. The scratch and both ports previously used 0.45. Plasma
Rifle and Plasma Cannon still use 0.45.

Native `0x00422c96..0x00422cab` multiplies the transition argument by the
float constant 0.5 and stores the result at `[esp+0x20]`. The three small-head
color calls reload that storage:

| Type | Native color call | Head size | Alpha multiplier |
| --- | --- | ---: | ---: |
| Plasma Minigun (11) | `0x00423ac8` | 16 | 0.5 |
| Spider Plasma (26) | `0x00423e37` | 16 | 0.5 |
| Shrinkifier (24) | `0x00423fc1` | 16 | 0.5 |

At transition alpha 0.7, native publishes float bits `0x3eb33333` (about 0.35),
whereas the previous source publishes `0x3ea147ae` (about 0.315). The Python draw
boundary consequently packs alpha 89 rather than 80. The focused renderer
regression failed for all three small-head types before the fix and passed
for Rifle/Cannon controls; all five pass after the correction. Python's and
Zig's shared small-plasma configuration now use 0.5.

## Bounded machine verification

[`verify.py`](verify.py) compiles and links the real COFF relocations, maps the
native image, and executes both entire renderer bodies in Unicorn 2.1.4. It
records each Grim call's receiver and initialized argument words, and compares
call order, argument bits, and final projectile storage. It rejects unexpected
code execution or non-stack writes in these plasma cases and checks stack
balance and callee-saved registers. Trigonometry and square roots execute as
machine x87 instructions; signed float conversion executes native `crt_ftol`.

The **200 fixtures** cover all five plasma types, lifetimes 0.4/0.2/1.2/-0.1,
transition alphas 0/0.2/0.7/1/1.5, and glow disabled/enabled. All native and
corrected-candidate call traces agree. The live head alpha is also checked
against an independent float-bit oracle. Recompiling the previous wrong
literals produces a single wrong color argument for each affected type; all
three negative controls are rejected. The full source, image, object, body,
build, relocation, fixture, and reference-debt identities are in
[`results.json`](results.json).

These fixtures contain one primary projectile, no players or secondary
projectiles, fixed geometry/speed, and x87 control word `0x037f`. Grim methods
are recording thiscall stubs, texture selection is a recording no-op, and the
perk query returns zero. Uninitialized padding in `grim_config_value_t` is
excluded; its id and initialized value word are compared. This proves the
stated caller-boundary behavior for these fixtures, not pixel equality, all
renderer paths, real-callee side effects, or universal semantic equivalence.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/plasma-head-alpha-2026-09-10/verify.py \
  --out /private/tmp/crimson-plasma-head-proof
```

Unicorn requires local JIT permission.

## Matching debt

At initial retention, the native-correct literal change lowered the normalized score from
**58.200879% to 57.104195%**, changes **2893 to 2891** candidate instructions
against **3021**, and changes aligned references from **452/0/12 to 444/0/14**.
The two additional reported pairings are native camera Y versus candidate
camera X at `0x00422e22`, and native Sharpshooter perk id versus candidate Grim
receiver at `0x00422e90`. They remain reported; no alias or exactness rule is
changed. All previous mismatch addresses remain present.

Six shared-local controls (value, const value, and const reference, before or
after the opening UV call) do not improve the corrected literal source. No
extra local or compiler control is retained. Both exactness flags remain false
and no new whole-function match is claimed.

The checkpoint initially rejects the 12-to-14 mismatch increase. The
[regression exception](../../regression-waivers.json) is pinned to base
`0acb990a825ca35b5c70feb8c8dedd1c2cf224e8` and this native alpha correction.
It permits retaining verified behavior while preserving the reported debt;
it does not grant matching credit.

The current receipt is refreshed after the independent
[beam direction/origin correction](../beam-direction-2026-09-10/README.md).
The wrong-alpha control restores only the three defective alpha literals in
that current source; its source hash therefore differs from the historical
pre-alpha-fix source. The shared runner also exposes optional beam stubs and
geometry inputs, which the plasma fixtures do not enable.

The receipt is also refreshed after the [ion-chain product correction](../ion-chain-product-2026-09-10/README.md). At that retention, renderer metrics were 57.427414%, 2903/3021 instructions, and 456/0/11 references; the preceding matching-debt discussion records the historical alpha correction. The plasma fixtures keep native creature search disabled and the perk stub at zero.

The current receipt includes the [laser owner/rounding recovery](../laser-owner-rounding-2026-09-10/README.md): 59.622514%, 2913/3021 instructions, and 464/0/10 references. Its wrong-alpha source retains the other corrections. The shared runner now accepts explicit player records; these plasma fixtures retain zero players.
