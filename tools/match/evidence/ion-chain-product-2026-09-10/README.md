# Ion-chain product lifetime

The renderer now evaluates `arc * effect_scale * 10.0f` at each of the four
inner-strip corner expressions, rather than sharing a named `side` vector.
The shared vector introduced a float32 rounding boundary in X that native
keeps in an x87 register. The difference is visible in the arguments supplied
to Grim, even though it is only one float bit in the first reproducer.

For Ion Cannon, head `(111.25, 208.5)`, target `(125.5, 180.0)`, and camera
`(13.125, -21.75)`, the first inner corner's X coordinate is:

| Source | Float bits | Value |
| --- | --- | ---: |
| Native and recovered expression | `0x42ba23dd` | 93.0700454711914 |
| Previous shared vector | `0x42ba23de` | 93.07005310058594 |

Native `0x424c45..0x424c98` retains the X product on the x87 stack through
multiplication by 10 and subtraction from the start position. Its Y product
is stored and reloaded separately. The verifier checks the complete x87
instruction sequence in this window and the native 10.0 constant. A separate
arithmetic oracle reproduces both the correct and prematurely rounded X bits.
This is evidence about expression lifetime; it does not uniquely identify the
original C++ spelling.

## Verification

[`verify.py`](verify.py) compiles the actual source and links its COFF
relocations. It executes native and candidate renderer bodies with recording
Grim calls. Unlike the preceding empty-search beam fixtures, this package
executes the **real native `creature_find_in_radius`** body at
`0x4206a0..0x420725`, including its x87 distance calculation and both returns.

All **384 fixtures** agree on ordered call arguments, selected creature
indices, projectile storage, and creature storage. They cover:

- three target arrangements, including oblique, axis-aligned, and zero-length arcs;
- Ion Rifle, Minigun, Cannon, and Fire Bullets;
- lifetimes 0.4, 0.2, 1.2, and -0.1;
- Ion Gun Master absent/present, glow off/on, and transition alpha 0.2/0.7.

Seven populated creature records include index zero, eligible targets,
an inactive record, a low-lifecycle record, a distant record, and a target
reached by Minigun only with the perk. An independent distance/membership
check verifies the native search results and checks two arc quads per selected
target. The fixtures are away from search equality boundaries. Stack balance,
callee-saved registers, allowed instruction addresses, and absence of
non-stack writes remain checked.

Recompiling the preceding shared-vector source reproduces the one-bit failure;
a separate wrong-width control is also rejected. All **six compiled negative
cases** fail at arc quad arguments. The preceding source is pinned exactly by
SHA-256 `6c41659dc52bbbd401e5f09b0d88390f00a2d83262cd89ad345555b6a520d1a5`.

D3DX normalization remains a shared deterministic sqrt/divide model with
float32 output, not execution of the external DLL. Perk counts are explicit
0/1 stubs, texture selection is a recording no-op, and Grim methods are
recording thiscall stubs. Other arithmetic uses machine x87 and native
`crt_ftol` under control word `0x037f`. The fixture has one primary projectile,
no players or secondary projectiles, and fixed camera/angle/speed. This proves
the specified caller behavior, not pixel identity or all renderer paths.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/ion-chain-product-2026-09-10/verify.py \
  --out /private/tmp/crimson-ion-chain-proof
```

Unicorn requires local JIT permission. The [receipt](results.json) records
source, engine, verifier, native search/body, object, build, relocation,
fixture, reference-debt, and negative-control identities.

## Matching progress

The source change improves alignment from **57.104195% to 57.427414%**, moves
**2891 to 2903** candidate instructions toward **3021** native instructions,
and changes references from **444/0/14 to 456/0/11**. All 11 remaining
mismatches are reported. Both exactness flags remain false; this is a verified
partial, with no new whole-function matching credit or regression exception.

The beam, plasma-alpha, head-color, and static call-boundary receipts are
refreshed against this source. Three additional source controls were tested
for the concrete rounding failure: component assignment to the shared vector
is unchanged, scalar-side locals and compound strip updates still fail the
fixture and lower alignment. No such control is retained.
