# Native overlay tint and trail rounding

The recovered auto-target trail now rounds both displacement components to
float32 before computing its length, as native does. Previously the Y store
left the unrounded subtraction in an x87 register for the first multiply.
At distances near multiples of eight, a one-bit difference in the stored
length made the loop draw one extra or missing 32-by-32 segment.

Moving the normalization-vector copy before the length calculation recovers
the native rounding boundary. Nine pinned cases at nominal distances
8/16/24/32/40/48/56/64/72 now produce native segment counts
**2/3/3/5/5/6/7/9/9**, versus **1/2/4/4/6/7/8/8/10** in the preceding source.
For the first case, native length bits are `0x41000001`; the preceding source
produces `0x41000000`. Native stores the computed length at `0x42945f` before
calling normalization at `0x429463`.

The alive-player tint also owns a byte copy of its alpha parameter. This
reproduces the complete **40-byte instruction window** at
`0x428c66..0x428c8e` (exclusive), including alpha's integer-register copy and
the white-color call. The verifier compares that window against the linked
candidate bytes after COFF relocations. Replacing the byte copy with ordinary
float assignment removes the window but preserves all nine tested boundary
call traces. This is local instruction recovery, not a newly demonstrated
color-behavior fix or a unique identification of the original C++ source.

## Replayable evidence

[`verify.py`](verify.py) compiles the current scratch and three independent
controls: previous distance order, ordinary tint assignment, and the exact
[`preceding source`](previous-source.cpp). Its SHA-256 is
`a50f2d9af1995c22fdc442ffb9411364a99590927aa408cbe8a02b4292ba1339`.
[`runner.py`](runner.py) links the COFF object using the shared
[machine loader](../plasma-head-alpha-2026-09-10/verify.py), then runs native
and candidate x86 instructions.

All **239 fixtures** agree on complete ordered caller argument bits, allowed
global writes, normalization inputs, stored distance bits, and player/creature
storage. They cover:

- nine pinned segment boundaries, three alphas, and three player layouts;
- seven axis distances including zero and the 80-unit gate;
- disabled perk, suppression, nonpositive alpha, and three trail thresholds;
- 144 body cases spanning one/two players, either overlay player, alive/dead,
  two muzzle-flash values, two headings, two shield values, and three alphas.

An independent arithmetic oracle checks the pinned rounded distances and
segment counts. Both the distance control and preceding source fail all nine
boundary cases, yielding **18 rejected runtime controls**. The tint control
fails the encoded-window check while its tested call traces remain equal.
The other player is inactive for the two-player boundary cases; general body
cases populate both records.

Grim calls use recording thiscall stubs; texture selection is a no-op and
perk queries have explicit fixture results. `D3DXVec2Normalize` uses a shared
sqrt/divide float32 model; the external DLL is not executed. Native x87 and
`crt_ftol` execute under control word `0x037f`. Stack balance, callee-saved
registers, allowed code, restricted global writes, and unchanged input player
and creature bytes are checked. UV tables come from the pinned image snapshot.
This is bounded caller evidence, not graphics-backend, pixel, or universal
function equivalence. The Python and Zig ports are unchanged.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/overlay-tint-trail-2026-09-11/verify.py \
  --out /private/tmp/crimson-overlay-proof
```

Unicorn requires local JIT permission. [`results.json`](results.json) pins
source, verifier, runner, shared loader, image, native body, object, relocation,
build, fixture, counterfactual, and matching identities. The four existing
projectile packages are replayed after generalizing the shared loader; all
**1,502** of their fixtures continue to agree.

## Matching progress

Normalized alignment improves from **91.186736% to 93.031359%** and candidate
instructions increase from **1,144 to 1,148**, equal to the native count.
All **331** positional references remain clean, and prefix remains 9.
Both whole-function exactness flags remain false. This partial recovery
grants **zero new whole-function matches** and changes no matching rule,
reference alias, or regression waiver.
