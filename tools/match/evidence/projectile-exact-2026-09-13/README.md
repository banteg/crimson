# Exact projectile update recovery

`projectile_update` matches all **2,203 instructions, 8,409 encoded body bytes,
and 507 positional references** at `0x420b90..0x422c69`. The native matcher reports
both normalized and encoded-body exactness, zero reference problems, and zero
padding on both sides. This adds one port-scope function match.

The final continuation starts from the [frozen ownership candidate](../projectile-ownership-and-stack-2026-09-13/README.md),
source `f46d40ef618dd67ddc365fc30fa4280966dcb4eec7f248fc165e9b15e138e078`.
The canonical source is now
`93a13039d7b7e15e735a4abea1afcd349d8f2d72be5c283eb2b9f5d953d281e7`,
with extracted object-body SHA-256
`9a35722b3dc5b0841d08d01173fed5a417cb71f5649597bfea766a20dc7870b5`.
The unchanged native matcher resolves relocations before comparing encoded bytes;
the object-body hash is not a claim that raw object relocations equal PE addresses.

## Residual causes

- The secondary indexed loop needs separate position ownership for explosion
  arithmetic and the later movement/impact path. The explosion X difference uses
  a position reference, while Y remains a record-field read. This recovers the
  native Y cursor, X-position pointer, retained differences, and loop endpoint.
  Its allocation effects also recover the particle call registers and first tint
  clamp's constant schedule.
- The three secondary decal angles and burst angle share one float. The primary
  and particle passes share their index; the two primary impact branches share
  their X and Y offset floats. Every use follows assignment. Together these
  lifetimes recover all **388 stack accesses**, including anonymous spills, and
  the native `0xf4` allocation. No storage is added to force an offset.
- The burst constructs its direction and keeps a separate X-product local before
  assembling the plain result vector. The compiler duplicates the live magnitude
  for X, then retains it for Y, removing the extra x87 exchange.
- `atan2f` uses the pinned SDK's inline float wrapper. It recovers the last seeker
  address/angle instruction order without changing the helper's return type.

`positions.py` checks every paired instruction, all 206 branch destinations,
and all 507 reference positions. It records explicit residuals for selected
intermediate sources rather than treating reordered operations or displaced
stack homes as exact. The final source has no exclusions or stack differences;
encoded identity is separately required by the native matcher.

The experiment graph retains 57 compiling variants and a 17-step path including
final formatting. Two variants are exact: the recovered source and its formatted
canonical form. All 58 graph builds, including the predecessor, are checked
against source and body hashes. A changed burst angle must fail both exactness
gates; altered branches, reference owners and stack locations must fail the
positional certificate. Controls include a shared burst counter that produces the right frame size
but the wrong native homes, and broader owners that repair one region while
breaking another. These are bounded source experiments, not an exhaustive set of
possible original spellings.

## Native replay

`replay.py` compares the predecessor and exact source against the same 12,402
cases from the preceding packages: particle trajectories (4,817), particle
impacts (1,230), integrated particle helpers (663), bubble expiry (224), primary
movement (1,000), primary impacts (1,000), primary weapons (576), rocket/minigun
impacts (300), explosion thresholds (192), steering (1,200), and trails (1,200).
All 12,402 cases have zero differences for both candidates. The receipt records
pool/scalar state, calls, ordered writes and RNG comparisons.

The original caller and selected native helpers execute. FX/audio/damage/spawn
boundaries are recorded as documented by the earlier packages. Expanded suites
use the same deterministic external D3DX normalization model on both sides;
they do not execute that DLL. These fixtures do not establish arbitrary-input,
whole-game or rendered-pixel equivalence. Full function identity comes from the
independent encoded-body and positional-reference proof.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/projectile-exact-2026-09-13/verify.py \
  --out /private/tmp/projectile-exact-proof

UV_CACHE_DIR=/private/tmp/crimson-uv-cache \
  uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/projectile-exact-2026-09-13/replay.py \
  --suite explosion --out /private/tmp/projectile-exact-explosion
```

Each verifier writes a hash-bound `results.json`. `proof-receipt.json` retains
the full source-graph and exactness proof; `native-receipts.json` retains compact
execution receipts with row digests. Canonical compiler flags, reference aliases,
image extent and matching rules are unchanged. No compiler state, instruction
bytes, padding, or register assignments are patched.
