# Native beam direction and origin

Ion Rifle (21), Ion Minigun (22), Ion Cannon (23), and Fire Bullets (45)
draw their streak **from the stored origin toward the projectile head**.
The scratch previously used the opposite direction and anchored the streak at
the head. Both live and fading branches were wrong. Python and Zig already
use the native direction and origin, so this correction changes only the scratch.

Native loads the primary cursor as `projectile_pool + 0x14` at `0x00424184`.
Relative to this cursor, head X/Y are `-0xc/-8` and origin X/Y are `-4/0`.
The native subtraction pairs are:

| Branch | X: head minus origin | Y: head minus origin | Normalize call |
| --- | --- | --- | --- |
| Live | `0x424500 / 0x424503` | `0x424512 / 0x424515` | `0x42455d` |
| Fading | `0x424838 / 0x42483b` | `0x42484a / 0x42484d` | `0x424895` |

The streak's base uses origin X/Y in the camera additions at
`0x4245cb / 0x4245e2` and `0x4248f9 / 0x424910`. Head sprites continue to use
the projectile position. The verifier checks these native instructions and
the pool cursor address directly, with their bytes recorded in the receipt.

For the example head `(111.25, 208.5)` and origin `(50.125, 91.75)`, native
passes `(61.125, 116.75)` to normalization; the previous scratch passed
`(-61.125, -116.75)`. For Ion Rifle and camera `(13.125, -21.75)`, the first
streak quad starts near `(28.05, 34.8)` in native, versus `(89.175, 151.55)`
in the previous scratch. Its first alpha is zero; subsequent visible quads
follow the same reversed path in the defective source.

## Bounded verification

[`verify.py`](verify.py) uses the COFF relocation linker and machine runner in
the adjacent plasma evidence package. **480 fixtures** cover four beam types,
four lifetimes (0.4, 0.2, 1.2, -0.1), three transition alphas (0.2, 0.7, 1.5),
glow off/on, and five geometries: positive/negative short segments, horizontal
and oblique segments longer than 256 units, and zero length.

For every fixture, the complete ordered call trace and projectile storage
agree between native and corrected machine bodies. An independent oracle
checks the normalization input bits against head minus origin. Stack balance,
callee-saved registers, allowed execution addresses, and absence of non-stack
writes are checked. Three separately compiled defects restore the reversed
direction, the wrong anchor, or both; all **24** type/lifetime negative cases
are rejected. At initial retention, the combined defect recreated the preceding source
SHA-256 `9290f2f0e57a4cc24b1ff5acec6f34e35afa7ebc39203f56dd265a6853ba8cb6`.
The refreshed receipt restores those same direction/anchor defects in the
current source while preserving the subsequent ion-chain expression and laser fixes.
Its `previous` control label refers to these restored expressions; its
recorded source hash differs from that historical full source.

These are caller-boundary fixtures. Grim methods record calls; texture
selection is a no-op and the perk count is zero. Normalization records input
bits and uses one shared deterministic sqrt/divide model with float32 output;
the external D3DX DLL is not executed. Creature search records its arguments
and returns -1, so chain arcs are not covered. Other arithmetic executes as
native x87, including native `crt_ftol`. The fixtures have one primary
projectile, no players or secondary projectiles, fixed angle/speed/camera,
and x87 control word `0x037f`. They do not prove pixel equality, real-callee
side effects, all renderer paths, or universal equivalence.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/beam-direction-2026-09-10/verify.py \
  --out /private/tmp/crimson-beam-direction-proof
```

Unicorn requires local JIT permission. [`results.json`](results.json) pins the
source, verifier, shared engine, image, native body, compiled objects, build
key, relocations, fixtures, negative controls, and example call traces.

## Matching status

At initial retention, the beam correction left **57.104195%**,
**2891/3021 instructions**, and **444/0/14 references** unchanged. The subsequent
receipt followed the independent [ion-chain product correction](../ion-chain-product-2026-09-10/README.md),
which improved those figures to **57.427414%**, **2903/3021**, and **456/0/11**.
The current receipt includes the [laser owner/rounding recovery](../laser-owner-rounding-2026-09-10/README.md), reaching **59.622514%**, **2913/3021**, and **464/0/10**.
The direction/anchor controls remain metric-neutral within this current source. Both exactness flags remain false. Aggregate metrics alone do not
establish semantic equality, as these fixtures demonstrate.
