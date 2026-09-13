# Creature corpse vector boundaries

Both corpse-queue branches now construct a half-size vector before subtracting
it from the creature position. This restores the float store consumed by the
native X subtraction. The ping-pong branch also snapshots its heading before
the queue call, like the existing ordinary branch.

Native `0x004274ab..0x0042755e` calculates `size * 0.5`, stores the half-size
with `fst`, subtracts that rounded float from X, and subtracts the retained x87
value from Y. The stores are at `0x004274d1` and `0x00427529`. In the preceding
scalar expressions VC6 kept the half-size only on x87, including when the
source named it as a `float`. A vector constructor followed by vector subtraction
recovers the observed boundary in each arm. Using an already-computed scalar
half-size as both constructor arguments does not recover the second store.

The 48 new cases use tiny and subnormal sizes, both queue branches, two
positions, and x87 PC24/PC64. The old source fails 24 cases, repairing only the
ordinary branch leaves 12 failures, and repairing both branches leaves zero.
These sizes are diagnostic inputs; this is not a claim that ordinary gameplay
produces such creatures.

The final source also passes all 2,472 historical creature cases, with each
native observation checked against its existing receipt, 192 interaction-radius
boundary cases, and 12 transient target-player callback controls. Disabled
callback adapters agree with unadapted execution. Observations include state,
callback arguments, and ordered writes under the existing explicit callback
models. This is finite execution evidence, not whole-game equivalence.

The standard VC6.5 `/O2 /GB /W3 /GR-` build changes as follows:

| Metric | Before | Recovered |
| --- | ---: | ---: |
| Instructions, against 1,338 native | 1,300 | 1,303 |
| Fuzzy alignment | 57.316149% | 57.856872% |
| Exact prefix instructions | 0 | 10 |
| Frame, against native `0x7c` | `0x6c` | `0x7c` |
| Positional references: clean/unresolved/mismatched | 228/0/1 | 228/0/1 |

The frame size agrees, but several local positions and field-pointer lifetimes
still differ. Both exactness flags remain false. The native 5,330-byte extent,
compiler settings, reference aliases, and matcher rules are unchanged.

`before.cpp` and `recover.py` reconstruct all four stages. The final source
SHA-256 is `d7136f28e4aae58932dd6368b837d5769f2d13f1388faada97e571bc06b14d4f`.
Its encoded object body SHA-256 is
`a2e7176ed1768b37c7c81142fc624393c05c4df7cf6e8bfe3a8aeaeb7266e3aa`.

Reproduce from the repository root with native JIT permission:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-corpse-vectors-2026-09-13/verify.py \
  --out /private/tmp/creature-corpse-vector-proof
```

`results.json` records compiler, image, source, helper, and harness identities,
all observations and negative-control failures. No changes to the Python or
Zig runtime are included in this native-source recovery.
