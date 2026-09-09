# Creature pool sentinel storage

The original constructor at `0x0041e6d0` initializes **385** records of `0x98`
bytes. The matching header and data object previously declared only 384.
The corrected storage covers `0x0049bf38..0x004aa3d0` (end exclusive), including
the sentinel at `0x004aa338`. Gameplay scans continue to use 384 active slots.

[verify.py](verify.py) interprets the original constructor's small integer
instruction sequence, following its actual branch until return. Unsupported
instructions or addressing modes fail. It observes the same ten stores for
each of 385 records, including the last record's animation field at offset
`0x94`; that four-byte store ends at `0x004aa3d0`. This establishes the required
storage from actual writes, rather than merely assuming that a loop counter
is an allocation size.

All 58,520 mapped image bytes initially contain zero. The added 152 bytes contain
no separately named data-map object; the next known object is the unused vector
at `0x004aa4d0`. The data definition therefore includes the complete sentinel,
with its zero initializer, and the ABI assertion and imported array type now
use 385 entries. The historical `oldtypes.h` declaration of
`creatures[MAX_CREATURES+1]`, with `MAX_CREATURES` equal to `256+128`, independently
agrees with the native constructor.

The initializer's canonical source remains unchanged and passes normalized,
reference, and encoded-body exactness checks. This corrects a storage extent;
it does not count as a new exact function.

```sh
uv run --no-sync python \
  tools/match/evidence/creature-pool-sentinel-2026-09-09/verify.py \
  --out /private/tmp/crimson-sentinel-proof
```

[results.json](results.json) records the image and constructor hashes, executed
instruction count, per-record byte writes, required extent, initializer hash,
and exactness results. The verifier also requires the declared data-definition
size to equal the observed extent, so the former 384-entry definition fails.
